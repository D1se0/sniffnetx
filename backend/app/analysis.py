"""SniffNex - Biblioteca comun de analisis de trafico.

Aqui vive TODA la logica de reconstitucion: fingerprinting de hosts,
sesiones TCP/UDP, reconstruccion de ficheros HTTP, DNS/MDNS/LLMNR/NBNS,
credenciales en claro, mensajes (correo/HTTP/mensajeria), parametros y
keywords detectados. Usada tanto por el sniffer en vivo como por el
lector de PCAP.
"""
from __future__ import annotations

import gzip
import io
import re
import socket
import hashlib
import threading
import time
import zlib
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Any

from scapy.all import Packet
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import TCPOptions

try:  # depuracion defensiva: import de utilidades de red
    from scapy.layers.inet import TCPOptions
except Exception:
    TCPOptions = None

from .oui_db import is_randomized_mac, lookup_mac

import scapy.packet as scapy_packet

try:
    from scapy.layers.dns import DNSQuestion
except Exception:
    class DNSQuestion:  # pragma: no cover
        ...


# Puertos conocidos -> dicionario
_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
    123: "ntp", 137: "nbns", 139: "netbios", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
    515: "lpd", 554: "rtsp", 587: "smtp-submit", 631: "ipp", 636: "ldaps",
    990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1883: "mqtt", 1900: "ssdp",
    2082: "cpanel", 2083: "cpanel-ssl", 3000: "dev-node", 3128: "squid",
    3306: "mysql", 3389: "rdp", 5000: "flask", 5353: "mdns",
    5355: "llmnr", 5432: "postgresql", 5439: "kafka", 5672: "amqp",
    5678: "droneci", 6379: "redis", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8088: "http-alt", 8139: "puppet",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9092: "kafka",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    51820: "wireguard", 1194: "openvpn", 5060: "sip", 5061: "sip-tls",
    3478: "stun", 51820: "wireguard",
}

_WWW_PORTS = {80, 8080, 8000, 8008, 8888, 3000, 5000, 3128, 8443}

# ---- Keywords que revelan actividad interesante sobre texto en claro
_DEFAULT_KEYWORDS = [
    "password", "passwd", "pass", "pwd", "usuario", "username", "user",
    "login", "admin", "administrator", "secret", "token", "api_key",
    "apikey", "authorization", "bearer", "session", "cookie", "token",
    "private key", "rsa key", "ssh-rsa", "begin rsa", "database",
    "mongodb://", "mysql://", "postgres://", "smtp", "host", "port",
]


def _ttl_to_os_guess(ttl: int) -> str:
    """Heuristica basica TTL -> familia SO."""
    if ttl <= 0:
        return "?"
    if ttl <= 64:
        if 63 <= ttl:
            return "Linux/Unix (2.4-2.6 o MacOS)"
        if 45 < ttl <= 64:
            return "Linux/Unix (2.6-3.x)"
        if 28 < ttl <= 45:
            return "Linux/Unix (2.x) o Android"
        return "Windows (desplazado por routers)"
    if 64 < ttl <= 128:
        if 127 <= ttl:
            return "Windows XP/2012"
        if 80 < ttl <= 127:
            return "Windows (7/8/10/2016/Server)"
        return "Solaris/AIX"
    if ttl <= 255:
        return "Router/Dispositivo embebido (Cisco/BSD)"
    return "?"


_RE_VA = re.compile(r"^(?P<fam>Windows|Linux|Unix|Mac|iOS|Android|FreeBSD|OpenBSD|NetBSD|Cisco|Solaris)", re.I)
_RE_LINUX_VER = re.compile(r"(?P<d>2\.4|2\.6|3\.0|3\.2|3\.10|3\.13|3\.14|3\.16|3\.18|3\.19|4\.0(?:\.x|)|4\.1|4\.4|4\.9|4\.14|4\.15|4\.18|4\.19|5\.0|4\.x)")


def _os_normalise(hostname: str) -> str:
    """Simplifica el nombre de host; deduce mas pistas de formato."""
    if not hostname:
        return "?"
    m = _RE_VA.match(hostname)
    return m.group("fam") if m else "?"


# ---------------------------------------------------------------------------
# Sesiones  (mira estado TCP/UDP; de momento UNA direccion; SEA copia del otro)
# ---------------------------------------------------------------------------


class TCPSession:
    """Cuando un extremo ve un SYN se genera una sesion; acumula bytes y reensambla si HTTP"""

    __slots__ = ("src", "dst", "sport", "dport", "state", "bytes", "packets",
                 "start", "end", "service", "banner", "syn", "http_state", "req", "resp")

    def __init__(self, src: str, dst: str, sport: int, dport: int, t: float):
        self.src, self.dst = src, dst
        self.sport, self.dport = sport, dport
        self.state = "SYN_SENT"
        self.bytes = 0
        self.packets = 0
        self.start = t
        self.end = t
        self.service = _SERVICES.get(dport, _SERVICES.get(sport, str(dport)))
        self.banner = b""
        self.syn = True
        self.http_state = None   # lista de trozos cliente -> server y viceversa
        self.req = None
        self.resp = None


class UDPFlow:
    __slots__ = ("src", "dst", "sport", "dport", "packets", "bytes", "start",
                 "end", "service")

    def __init__(self, src, dst, sport, dport, t):
        self.src, self.dst = src, dst
        self.sport, self.dport = sport, dport
        self.packets = 0
        self.bytes = 0
        self.start = t
        self.end = t
        self.service = _SERVICES.get(dport, _SERVICES.get(sport, str(dport)))


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------


class HostInfo:
    __slots__ = ("ip", "mac", "hostname", "domain", "ttl", "ttl_min", "os",
                 "os_guess", "packet_count", "bytes_count", "ports_open",
                 "sent", "recv", "last_seen", "first_seen", "arp", "mdns_names",
                 "nbns_names", "dns_queries", "keyword_hits",                 "locally_admin", "packets_sent_plain", "packets_recv_plain", "notes_quant", "tls_names")

    def __init__(self, ip):
        self.ip = ip
        self.mac = ""
        self.hostname = ""
        self.domain = ""
        self.ttl = 0
        self.ttl_min = 255
        self.os = "?"
        self.os_guess = ""
        self.packet_count = 0
        self.bytes_count = 0
        self.ports_open: set[int] = set()
        self.sent = 0
        self.recv = 0
        self.last_seen = ""
        self.first_seen = ""
        self.arp = False
        self.mdns_names: set[str] = set()
        self.nbns_names: set[str] = set()
        self.dns_queries: set[str] = set()
        self.keyword_hits: set[str] = set()
        self.locally_admin = False
        self.packets_sent_plain = 0
        self.packets_recv_plain = 0
        self.notes_quant = {}
        self.tls_names: set[str] = set()

    def register_l2(self, mac: str | None, t: float):
        if mac and not self.mac:
            self.mac = mac.upper()
            self.locally_admin = is_randomized_mac(self.mac)
        elif mac and self.mac and mac.upper() != self.mac:
            self.mac = mac.upper()
            self.locally_admin = is_randomized_mac(self.mac)
            self.notes_quant["mac_cached"] = 1

    def register_ip(self, ip_pkt, t: float, direction: str):
        # direction: "from" (host -> otro), "to" (otro -> host)
        ttl = int(getattr(ip_pkt, "ttl", 0) or 0)
        if ttl > 0:
            self.ttl = ttl
            self.ttl_min = min(self.ttl_min, ttl)
            self.os_guess = _ttl_to_os_guess(self.ttl_min)
        self.packet_count += 1
        if direction == "from":
            self.sent += 1
            self.packets_sent_plain += 1
        else:
            self.recv += 1
            self.packets_recv_plain += 1
        self.bytes_count += int(getattr(ip_pkt, "len", 0) or 0)
        stamp = datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds")
        self.last_seen = stamp
        if not self.first_seen:
            self.first_seen = stamp

    def to_dict(self) -> dict:
        vendor = lookup_mac(self.mac)
        return {
            "ip": self.ip,
            "mac": self.mac or "",
            "nic_vendor": vendor.get("nic_vendor", ""),
            "nic_vendor_long": vendor.get("nic_vendor_long", ""),
            "hostname": self.hostname,
            "domain": self.domain,
            "os": self.os,
            "os_guess": self.os_guess,
            "ttl": self.ttl,
            "ttl_min": self.ttl_min,
            "packet_count": self.packet_count,
            "bytes_count": self.bytes_count,
            "ports_open": sorted(self.ports_open),
            "sent": self.sent,
            "recv": self.recv,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "arp": self.arp,
            "randomized_mac": self.locally_admin,
            "mdns_names": sorted(self.mdns_names),
            "nbns_names": sorted(self.nbns_names),
            "dns_queries": sorted(self.dns_queries)[:100],
            "keyword_hits": sorted(self.keyword_hits),
            "tls_names": sorted(self.tls_names)[:30],
        }


# ---------------------------------------------------------------------------
# Analizador global
# ---------------------------------------------------------------------------


class TrafficAnalyzer:
    """Estado acumulado de la analisis + procesado packetea a packetea."""

    def __init__(self, keywords: list[str] | None = None):
        self.lock = threading.RLock()
        self.hosts: dict[str, HostInfo] = {}
        self.sessions: OrderedDict[str, TCPSession] = OrderedDict()
        self.udp_flows: OrderedDict[str, UDPFlow] = OrderedDict()
        self.files: list[dict] = []
        self.messages: list[dict] = []
        self.credentials: list[dict] = []
        self.dns_queries: list[dict] = []
        self.parameters: list[dict] = []
        self.keyword_hits: list[dict] = []
        self.tls_sessions: list[dict] = []   # SNI / handshakes TLS visibles
        self.alerts: list[dict] = []         # amenazas y anomalías (hunting)
        self._alerts_seq = 0
        self._scan_tracker: dict[str, dict[str, Any]] = {}   # src -> {ports,t0,dst}
        self._ip_macs: dict[str, set[str]] = {}   # ip -> MACs vistas (spoofing)
        self._mac_ips: dict[str, set[str]] = {}   # mac -> IPs anunciadas
        self._keywords: list[str] = [k.lower() for k in (keywords or _DEFAULT_KEYWORDS)]
        self.stats = {
            "packets": 0, "ip_packets": 0, "tcp": 0, "udp": 0, "icmp": 0,
            "arp": 0, "http": 0, "dns": 0, "other_l4": 0, "started": time.time(),
            "bytes": 0, "tls": 0, "alerts": 0,
        }
        # OJO: permite reconstruccion parcial del fichero TCP
        self._tcp_buf: dict[str, dict[str, Any]] = {}
        self._file_count = 0

    # ------------------------------------------------------------------ util
    @staticmethod
    def _session_key(src, dst, sport, dport) -> str:
        lo_a, lo_b, lo_p = ((src, dst, sport) if src <= dst else (dst, src, dport))
        return f"{lo_a}:{lo_p}-{lo_b}" if lo_a is src else f"{src}:{sport}-{dst}:{dport}"

    def _host(self, ip: str) -> HostInfo:
        h = self.hosts.get(ip)
        if h is None:
            h = HostInfo(ip)
            self.hosts[ip] = h
        return h

    # --------------------------------------------------- hunting / alerts
    def _add_alert(self, kind: str, severity: str, title: str, detail: str, t: float):
        """Registra una amenaza/anomalía detectada en la red."""
        self._alerts_seq += 1
        self.alerts.append({
            "id": self._alerts_seq,
            "kind": kind,
            "severity": severity,          # critical | high | medium | low | info
            "title": title,
            "detail": detail,
            "ts": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds"),
        })
        self.stats["alerts"] += 1
        if len(self.alerts) > 300:
            del self.alerts[:len(self.alerts) - 300]

    def _check_portscan(self, src: str, dst: str, dport: int, t: float):
        """Detector de escaneo de puertos: N puertos distintos hacia un mismo
        host en una ventana corta → alerta. Funciona para SYN, UDP, SYN/ACK."""
        st = self._scan_tracker.setdefault(src, {"ports": deque(), "warned": set()})
        q = st["ports"]
        q.append((t, dst, dport))
        # purga por ventana deslizante (8 s)
        while q and t - q[0][0] > 8.0:
            q.popleft()
        per_dst: dict[str, set[int]] = {}
        for _t, d, p in q:
            per_dst.setdefault(d, set()).add(p)
        for d, ports in per_dst.items():
            if len(ports) >= 20 and (src, d) not in st["warned"]:
                st["warned"].add((src, d))
                sample = ", ".join(str(p) for p in sorted(ports)[:12])
                self._add_alert(
                    "portscan", "high",
                    f"Escaneo de puertos desde {src} contra {d}",
                    f"{len(ports)} puertos distintos en <8 s (muestra: {sample})",
                    t)

    def _check_arp_conflict(self, arp, t: float):
        """ARP spoofing / poisoning: IP anunciada por >1 MAC, o MAC que se
        apropia de varias IPs del mismo segmento."""
        ip_str = str(arp.psrc)
        mac_str = str(arp.hwsrc).upper()
        self._ip_macs.setdefault(ip_str, set()).add(mac_str)
        self._mac_ips.setdefault(mac_str, set()).add(ip_str)
        macs = self._ip_macs[ip_str]
        if len(macs) > 1:
            ocurrences = " vs ".join(sorted(macs))
            self._add_alert(
                "arp-spoof", "critical",
                f"Posible ARP spoofing sobre {ip_str}",
                f"La IP {ip_str} la anuncian {len(macs)} MACs distintas: {ocurrences}",
                t)
        ips_ann = self._mac_ips[mac_str]
        if len(ips_ann) >= 3:
            self._add_alert(
                "arp-spoof", "high",
                f"MAC {mac_str} se anuncia para varias IPs",
                f"La MAC {mac_str} responde ARP para {len(ips_ann)} IPs: {', '.join(sorted(ips_ann))}",
                t)

    # ------------------------------------------------------ TLS / SNI
    @staticmethod
    def _parse_client_hello(payload: bytes) -> dict | None:
        """Extrae SNI, versión TLS y número de ciphers de un ClientHello crudo.
        Heurística tolerante: si el payload empieza con el record 0x16 0x03xx."""
        try:
            if len(payload) < 45 or payload[0] != 0x16:
                return None
            rec_ver = payload[1:3]
            # record: type(1) ver(2) len(2) | handshake: type(1) len(3) ver(2) random(32)
            if payload[5] != 0x01:
                return None
            off = 43                     # 5 record + 4 hs head + 32 random
            sid_len = payload[off]
            off += 1 + sid_len
            cs_len = int.from_bytes(payload[off:off + 2], "big")
            off += 2
            ciphers_raw = payload[off:off + cs_len]
            n_ciphers = cs_len // 2
            ciphers = [ciphers_raw[i:i + 2].hex() for i in range(0, min(cs_len, 24), 2)]
            off += cs_len
            comp_len = payload[off]
            off += 1 + comp_len
            ext_total = int.from_bytes(payload[off:off + 2], "big")
            off += 2
            end = min(off + ext_total, len(payload))
            sni = ""
            while off + 4 <= end:
                ext_type = int.from_bytes(payload[off:off + 2], "big")
                ext_len = int.from_bytes(payload[off + 2:off + 4], "big")
                body = payload[off + 4:off + 4 + ext_len]
                if ext_type == 0x0000 and len(body) >= 5:
                    slen = int.from_bytes(body[3:5], "big")
                    sni = body[5:5 + slen].decode("ascii", "ignore")
                    break
                off += 4 + ext_len
            return {
                "record_version": rec_ver.hex(),
                "sni": sni,
                "ciphers_n": n_ciphers,
                "ciphers_sample": ciphers,
            }
        except Exception:
            return None

    def _process_tls(self, payload: bytes, src, dst, sport, dport, t: float):
        if not payload:
            return
        rec = self._parse_client_hello(payload if dport in (443, 8443) else b"")
        if rec is None and sport in (443, 8443):
            rec = self._parse_client_hello(payload)
        if rec is None:
            return
        self.stats["tls"] += 1
        sni = rec.get("sni", "")
        entry = {
            "type": "client-hello",
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "sni": sni,
            "tls_version": rec.get("record_version", ""),
            "ciphers_n": rec.get("ciphers_n", 0),
            "ciphers_sample": rec.get("ciphers_sample", []),
            "ts": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds"),
        }
        self.tls_sessions.append(entry)
        if len(self.tls_sessions) > 300:
            del self.tls_sessions[:len(self.tls_sessions) - 300]
        if sni:
            self._host(src).tls_names.add(sni)
            self._host(dst).tls_names.add(sni)
            # hunting: SNI con patrones habituales de phishing/tracking
            low = sni.lower()
            if low.endswith(".tk") or low.endswith(".top") or low.endswith(".xyz") or low.endswith(".ru") or "login-" in low or "secure-" in low:
                self._add_alert("tls-sni", "medium",
                                f"SNI sospechoso: {sni}",
                                f"Dominio TLS hacia {dst} con patrón habitual de phishing/trackers",
                                t)

    # ------------------------------------------------------------- Ficheros
    def _register_file(self, size, filename, ct, src, dst, kind, data: bytes | None):
        fid = self._file_count
        self._file_count += 1
        entry = {
            "id": fid,
            "size": size,
            "filename": filename or f"unnamed_{fid}",
            "content_type": ct or "application/octet-stream",
            "src": src,
            "dst": dst,
            "kind": kind,
            "ts": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
            "complete": data is not None,
        }
        if data is not None:
            entry["sha256"] = ""
        self.files.append(entry)
        return entry

    # ------------------------------------------------------------- paquetea
    def process(self, pkt: Packet):
        """Analiza un paquete Scapy y rellena el estado acumulado."""
        with self.lock:
            self.stats["packets"] += 1
            t = float(getattr(pkt, "time", time.time()) or time.time())

            eth = pkt.getlayer(Ether)
            if eth:
                self.stats["bytes"] += len(pkt)

            if pkt.haslayer(ARP):
                self.stats["arp"] += 1
                arp = pkt[ARP]
                if (arp.op == 1 or arp.op == 2):
                    h = self._host(arp.psrc)
                    h.register_l2(arp.hwsrc, t)
                    h.arp = True
                    self._check_arp_conflict(arp, t)
                    return

            if pkt.haslayer(IP):
                self.stats["ip_packets"] += 1
                ip = pkt[IP]
                src = ip.src
                dst = ip.dst

                hs = self._host(src)
                hd = self._host(dst)
                hs.register_l2(eth.src if eth else None, t)
                hd.register_l2(eth.dst if eth else None, t)
                hs.register_ip(ip, t, "from")
                hd.register_ip(ip, t, "to")

                if pkt.haslayer(TCP):
                    self.stats["tcp"] += 1
                    self._process_tcp(pkt, ip, src, dst, hs, hd, t)
                elif pkt.haslayer(UDP):
                    self.stats["udp"] += 1
                    self._process_udp(pkt, ip, src, dst, hs, hd, t)
                elif pkt.haslayer(ICMP):
                    self.stats["icmp"] += 1
                else:
                    self.stats["other_l4"] += 1

    # ------------------------------------------------------------- TCP
    def _process_tcp(self, pkt: Packet, ip: Packet, src, dst, hs: HostInfo, hd: HostInfo, t: float):
        tcp = pkt[TCP]
        sport, dport = int(tcp.sport), int(tcp.dport)
        flags = int(tcp.flags)
        key = self._session_key(src, dst, sport, dport)
        ses = self.sessions.get(key)
        if ses is None:
            ses = TCPSession(src, dst, sport, dport, t)
            self.sessions[key] = ses
        ses.packets += 1
        ses.bytes += len(pkt)
        ses.end = t

        open_ports = (dport if (flags & 0x12) == 0x12 else sport if (flags & 0x14) == 0x12 else None)
        if open_ports:
            hd.ports_open.add(dport if flags & 0x10 == 0 else sport)

        # SYNs / FINs -> estado
        if flags & 0x02 and not (flags & 0x10):
            ses.state = "SYN_SENT"
        elif flags & 0x02 and flags & 0x10:
            ses.state = "SYN_ACK"
        elif flags & 0x10:
            ses.state = "ESTABLISHED"
        elif flags & 0x04:
            ses.state = "RST"
        elif flags & 0x01:
            ses.state = "FIN_WAIT"

        # hunting: SYN abierto (escaneo) —track por (src,dst,dport) en ventana
        if flags & 0x02:
            self._check_portscan(src, dst, dport, t)

        payload = bytes(tcp.payload) if tcp.payload else b""
        if not payload:
            return

        # HTTP
        if pkt.haslayer(HTTP) or pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
            self._process_http(pkt, ses, src, dst, hs, hd, t)
            return

        self._scan_blob(payload, src, dst, sport, dport, ses.service, t)
        if dport in (443, 8443) or sport in (443, 8443):
            self._process_tls(payload, src, dst, sport, dport, t)

    # ------------------------------------------------------------- HTTP
    def _process_http(self, pkt: Packet, ses: TCPSession, src, dst, hs, hd, t: float):
        self.stats["http"] += 1
        req = None
        resp = None
        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
        if pkt.haslayer(HTTPResponse):
            resp = pkt[HTTPResponse]
        if resp is not None and resp.fields.get("Status_Code") is not None or (resp is not None and "Status-Line" in resp.fields):
            status = ""
            if "Status-Line" in resp.fields:
                sl = resp.fields["Status-Line"]
                status = sl.decode(errors="ignore") if isinstance(sl, bytes) else str(sl)
            else:
                code = resp.fields.get("Status_Code", b"")
                reason = resp.fields.get("Reason_Phrase", b"")
                status = (_try_bytes(code) + " " + _try_bytes(reason)).strip()
            def _fh(name):
                v = resp.fields.get(name) or resp.fields.get(name.replace("-", "_")) or b""
                return v.decode(errors="ignore") if isinstance(v, bytes) else str(v)
            body = bytes(resp.payload) if resp.payload else b""
            ctype = _fh("Content_Type")
            disp = _fh("Content_Disposition")
            enc = _fh("Content_Encoding")
            if enc.lower() in ("gzip", "deflate", "br") or body[:2] == b"\x1f\x8b":
                try:
                    if body[:2] == b"\x1f\x8b":
                        body = gzip.decompress(body)
                    else:
                        body = zlib.decompress(body, -32)
                except Exception:
                    pass
            resp_fields = {k.decode(errors='ignore') if isinstance(k, bytes) else k: (v.decode(errors='ignore') if isinstance(v, bytes) else v) for k, v in resp.fields.items()}
            req_path = ""
            req_host = ""
            if ses.req:
                req_path = ses.req["path"]
                req_host = ses.req["host"]
            entry = {
                "type": "response",
                "status": status.split(" ")[0] if " " in status else status,
                "status_text": status,
                "method": ses.req["method"] if ses.req else "",
                "path": req_path,
                "host": req_host,
                "src": dst,
                "dst": src,
                "content_type": ctype,
                "size": len(body),
                "headers": {k: v for k, v in resp_fields.items() if k in ("Server", "Content-Type", "Content-Length", "Content-Disposition", "Set-Cookie", "Date", "Connection")},
                "ts": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds"),
            }
            self.messages.append(entry)
            self._scan_blob(body, dst, src, 0, 0, "http-data", t)

            disp = resp_fields.get("Content-Disposition")
            if disp and "filename=" in disp:
                m = re.search(r'filename="?([^";]+)', disp)
                if m:
                    self._save_http_file(body, m.group(1), ctype, dst, src, t)
            else:
                self._guess_http_file(body, ctype, req_path or status, dst, src, t)
            return

        if req is not None:
            method = req.fields.get("Method", b"").decode(errors="ignore") if isinstance(req.fields.get("Method"), bytes) else ""
            path = req.fields.get("Path", b"").decode(errors="ignore") if isinstance(req.fields.get("Path"), bytes) else ""
            version = req.fields.get("Http-Version", b"").decode(errors="ignore") if isinstance(req.fields.get("Http-Version"), bytes) else ""
            headers = {k.decode(errors="ignore") if isinstance(k, bytes) else k: (v.decode(errors="ignore") if isinstance(v, bytes) else v) for k, v in req.fields.items()}
            host = headers.get("Host", "")
            ua = headers.get("User-Agent", "")
            cookie = headers.get("Cookie", "")
            auth = headers.get("Authorization", "")
            entry = {
                "type": "request",
                "method": method,
                "path": path,
                "http_version": version,
                "host": host,
                "src": src,
                "dst": dst,
                "user_agent": ua,
                "cookie": cookie,
                "authorization": auth,
                "headers": {k: v for k, v in headers.items() if k in ("Host", "User-Agent", "Referer", "Accept", "Accept-Language", "Connection", "Content-Type", "Content-Length", "Authorization", "Cookie")},
                "size": len(req),
                "ts": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds"),
            }
            ses.req = entry
            self.messages.append(entry)

            if method in ("POST", "PUT", "DELETE", "PATCH"):
                body = bytes(req.payload) if req.payload else b""
                if body:
                    self._scan_blob(body, src, dst, 0, 0, "http-body", t)
                    self._extract_params(body, path, host, src, dst, t, "http-body")
            if path:
                self._extract_params("", path, host, src, dst, t, "http-url")
            if cookie:
                self.credentials.append({
                    "type": "http-cookie", "user": "", "password": "", "hash": "",
                    "domain": host, "src": src, "dst": dst, "port": 80,
                    "evidence": cookie, "ts": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds"),
                })
            if auth:
                self.credentials.append({
                    "type": "http-auth-header", "user": "", "password": "", "hash": auth,
                    "domain": host, "src": src, "dst": dst, "port": 80,
                    "evidence": auth[:200], "ts": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds"),
                })
            self._set_host_keywords(ua, hs)

    def _save_http_file(self, data: bytes, filename: str, ct: str, src, dst, t: float):
        self._file_count += 1
        f = {
            "id": self._file_count - 1,
            "filename": filename,
            "size": len(data),
            "mime": ct,
            "src": src,
            "dst": dst,
            "sha256": hashlib.sha256(data).hexdigest(),
            "data": data,
            "ts": datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds"),
            "type": "http",
        }
        self.files.append(f)

    def _guess_http_file(self, data: bytes, ct: str, label: str, src, dst, t: float):
        """Sin filename: deduce si el body PROBABLEMENTE es un fichero binario."""
        if len(data) < 64 or not ct:
            return
        ct = ct.split(";")[0].strip().lower()
        is_img = ct.startswith("image/")
        is_bin = data[:4].lower() in (b"\x89png", b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", b"\xff\xd8\xff\xdb")
        if not (is_img or ct in ("application/pdf", "application/octet-stream", "application/zip") or (data[:3].lower() == b"gif")):
            return
        ext = {
            "image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif",
            "image/webp": ".webp", "application/pdf": ".pdf", "application/zip": ".zip",
        }.get(ct, "")
        name = re.sub(r"[^\w\.\-]", "_", label.split("?")[0].strip("/").split("/")[-1] or f"file{self._file_count}")[:40] + ext
        self._save_http_file(data, name, ct, src, dst, t)

    # ------------------------------------------------------------- UDP
    def _process_udp(self, pkt: Packet, ip: Packet, src, dst, hs, hd, t: float):
        udp = pkt[UDP]
        sport, dport = int(udp.sport), int(udp.dport)
        key = self._session_key(src, dst, sport, dport)
        f = self.udp_flows.get(key)
        if f is None:
            f = UDPFlow(src, dst, sport, dport, t)
            self.udp_flows[key] = f
        f.packets += 1
        f.bytes += len(pkt)
        f.end = t

        if pkt.haslayer(DNS):
            self.stats["dns"] += 1
            self._process_dns(pkt, src, dst, t)
        else:
            hs.ports_open.add(sport)
            payload = bytes(udp.payload) if udp.payload else b""
            if dport in (53, 5353, 5355, 137) or sport in (53, 5353, 5355, 137):
                pass
            if payload:
                self._scan_blob(payload, src, dst, sport, dport, f.service, t)

    # ------------------------------------------------------------- DNS
    def _process_dns(self, pkt: Packet, src, dst, t: float):
        dns = pkt[DNS]
        ts = datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds")
        qr = 1 if dns.qr else 0
        record = {
            "ts": ts, "src": src, "dst": dst, "is_response": bool(dns.qr),
            "rcode": int(dns.rcode) if dns.qr else None,
            "questions": [], "answers": [],
        }
        # Preguntas y respuestas (scapy itera qd/an como listas de capas)
        try:
            for q in dns.qd or []:
                try:
                    record["questions"].append({
                        "name": _try_bytes(q.qname), "type": _DNSTYPES.get(int(q.qtype), str(q.qtype)),
                    })
                except Exception:
                    pass
        except Exception:
            pass
        try:
            for an in dns.an or []:
                try:
                    rr = {
                        "name": _try_bytes(an.rrname),
                        "type": _DNSTYPES.get(int(an.type), str(an.type)),
                        "ttl": int(getattr(an, "ttl", 0)),
                        "data": "",
                    }
                    rd = getattr(an, "rdata", "")
                    if rr["type"] in ("A", "AAAA", "CNAME", "NS", "PTR"):
                        rr["data"] = _try_bytes(rd)
                    elif rr["type"] == "TXT":
                        rr["data"] = _try_bytes(rd)[:300]
                    else:
                        rr["data"] = _try_bytes(rd)[:120]
                    record["answers"].append(rr)
                except Exception:
                    pass
        except Exception:
            pass

        self.dns_queries.append(record)

        for qe in record["questions"]:
            name = qe["name"].rstrip(".")
            if not name:
                continue
            hs = self._host(src)
            hd = self._host(dst)
            hs.dns_queries.add(name)
            hd.dns_queries.add(name)
            # mDNS/LLMNR/NBNS delatan hostnames
            try:
                udp = pkt.getlayer(UDP)
                dport, sport = (int(udp.dport), int(udp.sport)) if udp else (0, 0)
            except Exception:
                dport = sport = 0
            lower = name.lower()
            if lower.endswith(".local"):
                base = lower.split(".")[0]
                for h in (hs, hd):
                    h.mdns_names.add(base)
                    if not h.hostname:
                        h.hostname, h.domain = base, "local"
            elif "5355" in (str(dport), str(sport)):
                base = lower.split(".")[0]
                for h in (hs, hd):
                    if not h.hostname:
                        h.hostname, h.domain = base, ""    # LLMNR

    # ------------------------------------------------------------- params
    def _extract_params(self, body: bytes, path: str, host: str, src, dst, t: float, kind: str):
        ts = datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds")
        if path:
            for m in re.finditer(r"[?&]([^?&=]+)=([^&]*)", path):
                self.parameters.append({"key": m.group(1), "value": m.group(2)[:120], "kind": "url", "host": host, "src": src, "dst": dst, "ts": ts})
        if body:
            try:
                text = body.decode("utf-8", errors="ignore")
            except Exception:
                return
            for m in re.finditer(r"([?&\s]|^)([\w\-\.\[\]]{1,32})=([^\s&]{0,140})", text):
                self.parameters.append({"key": m.group(2), "value": m.group(3)[:120], "kind": kind, "host": host, "src": src, "dst": dst, "ts": ts})
            ct_json = text.lstrip().startswith("{")
            if ct_json:
                for km in re.finditer(r'"([A-Za-z_][\w\-\.]{1,31})"\s*:\s*("[^"]{0,140}"|[^\,\}\s]{1,140})', text):
                    self.parameters.append({"key": km.group(1), "value": km.group(2).strip('"')[:120], "kind": kind + ":json", "host": host, "src": src, "dst": dst, "ts": ts})

    # ------------------------------------------------------------- blob scan
    def _scan_blob(self, data: bytes, src, dst, sport, dport, service: str, t: float):
        """Escanea un 'blob' (payload o cuerpo) buscando keywords, credenciales,
        mensajes (SMTP/POP3/IMAP/FTP) y parámetros GET/POST."""
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return
        if len(text) > 200000:
            text = text[:200000]
        ts = datetime.fromtimestamp(t, tz=timezone.utc).isoformat(timespec="seconds")
        low = text.lower()

        # keywords
        for kw in self._keywords:
            hits = 0
            for m in re.finditer(re.escape(kw), low):
                hits += 1
                if hits > 5:
                    break
            if hits:
                for h in (self._host(src), self._host(dst)):
                    if kw not in h.keyword_hits:
                        h.keyword_hits.add(kw)
                self.keyword_hits.append({"keyword": kw, "src": src, "dst": dst, "port": dport or sport, "service": service, "ts": ts, "context": text[max(0, low.find(kw) - 60): low.find(kw) + len(kw) + 80]})

        # credenciales (formularios HTTP, USER/PASS FTP, AUTH PLAIN, etc)
        for m in re.finditer(r"(?:login=|user=|username=|usuario=|email=)([^&\s\x03\x0a]{1,64})", text, re.I):
            passw = re.search(r"(?:pass(?:word|wd)?|pwd|contra(?:se&)?a?)=([^&\s\x03\x0a]{1,64})", text, re.I)
            self.credentials.append({
                "type": "form/urlencoded", "user": m.group(1),
                "password": passw.group(1) if passw else "",
                "hash": "", "src": src, "dst": dst, "port": dport or sport,
                "evidence": m.group(0)[:150], "ts": ts,
            })
        for m in re.finditer(r"(?:^|\n)(?:USER|Username|NICK) (\S{1,64})", text, re.I):
            self.credentials.append({"type": "plaintext-protocol", "user": m.group(1), "password": "", "hash": "", "src": src, "dst": dst, "port": dport or sport, "evidence": m.group(0)[:150], "ts": ts})
        for m in re.finditer(r"(?:^|\n)PASS (\S{1,64})", text, re.I):
            self.credentials.append({"type": "plaintext-protocol", "user": "", "password": m.group(1), "hash": "", "src": src, "dst": dst, "port": dport or sport, "evidence": m.group(0)[:150], "ts": ts})
        if "Authorization: Basic" in text[:3000]:
            for m in re.finditer(r"Authorization: Basic ([A-Za-z0-9+/=]{8,200})", text):
                self.credentials.append({"type": "basic-b64", "user": "", "password": "", "hash": m.group(1), "src": src, "dst": dst, "port": dport or sport, "evidence": m.group(0)[:200], "ts": ts})

        # FTP usuario+pass: "USER <user>" seguido de "PASS <pass>"
        raw_pairs = re.findall(r"USER (\S{1,64})\s+(?:PASS )?(\S{1,64})", text, re.I)
        for u, p in raw_pairs:
            self.credentials.append({"type": "ftp", "user": u, "password": p, "hash": "", "src": src, "dst": dst, "port": dport or sport, "evidence": f"USER {u} / PASS {p}", "ts": ts})

        # SMTP MAIL FROM/RCPT TO  -> mensajes
        if "MAIL FROM" in text.upper() or "RCPT TO" in text.upper():
            self.messages.append({"type": "smtp-meta", "src": src, "dst": dst, "port": dport or sport, "from": "", "to": [], "subject": "", "body": text[:400], "ts": ts})

        # Nordics: HTTP post con cuerpo JSON largo -> mensajes generales
        if service in ("http", "http-alt", "http-proxy") and len(text) > 60:
            self.messages.append({"type": "http-raw", "src": src, "dst": dst, "port": dport or sport, "from": "", "to": [], "subject": "", "body": text[:400], "ts": ts})

    def _set_host_keywords(self, ua: str, h: HostInfo):
        if not ua:
            return
        ua = ua.lower()
        if "windows nt" in ua:
            h.os = "Windows"
        elif "android" in ua:
            h.os = "Android"
        elif "iphone" in ua or "ipad" in ua:
            h.os = "iOS"
        elif "mac os" in ua:
            h.os = "macOS"
        elif "linux" in ua or "x11" in ua:
            h.os = "Linux"


def _try_bytes(v: Any) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="ignore").rstrip("\x00")
    return str(v)


def _pid_port_from_packet(analyzer, pkt, src, dst):
    """best effort obtiene puerto UDP del dns para mdns"""
    try:
        udp = pkt[UDP]
        return int(udp.sport), int(udp.dport)
    except Exception:
        return 0, 0


_DNSTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 41: "OPT", 65: "HTTPS", 255: "ANY",
}
