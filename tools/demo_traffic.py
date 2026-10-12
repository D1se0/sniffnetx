#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SniffNex demo_traffic — genera tráfico REALISTA de laboratorio para probar TODAS
las secciones de la aplicación (Hosts, Archivos, Imágenes, Mensajes, Credenciales,
Sesiones, DNS, Parámetros, Keywords).

Modos:
  ./tools/demo_traffic.py pcap  OUT.pcap [--loops N]   → escribe un PCAP listo para
                                                        arrastrar a "Cargar PCAP".
  ./tools/demo_traffic.py lo    [--loops N]            → inyecta el mismo tráfico en la
                                                        interfaz loopback YA ANALIZADO.
  ./tools/demo_traffic.py eth0 [--loops N]             → capa 2 real saliendo por una
                                                        interfaz (necesita root).
  ./tools/demo_traffic.py lo-real                      → HTTP/FTP reales contra un
                                                        servidor Python efímero en
                                                        127.0.0.1 (los ve el sniffer
                                                        en vivo sobre `lo`).
"""
import os
import sys
import time
import random
import string
import argparse
from datetime import datetime, timezone

try:
    from scapy.all import Ether, IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR, ICMP, wrpcap, sendp, send, conf
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    sys.exit("Instala scapy:  pip install scapy")

# ----------------------------------------------------------------------------------
# Identity map: cada "actor" de la demo es una estación plausible en una LAN de casa
# ----------------------------------------------------------------------------------
FAKE_MACS = {
    "kali":        "08:00:27:F1:A2:33",   # Kali auditor (Oracle/VM)
    "win":         "00:1A:2B:3C:4D:5E",   # PC Windows (Intel)
    "android":     "60:57:18:11:22:33",   # móvil Android (Azurewave)
    "iphone":      "F0:B4:79:12:34:56",   # iPhone (Apple)
    "iot_cam":     "00:16:79:AA:BB:CC",   # cámara IP (Sveon/Broadcom)
    "linux_srv":   "B8:27:EB:99:88:77",   # Raspberry Pi (Raspberry Pi Foundation)
    "printer":     "00:00:48:DE:AD:01",   # impresora HP
    "switch":      "52:54:00:12:34:56",   # gateway Linux/QEMU
}
IP_NET = {            # 192.168.42.0/24 — red de demo
    "kali":      "192.168.42.131",
    "win":       "192.168.42.105",
    "android":   "192.168.42.112",
    "iphone":    "192.168.42.114",
    "iot_cam":   "192.168.42.120",
    "linux_srv": "192.168.42.50",
    "printer":   "192.168.42.60",
    "switch":    "192.168.42.1",
}
INTERNET_MAC = "52:54:00:AB:CD:EF"
INTERNET_IP  = "203.0.113.77"        # TEST-NET-3, server "remoto"

def _ts():
    return time.time()

# ----------------------------------------------------------------------------------
# Builders: cada función genera UNA conversación completa de un protocolo concreto
# ----------------------------------------------------------------------------------
def http_login(fr, to, host="192.168.7.5", path="/login"):
    """POST /login con credenciales en claro (form-urlencoded). Probará · Credenciales y Parámetros."""
    body = b"user=auditor-tiana&password=Tr4xBDu1987&remember=1"
    req = (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) /
           IP(src=IP_NET[fr], dst=IP_NET[to]) /
           TCP(sport=55001, dport=80, flags="PA") /
           HTTP() / HTTPRequest(
               Method=b"POST", Path=path.encode(), Http_Version=b"HTTP/1.1",
               Host=host.encode(),
               User_Agent=b"Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0",
               Content_Type=b"application/x-www-form-urlencoded",
               Content_Length=str(len(body)).encode(),
               Cookie=b"session=auditor-tiana-gGb29A1",
               Connection=b"keep-alive") / Raw(load=body))
    ok = (Ether(src=FAKE_MACS[to], dst=FAKE_MACS[fr]) /
          IP(src=IP_NET[to], dst=IP_NET[fr]) /
          TCP(sport=80, dport=55001, flags="PA", seq=1) /
          HTTP() / HTTPResponse(Http_Version=b"HTTP/1.1", Status_Code=b"302", Reason_Phrase=b"Found", Server=b"nginx/1.24.0", Location=b"https://intranet.local/dashboard", Set_Cookie=b"session=sTB32k authService=ok") / Raw(load=b""))
    return [req, ok]

def http_download_image(fr, to, host="photos.shared-host.net", path="/media/family2019.png"):
    """GET /media/family2019.png → respuesta con PNG de verdad; probará Imagenes, Archivos."""
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d494844520000004000000040080600000"
        "0aa6971de0000014494441547847e5edc1b10c705016c000000000000"
        "000000000000000000000000000000000000"
        "00d0cfa8fb6d0000000049454e44ae426082")
    req = (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) /
           IP(src=IP_NET[fr], dst=IP_NET[to]) /
           TCP(sport=48211, dport=80, flags="PA", seq=1) /
           HTTP() / HTTPRequest(
               Method=b"GET", Path=path.encode(), Http_Version=b"HTTP/1.1",
               Host=host.encode(), User_Agent=b"curl/8.5.0",
               Accept=b"image/png,image/*,*/*"))
    resp = (Ether(src=FAKE_MACS[to], dst=FAKE_MACS[fr]) /
            IP(src=IP_NET[to], dst=IP_NET[fr]) /
            TCP(sport=80, dport=48211, flags="PA", seq=1) /
            HTTP() / HTTPResponse(
                Status_Code=b"200", Reason_Phrase=b"OK", Http_Version=b"HTTP/1.1",
                Server=b"nginx", Content_Type=b"image/png",
                Content_Length=str(len(png)).encode(),
                Connection=b"close") / Raw(load=png))
    return [req, resp]

def http_secret_keyword_page(fr, to, host="confidential.intranet.local"):
    """Una página con passwords/tokens/api_key por todas partes → probará Keywords."""
    body = (b"<!DOCTYPE html><html><head><title>Panel interno</title></head><body>"
            b"<h1>DevOps Bootstrap</h1>"
            b"<pre>database:host=192.168.42.50 port=3306 name=maindb user=root pass=admin1234"
            b"\\ntoken bearer  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"
            b"\\napi_key = SK-7Hx9-88771-PROD\\nprivate key follows:"
            b"-----BEGIN RSA PRIVATE KEY-----\\nMIIBOgIBAAJBAK...\\n-----END RSA PRIVATE KEY-----"
            b"</pre></body></html>")
    resp = (Ether(src=FAKE_MACS[to], dst=FAKE_MACS[fr]) /
            IP(src=IP_NET[to], dst=IP_NET[fr]) /
            TCP(sport=80, dport=48312, flags="PA", seq=1) /
            HTTP() / HTTPResponse(
                Status_Code=b"200", Reason_Phrase=b"OK", Http_Version=b"HTTP/1.1",
                Server=b"Apache/2.4.52 (Unix)", Content_Type=b"text/html",
                Content_Length=str(len(body)).encode()) / Raw(load=body))
    return [resp]

def http_query_params(fr, to, host="checkout.nordpay.net"):
    """GET con parámetros sensibles en la URL. Probará Parámetros según `http-url`."""
    req = (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) /
           IP(src=IP_NET[fr], dst=IP_NET[to]) /
           TCP(sport=55990, dport=80, flags="PA") /
           HTTP() / HTTPRequest(
               Method=b"GET",
               Path=b"/v1/search?q=bicicleta+gokart&session=XYZ-881-Z&apikey=SK-9f3A&email=ana%40home.net",
               Http_Version=b"HTTP/1.1", Host=host.encode(), User_Agent=b"PostmanRuntime/7.32"))
    ok = (Ether(src=FAKE_MACS[to], dst=FAKE_MACS[fr]) /
          IP(src=IP_NET[to], dst=IP_NET[fr]) /
          TCP(sport=80, dport=55990, flags="PA", seq=1) /
          HTTP() / HTTPResponse(Http_Version=b"HTTP/1.1", Status_Code=b"200", Reason_Phrase=b"OK", ) /
          Raw(load=b'{"ok":"true","results":["casa","jardin"]}'))
    return [req, ok]

def json_api_key_post(fr, to, host="api.cloudmails.net"):
    """POST /v1/api-key con JSON que vedará Keywords y Parámetros JSON."""
    body = (b'{"username":"svc_backup","password":"0xF00d-BEER-Babe","api_key":"AKIAIOSFODNN7EXAMPLE",'
            b'"endpoint":"s3.eu-west-1.amazonaws.com","port":443,"session":"eyJhbGciOi.editoral"}')
    req = (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) /
           IP(src=IP_NET[fr], dst=IP_NET[to]) /
           TCP(sport=56123, dport=80, flags="PA") /
           HTTP() / HTTPRequest(
               Method=b"POST", Path=b"/v1/api-key", Http_Version=b"HTTP/1.1",
               Host=host.encode(), Content_Type=b"application/json",
               Authorization=b"Bearer eyJhbGciOiJIUzI1NiJ9.OK.EDITOR",
               Content_Length=str(len(body)).encode()) / Raw(load=body))
    ok = (Ether(src=FAKE_MACS[to], dst=FAKE_MACS[fr]) /
          IP(src=IP_NET[to], dst=IP_NET[fr]) /
          TCP(sport=80, dport=56123, flags="PA", seq=1) /
          HTTP() / HTTPResponse(Http_Version=b"HTTP/1.1", Status_Code=b"201", Reason_Phrase=b"Created", Content_Type=b"application/json") /
          Raw(load=b'{"created":true,"api_key_prefix":"AKIAIOSF"}'))
    return [req, ok]

def ftp_login(fr, to):
    """USER/PASS FTP en claro. Probará Credenciales (type=ftp) y Mensajes."""
    return [
        (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) / IP(src=IP_NET[fr], dst=IP_NET[to]) /
         TCP(sport=50111, dport=21, flags="PA") / Raw(load=b"USER ftpbackup\r\n")),
        (Ether(src=FAKE_MACS[to], dst=FAKE_MACS[fr]) / IP(src=IP_NET[to], dst=IP_NET[fr]) /
         TCP(sport=21, dport=50111, flags="PA", seq=1) / Raw(load=b"331 Password required\r\n")),
        (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) / IP(src=IP_NET[fr], dst=IP_NET[to]) /
         TCP(sport=50111, dport=21, flags="PA", seq=2) / Raw(load=b"PASS H4rdC0re2026!\r\n")),
        (Ether(src=FAKE_MACS[to], dst=FAKE_MACS[fr]) / IP(src=IP_NET[to], dst=IP_NET[fr]) /
         TCP(sport=21, dport=50111, flags="PA", seq=2) / Raw(load=b"230 User logged in\r\n")),
    ]

def smtp_send_mail(fr, to):
    """Conversación SMTP de商务 con FROM/RCPT en claro. Probará Mensajes."""
    return [
        (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) / IP(src=IP_NET[fr], dst=IP_NET[to]) /
         TCP(sport=52231, dport=25, flags="PA") /
         Raw(load=b"MAIL FROM:<auditor@corp.local>\r\n")),
        (Ether(src=FAKE_MACS[to], dst=FAKE_MACS[fr]) / IP(src=IP_NET[to], dst=IP_NET[fr]) /
         TCP(sport=25, dport=52231, flags="PA", seq=1) / Raw(load=b"250 OK\r\n")),
        (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) / IP(src=IP_NET[fr], dst=IP_NET[to]) /
         TCP(sport=52231, dport=25, flags="PA", seq=2) /
         Raw(load=b"RCPT TO:<abuse@example.com>\r\n")),
        (Ether(src=FAKE_MACS[to], dst=FAKE_MACS[fr]) / IP(src=IP_NET[to], dst=IP_NET[fr]) /
         TCP(sport=25, dport=52231, flags="PA", seq=2) / Raw(load=b"250 Accepted\r\n")),
        (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) / IP(src=IP_NET[fr], dst=IP_NET[to]) /
         TCP(sport=52231, dport=25, flags="PA", seq=3) /
         Raw(load=b"DATA\r\nSubject: Informe auditoria semanal\r\n\r\nEncontrado login invalido en 192.168.42.105.\r\n.\r\n")),
    ]

def dns_burst(fr, to):
    """Consultas DNS reales hacia el gateway — unaNXDOMAIN para ilustar 'dns-flood'."""
    names = ["api.github.com", "wifi.analyzer.local", "nonexistent-1.local",
             "nonexistent-2.local", "cdn.jsdelivr.net", "ftp.intranet.local",
             "bad-domain-abc123xyz.net", "bad-domain-abc123xyz.net"]
    out = []
    for n in names:
        q = (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) / IP(src=IP_NET[fr], dst=IP_NET[to]) /
             UDP(sport=44455, dport=53) / DNS(id=random.randint(1, 65535), rd=1,
                                              qd=DNSQR(qname=n, qtype="A")))
        out.append(q)
    # una respuesta A
    out.append((Ether(src=FAKE_MACS[to], dst=FAKE_MACS[fr]) / IP(src=IP_NET[to], dst=IP_NET[fr]) /
                UDP(sport=53, dport=44455) /
                DNS(id=random.randint(1, 65535), qr=1, ra=1,
                    qd=DNSQR(qname="api.github.com", qtype="A"),
                    an=DNSRR(rrname="api.github.com", ttl=180, rdata=IP_NET[to]))))
    return out

def mdns_probe(fr):
    """mDNS .local para 'volcar hostname' — asomba keras kas.
    {'kali-lab.local'} en el networking local. LLMNR (5355) no lo vamos a meter para no juntarlo
    con mDNS."""
    mdns_ip = "224.0.0.251"
    q = (Ether(src=FAKE_MACS[fr], dst="01:00:5e:00:00:fb") / IP(src=IP_NET[fr], dst=mdns_ip) /
         UDP(sport=5353, dport=5353) /
         DNS(id=0, qr=0, qd=DNSQR(qname="kali-lab.local", qtype="A")))
    r = (Ether(src=FAKE_MACS[fr], dst="01:00:5e:00:00:fb") / IP(src=IP_NET[fr], dst=mdns_ip) /
         UDP(sport=5353, dport=5353) /
         DNS(id=0, qr=1, aa=1, qd=DNSQR(qname="kali-lab.local", qtype="A"),
             an=DNSRR(rrname="kali-lab.local", ttl=120, rdata=IP_NET[fr])))
    return [q, r]

def ntp_and_icmp(fr, to):
    """NTP e ICMP tal cual para rellenar contadores y hostmeta. También da otro hosttalkers."""
    return [
        (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) /
         IP(src=IP_NET[fr], dst=IP_NET[to]) / UDP(sport=123, dport=123) /
         Raw(load=bytes([0x1b] + [random.randint(0, 255)] * 47))),
        (Ether(src=FAKE_MACS[fr], dst=FAKE_MACS[to]) /
         IP(src=IP_NET[fr], dst=IP_NET[to]) / ICMP(type=8, id=99, seq=1) /
         Raw(load=b"sniffnex-demo-ping")),
    ]

# ----------------------------------------------------------------------------------
# Escena completa: ensambla todo y lo opcionalmente reordana de forma cronológica
# ----------------------------------------------------------------------------------
def build_scene(rng: random.Random):
    H, W = "kali", "switch"          # kali ↔ switch (gateway) es cada flujo aquí
    S = []
    S += http_login("win", H)                      # → Credenciales + Parámetros + Sesión
    S += http_download_image("android", H)          # → Archivos + Imágenes (PNG)
    S += http_query_params("iphone", H)             # → Parámetros (http-url)
    S += json_api_key_post("linux_srv", H)          # → Parámetros JSON + Keywords
    S += http_secret_keyword_page("iot_cam", H)     # → Keywords (database, api_key…) + host
    S += ftp_login("printer", H)                    # → Credenciales FTP + Mensajes
    S += smtp_send_mail("kali", H)                  # → Mensajes SMTP
    S += dns_burst("android", H)                    # → DNS (+2 NXDOMAIN)
    S += mdns_probe("iphone")                       # → mDNS (kali-lab.local)
    S += ntp_and_icmp("win", H)                     # → UDP/NTP/ICMP
    rng.shuffle(S)
    return S

def seq_packets(packets):
    """Asigna seq/ack plausibles a los paquetes TCP ya construidos (los builders no lo hacen)."""
    flow = {}
    out = []
    for p in packets:
        if TCP in p:
            key = (p[IP].src, p[IP].dst, int(p[TCP].sport), int(p[TCP].dport))
            stamps = flow.setdefault(key, {"next_seq": {}, "ack": 1000})
            src_s, dst_s = key[:4], (key[1], key[0], key[3], key[2])
            if src_s not in stamps["next_seq"]:
                stamps["next_seq"][src_s] = random.randint(1000, 4000)
                stamps["next_seq"][dst_s] = random.randint(1000, 4000)
            payload = bytes(p[TCP].payload) if p[TCP].payload else b""
            adv = max(1, len(payload))
            p[TCP].seq = stamps["next_seq"].get(src_s, stamps["ack"])
            p[TCP].ack = stamps["next_seq"].get(dst_s, stamps["ack"])
            p[TCP].window = 8192
            stamps["next_seq"][src_s] = p[TCP].seq + adv
        out.append(p)
    return out

# ----------------------------------------------------------------------------------
# Modos de entrega
# ----------------------------------------------------------------------------------
def out_pcap(path: str, loops: int, rng: random.Random):
    all_pkts = []
    for i in range(loops):
        base = _ts()
        scene = build_scene(rng)
        all_pkts.extend(scene)
    # reproducidas una tras otra (scapy les dará timestamps al hacer wrpcap)
    wrpcap(path, all_pkts)
    print(f"[✓] {len(all_pkts)} paquetes escritos en {path}")
    print(f"    Cárgalo en la app: Cargar PCAP, o curl -F file=@{path} http://localhost:8099/api/upload/pcap")

def out_live(iface: str, loops: int, rng: random.Random, delay: float):
    conf.verb = 0
    scene = seq_packets(build_scene(rng))
    print(f"[*] Enviando {len(scene) * loops} paquetes por {iface} (unlink layer2={iface!='lo'})…")
    for i in range(loops):
        for p in scene:
            if iface == "lo" and Ether in p:
                # loopback no tiene ethernet: fastidio; strip ethernet y deja ip directamente
                p = p[IP]
                p.src = "127.0.0.1"
                p.dst = "127.0.0.1"
                # reescribimos IPs internas también para que el analyzer las vea
                for layer in (IP,):
                    if layer in p:
                        pass
                send(p, iface="lo", verbose=0)
            else:
                sendp(p, iface=iface, verbose=0)
            time.sleep(delay)
    print("[✓] Enviado. La app (capturando sobre esa iface) ya debería mostrarlo.")

def out_real_local_http(loops: int):
    """Arranca un servidor HTTP de juguete en 127.0.0.1 y dispara requests reales; el
    sniffer corriendo sobre `lo` lo ve — mensajes con credenciales de URL + fichero."""
    import threading, urllib.request, urllib.parse
    from http.server import BaseHTTPRequestHandler, HTTPServer

    PNG_DATA = bytes.fromhex(
        "89504e470d0a1a0a0000000d4948445200000010000000100802000000909168360000004049444154"
        "78dacecl570000e02496d340000000049454e44ae426082")

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            if self.path.startswith("/secret"):
                self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
                self.wfile.write(b"<html><body><h1>bootstrap</h1><pre>password=test-pass admin=true "
                                 b"token api_key SESSION database host 3306 private key session</pre></body></html>")
            elif self.path.startswith("/img/house.png"):
                self.send_response(200); self.send_header("Content-Type", "image/png")
                self.send_header("Content-Disposition", 'attachment; filename="house.png"')
                self.send_header("Content-Length", str(len(PNG_DATA))); self.end_headers()
                self.wfile.write(PNG_DATA)
            elif self.path.startswith("/api/v1"):
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(b'{"query":"sftp","status":"DOWN","user":"root"}')
            elif self.path.startswith("/login-post"):
                self.send_response(302); self.send_header("Location", "/"); self.end_headers()
            else:
                self.send_response(404); self.end_headers()
        def do_POST(self):
            ln = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(ln)
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"ok":true}')

    srv = HTTPServer(("127.0.0.1", 8899), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("[*] Servidor de demo en http://127.0.0.1:8899 — generando tráfico REAL por loopback…")
    # priming: abrimos/llamamos a urls variadas
    urls = [
        ("/login?user=admin&password=S3cr3t123&session=abc",        "POST", b"user=admin&password=S3cr3t123&session=abc"),
        ("/img/house.png",  "GET", None),
        ("/api/v1/search?q=x&apikey=SK-TEST&email=demo%40mail.net", "GET", None),
        ("/secret",          "GET", None),
        ("/api/v1",          "GET", None),
        ("/login-post",      "POST", b"user=anakin&password=skywalker98&token=eyJ.abc"),
    ]
    for i in range(loops):
        for u, m, body in urls:
            data = body if m == "POST" else None
            req = urllib.request.Request("http://127.0.0.1:8899" + u, data=data, method=m,
                                         headers={"User-Agent": "demo-traffic/1.0",
                                                  "Content-Type": "application/x-www-form-urlencoded"})
            try:
                urllib.request.urlopen(req, timeout=3).read(512)
            except Exception:
                pass
            time.sleep(0.11)
    srv.shutdown()
    print("[✓] Tráfico HTTP real generado sobre loopback: puertos 8899 (cliente) y 8899 (server).")

# ----------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Tráfico de demo para SniffNex (o cualquier sniffer).")
    ap.add_argument("mode", choices=["pcap", "lo", "lo-real", "eth0", "wlan0", "any"],
                    help="pcap=escribe fichero · lo/eth0/wlan0=inyecta capa2+3 · lo-real=HTTP real localhost")
    ap.add_argument("outfile", nargs="?", default="/tmp/sniffnex_demo.pcap", help="PCAP de salida (solo modo pcap)")
    ap.add_argument("--loops", type=int, default=1, help="cuántas veces repetir la escena")
    ap.add_argument("--delay", type=float, default=0.08, help="pausa entre paquetes (live)")
    args = ap.parse_args()

    rng = random.Random(20260214)
    if args.mode == "pcap":
        out_pcap(args.outfile, args.loops, rng)
    elif args.mode == "lo":
        out_live("lo", args.loops, rng, args.delay)
    elif args.mode == "lo-real":
        out_real_local_http(args.loops)
    elif args.mode in ("eth0", "wlan0", "any"):
        out_live(args.mode, args.loops, rng, args.delay)

if __name__ == "__main__":
    main()
