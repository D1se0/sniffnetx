"""SniffNex - Motor de captura en vivo + lector de PCAP.

 - CaptureEngine: hilo sniffer con START/STOP, BPF filter, snaplen,
   buffer circular de paquetes (para exportar PCAP) y analizador en vivo.
 - load_offline_pcap(): reutiliza el mismo analizador sobre un .pcap/.pcapng.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import conf, sniff, PcapWriter, rdpcap, wrpcap
from scapy.arch import get_if_list

from .analysis import TrafficAnalyzer


class CaptureEngine:
    """Gestiona UNA captura activa (start/stop) compartiendo analizador."""

    def __init__(self, app_state):
        self.app = app_state
        self.thread: threading.Thread | None = None
        self.stop_evt = threading.Event()
        self.running = False
        self.iface = ""
        self.filter = ""
        self.started_at = 0.0
        self.buffer: deque = deque(maxlen=100000)  # paquetes crudos para exportar
        self._lock = threading.Lock()

    # ------------------------------------------------------------- adaptadores
    @staticmethod
    def list_interfaces() -> list[dict]:
        """Lista interfaces de red con IP/MAC/flags usando scapy + /sys."""
        from scapy.interfaces import get_working_if
        out = {}
        try:
            for name in get_if_list():
                out[name] = {"name": name, "mac": "", "ip": "", "up": False, "loopback": name == "lo", "default": False}
        except Exception:
            pass
        # estado UP desde /sys/class/net
        try:
            for name, d in out.items():
                flags = Path(f"/sys/class/net/{name}/flags").read_text().strip()
                d["up"] = bool(int(flags, 16) & 0x1)
        except Exception:
            pass
        # IPs por ruta de scapy
        try:
            from scapy.all import conf
            for r in conf.route.routes:
                iface, ipnet = r[3], r[4]
                if iface in out and ipnet:
                    out[iface]["ip"] = ipnet
        except Exception:
            pass
        # MACs
        try:
            from scapy.arch import get_if_hwaddr
            for name, d in out.items():
                try:
                    d["mac"] = get_if_hwaddr(name)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            wif = get_working_if()
            if wif in out:
                out[wif]["default"] = True
        except Exception:
            pass
        return list(out.values())

    # ------------------------------------------------------------- start/stop
    def start(self, iface: str, bpf: str = "", snaplen: int = 65535, promisc: bool = True, pcap_out: str | None = None):
        if self.running:
            raise RuntimeError("La captura ya esta en marcha")
        self.stop_evt.clear()
        self.buffer.clear()
        self.iface = iface
        self.filter = bpf
        self.started_at = time.time()
        self.running = True

        def _run():
            def _cb(pkt):
                if self.stop_evt.is_set():
                    return True  # detiene el sniff() de scapy
                try:
                    self.app.analyzer.process(pkt)
                except Exception:
                    pass   # un paquete malformato no debe matar la captura
                with self._lock:
                    self.buffer.append(pkt)
                try:
                    self.app.note_packet()
                except Exception:
                    pass
            kwargs = dict(iface=iface or None, filter=bpf or None, prn=_cb,
                          store=False, stop_filter=lambda _p: self.stop_evt.is_set(),
                          promisc=promisc, timeout=2)
            if snaplen and snaplen != 65535:
                # scapy 2.5 no acepta snaplen en L2Socket: se usa conf.snaplen si se pasa explicito
                try:
                    kwargs["snaplen"] = snaplen
                except Exception:
                    pass
            # Bucle externo: sniﬀ() con timeout=2 solo escucharía 2 s; Re-lanzarlo
            # indefinidamente hasta que stop_evt se active — así el botón Detener
            # es lo único que corta la captura.
            try:
                while not self.stop_evt.is_set():
                    if not self.running:
                        break
                    try:
                        sniff(**kwargs)
                    except Exception as e:   # permisos / iface invalida
                        if not self.stop_evt.is_set():
                            self.app.capture_error(str(e))
                        break
            except Exception as e:
                if not self.stop_evt.is_set():
                    self.app.capture_error(f"hilo captura: {e}")
            finally:
                self.running = False
                try:
                    self.app.capture_stopped()
                except Exception:
                    pass

        self.thread = threading.Thread(target=_run, daemon=True, name="sniffnex-capture")
        self.thread.start()

    def stop(self):
        self.stop_evt.set()
        if self.thread:
            self.thread.join(timeout=6)
        self.running = False

    def get_buffer_pkts(self, limit: int | None = None):
        with self._lock:
            pkts = list(self.buffer)
        if limit:
            pkts = pkts[-limit:]
        return pkts


def load_offline_pcap(path: str, analyzer: TrafficAnalyzer, progress_cb=None, engine=None) -> int:
    """Lee un .pcap/.pcapng y procesa cada paquete con el analizador.
    Si se pasa engine, además rellena el buffer circular para que el
    PacketExplorer y el follow-stream funcionen también en modo offline."""
    from scapy.utils import PcapReader

    n = 0
    with PcapReader(path) as pr:
        for pkt in pr:
            analyzer.process(pkt)
            if engine is not None:
                with engine._lock:
                    engine.buffer.append(pkt)
            n += 1
            if progress_cb and n % 500 == 0:
                progress_cb(n)
    return n


def export_pcap(pkts: list, out_path: str) -> int:
    """Escribe una lista de paquetes Scapy a un .pcap clasico."""
    wrpcap(out_path, pkts)
    return len(pkts)
