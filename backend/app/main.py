"""SniffNex - API FastAPI: REST + WebSocket + exportaciones."""
from __future__ import annotations

import asyncio
import base64
import csv
import io
import json
import os
import shutil
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from .analysis import TrafficAnalyzer
from .capture import CaptureEngine, export_pcap, load_offline_pcap

app = FastAPI(title="SniffNex API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Servir el frontend compilado (../frontend/dist) — modo app desktop-portable
_FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


analyzer = TrafficAnalyzer()
class _State:
    """Puente CaptureEngine <-> analyzer global."""
    analyzer = None
    note_packet = None
    capture_error = None
    capture_stopped = None


engine = CaptureEngine(_State)
LIVE_CLIENTS: set[WebSocket] = set()
LIVE_LOCK = threading.Lock()


class StartReq(BaseModel):
    iface: str
    bpf: str = ""
    promisc: bool = True
    snaplen: int = 65535


# --------------------------------------------------------------------------
# Estado global para eventos en vivo (WebSockets)
# --------------------------------------------------------------------------
def note_packet():
    pass  # la presión por WebSocket va por batch en el broadcaster


LAST_CAPTURE_ERROR = {"msg": "", "ts": 0.0}   # visible para el frontend vía /api/capture/status


def capture_error(msg):
    print(f"[capture-error] {msg}")
    LAST_CAPTURE_ERROR["msg"] = str(msg)
    LAST_CAPTURE_ERROR["ts"] = time.time()


def capture_stopped():
    pass


_State.analyzer = analyzer
_State.note_packet = note_packet
_State.capture_error = capture_error
_State.capture_stopped = capture_stopped


async def broadcaster():
    """Envia a los clientes un snapshot agregado cada segundo."""
    i = 0
    while True:
        await asyncio.sleep(1.0)
        if not LIVE_CLIENTS:
            continue
        snap = snapshot()
        msg = json.dumps(snap, default=str)
        dead = []
        for w in list(LIVE_CLIENTS):
            try:
                await w.send_text(msg)
            except Exception:
                dead.append(w)
        for d in dead:
            LIVE_CLIENTS.discard(d)


def snapshot(compact: bool = True) -> dict:
    with analyzer.lock:
        hosts = [h.to_dict() for h in analyzer.hosts.values()]
        hosts.sort(key=lambda h: -h["packet_count"])
        files = analyzer.files[-300:]
        if compact:
            # sin bytes crudos en el JSON: solo metadatos + flag de preview
            files = [{k: v for k, v in f.items() if not isinstance(v, (bytes, bytearray))} for f in files]
        return {
            "stats": analyzer.stats,
            "hosts": hosts,
            "files": files,
            "messages": analyzer.messages[-300:][::-1],
            "credentials": analyzer.credentials[-200:][::-1],
            "dns": analyzer.dns_queries[-300:][::-1],
            "parameters": analyzer.parameters[-500:][::-1],
            "keywords": analyzer.keyword_hits[-300:][::-1],
            "sessions": _sessions_dict(),
        }


def _sessions_dict():
    out = []
    for k, s in analyzer.sessions.items():
        out.append({
            "src": s.src, "dst": s.dst, "sport": s.sport, "dport": s.dport,
            "state": s.state, "service": s.service, "bytes": s.bytes,
            "packets": s.packets,
            "start": datetime.fromtimestamp(s.start, tz=timezone.utc).isoformat(timespec="seconds"),
            "end": datetime.fromtimestamp(s.end, tz=timezone.utc).isoformat(timespec="seconds"),
        })
    out.sort(key=lambda x: x["start"], reverse=True)
    return out[:500]


# --------------------------------------------------------------------------
# Endpoints REST
# --------------------------------------------------------------------------
@app.get("/api/interfaces")
def api_interfaces():
    return {"interfaces": CaptureEngine.list_interfaces()}


@app.post("/api/capture/start")
def api_start(req: StartReq):
    if engine.running:
        raise HTTPException(400, "Captura ya activa")
    analyzer.stats["started"] = time.time()
    try:
        engine.start(req.iface, req.bpf, req.snaplen, req.promisc)
    except PermissionError:
        raise HTTPException(403, "Permisos insuficientes: ejecuta con sudo/root (CAP_NET_RAW)")
    return {"ok": True, "iface": req.iface, "bpf": req.bpf}


@app.post("/api/capture/stop")
def api_stop():
    engine.stop()
    return {"ok": True}


@app.get("/api/capture/status")
def api_status():
    return {
        "running": engine.running,
        "iface": engine.iface,
        "bpf": engine.filter,
        "started_at": engine.started_at,
        "elapsed": time.time() - engine.started_at if engine.running else 0,
        "buffered_packets": len(engine.buffer),
        "last_error": LAST_CAPTURE_ERROR["msg"],
        "root": (os.geteuid() == 0 if hasattr(os, "geteuid") else False),
    }


@app.get("/api/can-capture")
def api_can_capture():
    """¿Puedo abrir un raw socket (permisos de captura)?"""
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(3))
        s.close()
        return {"can": True}
    except PermissionError:
        return {"can": False, "error": "sin CAP_NET_RAW", "uid": os.geteuid() if hasattr(os, "geteuid") else -1}


@app.get("/api/data")
def api_data():
    return snapshot()


@app.delete("/api/data")
def api_reset():
    global analyzer
    with analyzer.lock:
        analyzer = TrafficAnalyzer()
        _State.analyzer = analyzer
    return {"ok": True}


# ------------------------------- PCAP / ficheros ---------------------------
class PcapOutReq(BaseModel):
    limit: int = 5000


@app.post("/api/export/pcap")
def api_export_pcap(req: PcapOutReq):
    pkts = engine.get_buffer_pkts(req.limit)
    if not pkts:
        raise HTTPException(400, "No hay paquetes en el bufer (captura aun no iniciada o vacia)")
    out = Path(tempfile.gettempdir()) / f"sniffnex_{int(time.time())}.pcap"
    n = export_pcap(pkts, str(out))
    return FileResponse(str(out), media_type="application/vnd.tcpdump.pcap",
                        filename=out.name, background=None)


@app.post("/api/upload/pcap")
async def api_upload_pcap(file: UploadFile = File(...)):
    """Carga un PCAP/PCAPNG offline, lo analiza y devuelve el resumen."""
    global analyzer
    tmp = Path(tempfile.gettempdir()) / f"sniffnex_up_{int(time.time()*1000)}_{os.path.basename(file.filename or 'upload.pcap')}"
    try:
        with tmp.open("wb") as fh:
            shutil.copyfileobj(file.file, fh)
        parser = TrafficAnalyzer()
        def _prog(n):
            pass
        n = load_offline_pcap(str(tmp), parser, _prog)
        analyzer = parser
        _State.analyzer = parser
        return {"ok": True, "packets": n, "filename": file.filename}
    except Exception as e:
        raise HTTPException(500, f"No se pudo analizar el PCAP: {e}")
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


@app.get("/api/files/{fid}/preview")
def api_file_preview(fid: int):
    def _match(f):
        try:
            return int(f.get("id", -1)) == fid and f.get("data")
        except Exception:
            return False
    for f in analyzer.files:
        if _match(f):
            data = f["data"]
            mime = f.get(        "mime" if f.get("mime") else "mime", "application/octet-stream")
            if mime.startswith("image/"):
                b64 = base64.b64encode(data).decode()
                return {"ok": True,         "mime" if f.get("mime") else "mime": mime, "b64": b64, "size": len(data)}
            return JSONResponse({"ok": False, "reason": "sin preview"}, status_code=404)
    raise HTTPException(404, "fichero no encontrado")


@app.get("/api/files/{fid}/raw")
def api_file_raw(fid: int):
    def _match(f):
        try:
            return int(f.get("id", -1)) == fid and f.get("data")
        except Exception:
            return False
    for f in analyzer.files:
        if _match(f):
            data = f["data"]
            if isinstance(data, (bytes, bytearray)):
                mime = f.get("mime") or f.get("content_type") or "application/octet-stream"
                return StreamingResponse(iter([bytes(data)]),
                                         media_type=mime,
                                         headers={"Content-Disposition": f"attachment; filename={f.get('filename', 'file')}"})
    raise HTTPException(404, "fichero no encontrado")


# ------------------------------- Exportaciones -----------------------------
class ExportReq(BaseModel):
    what: str  # hosts, files, messages, credentials, dns, parameters, keywords, sessions, all
    fmt: str   # csv, json, pdf


@app.post("/api/export/{what}/{fmt}")
def api_export(what: str, fmt: str):
    snap = snapshot()
    if what not in ("hosts", "files", "messages", "credentials", "dns",
                    "parameters", "keywords", "sessions", "all"):
        raise HTTPException(404, f"seccion desconocida: {what}")
    sections = [what] if what != "all" else ["hosts", "files", "messages", "credentials", "dns", "parameters", "keywords", "sessions"]
    if fmt == "json":
        data = {s: snap[s] for s in sections}
        return JSONResponse(data, headers={"Content-Disposition": "attachment; filename=sniffnex_export.json"})
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        for s in sections:
            w.writerow([f"# {s.upper()}"])
            rows = snap[s]
            if s == "hosts":
                header = ["ip", "mac", "nic_vendor", "hostname", "os_guess", "ttl_min", "sent", "recv", "bytes", "ports_open", "first_seen", "last_seen"]
                w.writerow(header)
                for h in rows:
                    w.writerow([h["ip"], h["mac"], h["nic_vendor"], h["hostname"], h["os_guess"], h["ttl_min"], h["sent"], h["recv"], h["bytes_count"], " ".join(map(str, h["ports_open"])), h["first_seen"], h["last_seen"]])
            elif rows and isinstance(rows[0], dict):
                keys = list(rows[0].keys())
                w.writerow(keys)
                for r in rows:
                    w.writerow([str(r.get(k, "")) for k in keys])
            w.writerow([])
        return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                                 headers={"Content-Disposition": f"attachment; filename=sniffnex_{what}.csv"})
    if fmt == "pdf":
        pdf = _make_pdf(sections, snap)
        return StreamingResponse(iter([pdf]), media_type="application/pdf",
                                 headers={"Content-Disposition": f"attachment; filename=sniffnex_report.pdf"})
    raise HTTPException(400, "formato desconocido")


def _make_pdf(sections, snap: dict) -> bytes:
    """Genera un PDF 100% porcodigo conschrift con tablas por seccion."""
    import zlib

    PAGE_W, PAGE_H = 842, 595      # A4 landscape puntos

    def esc(t: str) -> str:
        return (t.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
                .encode("latin-1", "replace").decode("latin-1"))

    def wrap(s: str, n: int) -> str:
        words = str(s).split()
        if not words:
            return ""
        out = words[0][: n]
        line = out
        for wd in words[1:]:
            if len(line) + 1 + len(wd) <= n:
                line += " " + wd
            else:
                out += "\n" + wd[: n]
                line = wd
        return out

    streams = []

    def start_page(title: str):
        cmds = ["BT /F2 20 Tf 1 0 0 1 40 548 Tm", f"({esc(title)}) Tj", "ET"]
        cmds += _toc.setColor   # placeholder removed below
        return None  # never used

    class _Page:
        def __init__(self):
            self.parts: list[str] = []
            self.y = 545

        def title(self, s: str):
            self.parts.append(f"BT /F2 18 Tf 1 0 0 1 40 {self.y} Tm ({esc(s)}) Tj ET")
            self.y -= 34

        def text(self, s: str, font="F1", size=8.5, indent=40, lead=None):
            for line in s.split("\n"):
                if self.y < 40:
                    return False
                self.parts.append(f"BT /{font} {size} Tf 1 0 0 1 {indent} {self.y} Tm ({esc(line)}) Tj ET")
                self.y -= (lead or (size + 3))
            return True

        def table(self, headers, rows, widths, size=7.2):
            x = 40
            # cabecera
            self.parts.append("0.13 0.16 0.18 rg 40 40 q")
            self.parts.append("Q")
            cx = 40
            for i, hcell in enumerate(headers):
                self.parts.append(f"BT /F2 8 Tf 1 0 0 1 {cx} {self.y} Tm ({esc(hcell)}) Tj ET")
                cx += widths[i]
            self.y -= 16
            for r in rows:
                if self.y < 34:
                    return False
                cx = 40
                for i, cell in enumerate(r):
                    for ln in wrap(cell, int(widths[i] / (size * 0.5))).split("\n"):
                        if self.y < 34:
                            break
                        self.parts.append(f"BT /F1 {size} Tf 1 0 0 1 {cx} {self.y} Tm ({esc(ln)}) Tj ET")
                        self.y -= (size + 2)
                    self.y -= 2
                    cx += widths[i]
                self.y -= 8
                # línea
                self.parts.append(f"0.8 G 40 {self.y} m 802 {self.y} l S")
                self.y -= 2
            return True

        def footer(self, n: int):
            self.parts.append(f"BT /F1 8 Tf 1 0 0 1 40 20 Tm (SniffNex  |  pagina {n}  |  generado {datetime.now(tz=timezone.utc).isoformat(timespec='seconds')}) Tj ET")

    pages: list[_Page] = []
    cur = _Page()
    pages.append(cur)

    def new_if_needed():
        nonlocal cur
        if cur.y < 120:
            cur = _Page()
            pages.append(cur)

    st = snap.get("stats", {})
    if cur.text(f"SniffNex Network Forensics Report", "F2", 22):
        pass
    cur.y -= 10
    gen = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
    cur.text(f"Generado: {gen}   |   Paquetes: {st.get('packets', 0)}   TCP: {st.get('tcp', 0)}   UDP: {st.get('udp', 0)}   ARP: {st.get('arp', 0)}   HTTP: {st.get('http', 0)}   DNS: {st.get('dns', 0)}", "F1", 9.5)
    cur.y -= 14

    LIMITS = {"hosts": 60, "files": 40, "messages": 40, "credentials": 40, "dns": 60, "parameters": 60, "keywords": 40, "sessions": 60}

    def add_section(name: str):
        nonlocal cur
        if name not in sections:
            return
        rows_src = snap.get(name, [])
        new_if_needed()
        cur.title(SECTIONS_TITLES.get(name, name))
        if not rows_src:
            cur.text("(sin datos capturados)", "F1", 9)
            return
        if name == "hosts":
            headers3 = ["IP", "MAC", "Fabricante", "Hostname", "SO estimado", "TTLm", "Enviados", "Recibidos", "Bytes", "Puertos abiertos"]
            widths = [90, 105, 80, 90, 110, 32, 52, 52, 52, 87]
            rows = [[h["ip"], h["mac"], h["nic_vendor"], (h["hostname"] or "-")[:16], str(h["os_guess"])[:20], h["ttl_min"], h["sent"], h["recv"], h["bytes_count"], ",".join(str(p) for p in h["ports_open"][:16])] for h in rows_src[:LIMITS["hosts"]]]
            cur.table(headers3, rows, widths, size=7.0)
        elif name == "sessions":
            hs = ["Origen", "Dest", "Servicio", "Estado", "Pkt", "Bytes", "Inicio"]
            ws = [120, 120, 80, 90, 40, 70, 130]
            rows = [[s["src"] + ":" + str(s["sport"]), s["dst"] + ":" + str(s["dport"]), s["service"], s["state"], s["packets"], s["bytes"], s["start"][11:19]] for s in rows_src[:LIMITS["sessions"]]]
            cur.table(hs, rows, ws)
        elif name == "files":
            hs = ["Fichero", "MIME", "Tamano", "Origen", "Destino", "Hora"]
            ws = [180, 130, 60, 110, 110, 100]
            rows = [[f["filename"][:28], (f.get(        "mime" if f.get("mime") else "mime") or f.get("content_type", ""))[:24], f["size"], f.get("src", ""), f.get("dst", ""), f.get("ts", "")[11:19]] for f in rows_src[:LIMITS["files"]]]
            cur.table(hs, rows, ws)
        elif name == "credentials":
            hs = ["Tipo", "Usuario", "Password", "Dominio/Puerto", "Origen", "Hora"]
            ws = [110, 110, 130, 110, 110, 90]
            rows = [[c["type"], (c.get("user") or "-")[:24], (c.get("password") or c.get("hash") or "-")[:26], (c.get("domain") or str(c.get("port") or ""))[:22], c.get("src", ""), c.get("ts", "")[11:19]] for c in rows_src[:LIMITS["credentials"]]]
            cur.table(hs, rows, ws)
        elif name == "dns":
            hs = ["Hora", "Consultor", "Servidor", "Tipo", "Dominio", "Respuesta"]
            ws = [60, 100, 100, 50, 180, 190]
            rows = []
            for d in rows_src[:LIMITS["dns"]]:
                for q in d.get("questions", []) or [{}]:
                    answ = "; ".join(a["data"] or a["type"] for a in d.get("answers", [])[:3])
                    host, srv = (d["src"], d["dst"]) if not d["is_response"] else (d["dst"], d["src"])
                    rows.append([d.get("ts", "")[11:19], host, srv, q.get("type", ""), (q.get("name") or "")[:34], answ[:34]])
            if rows:
                cur.table(hs, rows, ws)
        elif name == "messages":
            hs = ["Tipo", "Origen", "Destino", "Detalle"]
            ws = [90, 110, 110, 430]
            rows = [[m.get("type", ""), m.get("src", ""), m.get("dst", ""), (m.get("method", "") + " " + (m.get("path", "") or m.get("subject", "") or (m.get("body", "") or "")[:60]))[:80]] for m in rows_src[:LIMITS["messages"]]]
            cur.table(hs, rows, ws)
        elif name == "parameters":
            hs = ["Param", "Valor", "Contexto", "Origen", "Hora"]
            ws = [110, 180, 130, 120, 70]
            rows = [[p.get("key", ""), str(p.get("value", ""))[:36], p.get("kind", ""), p.get("src", ""), p.get("ts", "")[11:19]] for p in rows_src[:LIMITS["parameters"]]]
            cur.table(hs, rows, ws)
        elif name == "keywords":
            hs = ["Keyword", "Servicio", "Origen", "Destino", "Contexto"]
            ws = [80, 80, 100, 100, 380]
            rows = [[k.get("keyword", ""), k.get("service", ""), k.get("src", ""), k.get("dst", ""), (k.get("context", "") or "")[:70]] for k in rows_src[:LIMITS["keywords"]]]
            cur.table(hs, rows, ws)

    for sec in sections:
        add_section(sec)

    # pie con numeros de pagina
    for i, pg in enumerate(pages, 1):
        pg.footer(i)

    # ---- ensamblado PDF
    def _as_pdf(pages: list[_Page]) -> bytes:
        objs: list[bytes] = []

        def add(b: bytes) -> int:
            objs.append(b)
            return len(objs)

        cat_id = add(b"<< /Type /Catalog /Pages 3 0 R >>")
        font1 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        font2 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        kids = []
        page_ids = []
        for pg in pages:
            content = "\n".join(pg.parts).encode("latin-1", "ignore")
            comp = zlib.compress(content)
            c_id = add(b"<< /Length " + str(len(comp)).encode() + b" /Filter /FlateDecode >>\nstream\n" + comp + b"\nendstream")
            p_id = add(("<< /Type /Page /Parent 3 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >> /Contents %d 0 R >>" % (PAGE_W, PAGE_H, font1, font2, c_id)).encode())
            page_ids.append(p_id)
            kids.append(f"{p_id} 0 R")
        pages_obj_id = 3  # reservado
        kids_str = " ".join(kids)
        objs[2] = (f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids_str}] >>").encode()
        info = add(b"<< /Producer (SniffNex) /Title (SniffNex Network Forensics Report) >>")
        tot = len(objs)
        buf = io.BytesIO()
        buf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for i, o in enumerate(objs, 1):
            offsets.append(buf.tell())
            buf.write(f"{i} 0 obj\n".encode() + o + b"\nendobj\n")
        xref = buf.tell()
        buf.write(f"xref\n0 {tot + 1}\n".encode())
        buf.write(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            buf.write(("%010d 00000 n \n" % off).encode())
        buf.write(f"trailer\n<< /Size {tot + 1} /Root {cat_id} 0 R /Info {info} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
        return buf.getvalue()

    return _as_pdf(pages)


SECTIONS_TITLES = {
    "hosts": "Hosts detectados en la red",
    "files": "Ficheros reconstruidos",
    "messages": "Mensajes obtenidos de la red",
    "credentials": "Credenciales detectadas",
    "dns": "Consultas DNS",
    "parameters": "Parametros y keywords",
    "keywords": "Keywords detectadas",
    "sessions": "Sesiones TCP/UDP",
}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    LIVE_CLIENTS.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        LIVE_CLIENTS.discard(ws)
    except Exception:
        LIVE_CLIENTS.discard(ws)


@app.on_event("startup")
async def _startup():
    asyncio.create_task(broadcaster())


@app.get("/api/packets/recent")
def api_packets_recent(limit: int = Query(300, le=2000)):
    """Resumen de los ultimos paquetes del buffer en vivo."""
    pkts = engine.get_buffer_pkts(limit)
    out = []
    base = len(engine.buffer) - len(pkts) + 1
    for i, p in enumerate(pkts):
        try:
            summary = p.summary()
        except Exception:
            summary = "(paquete indescifrable)"
        out.append({"n": base + i, "summary": summary})
    return {"packets": out}


@app.get("/api/health")
def health():
    return {"ok": True, "ts": datetime.now(tz=timezone.utc).isoformat(timespec="seconds")}


# ----- UI SPA: SIEMPRE la ultima ruta, para no tapar ninguna API -----
@app.get("/", include_in_schema=False)
def _index():
    if _FRONTEND_DIST.is_dir():
        return FileResponse(str(_FRONTEND_DIST / "index.html"))
    return JSONResponse({"ok": True, "ui": "no compilada: cd frontend && npm run build"})


@app.get("/{path:path}", include_in_schema=False)
def _spa(path: str):
    if _FRONTEND_DIST.is_dir():
        f = _FRONTEND_DIST / path
        if f.is_file() and str(f.resolve()).startswith(str(_FRONTEND_DIST.resolve())):
            return FileResponse(str(f))
        return FileResponse(str(_FRONTEND_DIST / "index.html"))
    raise HTTPException(404, "frontend no compilado")
