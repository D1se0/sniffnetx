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
from .report import make_pdf as _make_pdf

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
        data = {"_meta": {
                    "tool": "SniffNex", "version": "1.0.0",
                    "generated": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
                    "stats": snap.get("stats", {}), "sections": sections,
                },
                **{s: snap[s] for s in sections}}
        return JSONResponse(data, headers={"Content-Disposition": "attachment; filename=sniffnex_export.json"})
    if fmt == "csv":
        # BOM UTF-8 para que Excel/Sheets detecten la codificación y las tildes
        buf = io.StringIO(newline="")
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
        csv_data = "\ufeff" + buf.getvalue()
        return StreamingResponse(iter([csv_data]), media_type="text/csv; charset=utf-8",
                                 headers={"Content-Disposition": f"attachment; filename=sniffnex_{what}_{datetime.now(tz=timezone.utc).strftime('%Y%m%d_%H%M')}.csv"})
    if fmt == "pdf":
        pdf = _make_pdf(sections, snap)
        stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M")
        return StreamingResponse(iter([pdf]), media_type="application/pdf",
                                 headers={"Content-Disposition": f"attachment; filename=sniffnex_report_{stamp}.pdf"})
    raise HTTPException(400, "formato desconocido")


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
