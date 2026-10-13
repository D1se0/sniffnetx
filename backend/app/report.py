"""SniffNex — Informe PDF forense (generador reportlab).

Diseño completo: portada oscura con banda de acento, página de resumen con
gráficas (protocolos, top hosts, timeline), secciones con tablas zebra de
cabecera oscura, credenciales resaltadas en ámbar, bookmarks/outline
navegable y pie de página "página X de Y".
"""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4, landscape
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas

# ---------------------------------------------------------------- paleta ----
BG        = HexColor("#0b0f14")   # fondo portada
PANEL     = HexColor("#121820")   # fondo página normal
PANEL2    = HexColor("#181f2a")   # zebra alterno
HEADERBG  = HexColor("#1c2633")   # cabecera de tabla
BORDER    = HexColor("#263041")
ACCENT    = HexColor("#22d3ee")   # cian SniffNex
ACCENT_D  = HexColor("#0e7490")
GREEN     = HexColor("#4ade80")
RED       = HexColor("#f87171")
AMBER     = HexColor("#fbbf24")
TEXT      = HexColor("#e2e8f0")
MUTED     = HexColor("#8b98a9")

PAGE_W, PAGE_H = landscape(A4)            # 842 x 595 pt
MARGIN = 42
CONTENT_W = PAGE_W - 2 * MARGIN

LIMITS = {"hosts": 80, "files": 60, "messages": 60, "credentials": 60,
          "dns": 80, "parameters": 80, "keywords": 60, "sessions": 80}

SECTIONS_TITLES = {
    "hosts": "Hosts detectados en la red",
    "files": "Ficheros reconstruidos",
    "messages": "Mensajes obtenidos de la red",
    "credentials": "Credenciales detectadas",
    "dns": "Consultas DNS",
    "parameters": "Parámetros capturados",
    "keywords": "Keywords sensibles detectadas",
    "sessions": "Sesiones TCP/UDP",
}


def _register_fonts():
    """DejaVu (unicode completo) si existe; si no, alias Helvetica/Courier
    bajo los mismos nombres lógicos SN* para que el resto del módulo no cambie."""
    import os
    base = "/usr/share/fonts/truetype/dejavu"
    paths = [(base + "/DejaVuSans.ttf", "SNSans"),
             (base + "/DejaVuSans-Bold.ttf", "SNSans-Bold"),
             (base + "/DejaVuSansMono.ttf", "SNMono")]
    if all(os.path.exists(p) for p, _ in paths):
        for path, name in paths:
            pdfmetrics.registerFont(TTFont(name, path))
        return
    _std = {"SNSans": "Helvetica", "SNSans-Bold": "Helvetica-Bold", "SNMono": "Courier"}
    from reportlab.pdfbase import _fontdata  # noqa: permite mapear por nombre
    for alias, real in _std.items():
        if alias not in pdfmetrics._fonts:
            pdfmetrics.registerFont(pdfmetrics.Font(alias, real, "WinAnsiEncoding"))


def _clean(s) -> str:
    if s is None:
        return ""
    return str(s).replace("\r", " ").replace("\n", " ").strip()


def _wrap(c, text: str, font: str, size: float, max_w: float) -> list[str]:
    """Corta texto en líneas usando anchura real de glifos."""
    out: list[str] = []
    cur = ""
    for wd in _clean(text).split(" "):
        trial = (cur + " " + wd).strip() if cur else wd
        if c.stringWidth(trial, font, size) <= max_w:
            cur = trial
            continue
        if cur:
            out.append(cur)
            cur = ""
        while len(wd) > 1 and c.stringWidth(wd, font, size) > max_w:
            lo, hi = 1, len(wd)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if c.stringWidth(wd[:mid], font, size) <= max_w:
                    lo = mid
                else:
                    hi = mid - 1
            out.append(wd[:lo])
            wd = wd[lo:]
        cur = wd
    if cur:
        out.append(cur)
    return out or [""]


class _Ctx:
    def __init__(self, snap, sections):
        self.snap, self.sections = snap, sections


class _Doc:
    """Wrapper de dibujo con cursor vertical + tabla zebra."""

    def __init__(self, c, ctx: _Ctx):
        self.c = c
        self.ctx = ctx
        self.y = PAGE_H - MARGIN

    def new_page(self):
        self.c.showPage()
        self.c.setFillColor(PANEL)
        self.c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
        self.c.setFillColor(ACCENT)
        self.c.rect(0, 0, 4, PAGE_H, stroke=0, fill=1)
        self.y = PAGE_H - MARGIN

    def need(self, h: float):
        if self.y - h < MARGIN + 30:
            self.new_page()

    def section_header(self, name: str, count: int):
        c = self.c
        c.bookmarkPage(f"sec_{name}")
        c.addOutlineEntry(SECTIONS_TITLES.get(name, name), f"sec_{name}", level=0)
        self.need(90)
        y = self.y - 6
        c.setFillColor(ACCENT)
        c.rect(MARGIN, y - 16, 3.5, 19, stroke=0, fill=1)
        c.setFillColor(TEXT)
        c.setFont("SNSans-Bold", 14.5)
        c.drawString(MARGIN + 12, y - 12, SECTIONS_TITLES.get(name, name))
        cnt = f"{count} registros"
        w = c.stringWidth(cnt, "SNSans", 8.5) + 16
        c.setFillColor(HEADERBG)
        c.roundRect(PAGE_W - MARGIN - w, y - 15, w, 15, 4, stroke=0, fill=1)
        c.setFillColor(ACCENT)
        c.setFont("SNSans", 8.5)
        c.drawCentredString(PAGE_W - MARGIN - w / 2, y - 10.6, cnt)
        self.y = y - 28

    def empty_note(self):
        self.c.setFillColor(MUTED)
        self.c.setFont("SNSans", 9)
        self.c.drawString(MARGIN, self.y - 4, "(sin datos capturados)")
        self.y -= 20

    def table(self, headers, rows, widths, size=8.0, mono=(),
              color_rules=None):
        """Tabla con cabecera oscura, zebra, wrap por columna y hairlines."""
        c = self.c
        pad = 5

        def _draw_header():
            hh = size + 10
            top = self.y
            c.setFillColor(HEADERBG)
            c.roundRect(MARGIN, top - hh - 3, CONTENT_W, hh + 3, 3, stroke=0, fill=1)
            c.setFillColor(ACCENT)
            c.setFont("SNSans-Bold", size)
            x = MARGIN + 6
            for i, hcell in enumerate(headers):
                c.drawString(x + pad, top - hh + 2, _clean(hcell).upper())
                x += widths[i]
            self.y -= hh + 9

        _draw_header()
        if not rows:
            return

        for i_row, r in enumerate(rows):
            cells = []
            hmax = 1
            for i, cell in enumerate(r):
                fnt = "SNMono" if i in mono else "SNSans"
                lines = _wrap(c, cell, fnt, size, widths[i] - 2 * pad - 1)
                cells.append((fnt, lines))
                hmax = max(hmax, len(lines))
            rh = hmax * (size + 2.6) + 8
            if self.y - rh < MARGIN + 30:
                self.new_page()
                _draw_header()
            rowbg = PANEL2 if i_row % 2 else PANEL
            bg_hex, fg_hex = (None, None)
            if color_rules:
                bg_hex, fg_hex = color_rules(r)
            if bg_hex:
                rowbg = HexColor(bg_hex)
            c.setFillColor(rowbg)
            c.rect(MARGIN, self.y - rh, CONTENT_W, rh, stroke=0, fill=1)
            c.setStrokeColor(BORDER)
            c.setLineWidth(0.5)
            c.line(MARGIN, self.y - rh, PAGE_W - MARGIN, self.y - rh)
            x = MARGIN + 6
            ty = self.y - size - 3.5
            yy = ty
            for i, (fnt, lines) in enumerate(cells):
                if fg_hex:
                    fg = HexColor(fg_hex)
                elif i in mono:
                    fg = HexColor("#a5d8f7")
                else:
                    fg = TEXT
                c.setFillColor(fg)
                c.setFont(fnt, size)
                yy = ty
                for ln in lines:
                    c.drawString(x, yy, ln)
                    yy -= size + 2.6
                x += widths[i]
            self.y -= rh
        self.y -= 10
        c.setStrokeColor(HexColor("#1a2230"))
        c.setLineWidth(0.6)
        c.line(MARGIN, self.y + 5, PAGE_W - MARGIN, self.y + 5)


def _fmt_size(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    if n < 1024:
        return f"{int(n)} B"
    for unit in ("KB", "MB", "GB"):
        n /= 1024
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
    return "—"


def _bar_chart(c, doc, title: str, items, x0, width, label_w=88, mono=False):
    if not items:
        return
    c.setFillColor(MUTED)
    c.setFont("SNSans-Bold", 8.5)
    c.drawString(x0, doc.y, _clean(title).upper())
    doc.y -= 11
    vmax = max([1] + [v for _, v, _ in items])
    bar_x = x0 + label_w
    bar_w = width - label_w - 52
    yy = doc.y - 3
    for lab, val, col in items:
        frac = min(val / vmax, 1) if vmax else 0
        c.setFillColor(HexColor("#1a2230"))
        c.roundRect(bar_x, yy - 4, bar_w, 10, 3, stroke=0, fill=1)
        if frac > 0:
            c.setFillColor(col)
            c.roundRect(bar_x, yy - 4, max(4, bar_w * frac), 10, 3, stroke=0, fill=1)
        c.setFillColor(TEXT)
        c.setFont("SNMono" if mono else "SNSans", 7.6)
        c.drawString(x0, yy - 2, _clean(lab)[:18])
        c.setFillColor(MUTED)
        c.setFont("SNSans", 7)
        c.drawRightString(x0 + width, yy - 2, f"{val:,}")
        yy -= 17
    doc.y = yy - 10


def _timeline(c, doc, snap):
    """Histograma eventos/minuto a partir de ts de mensajes/DNS/parámetros…"""
    from collections import Counter
    evs = []
    for sec in ("messages", "dns", "parameters", "keywords", "credentials"):
        for r in snap.get(sec, []):
            ts = r.get("ts")
            if ts and len(ts) >= 16:
                evs.append(ts[:16])
    if not evs:
        return
    bins = sorted(Counter(evs).items())
    n = len(bins)
    c.setFillColor(MUTED)
    c.setFont("SNSans-Bold", 8.5)
    c.drawString(MARGIN, doc.y, "LÍNEA DE ACTIVIDAD (eventos por minuto)")
    doc.y -= 11
    h_plot = 72
    x0 = MARGIN + 26
    plot_w = CONTENT_W - 26
    base_y = doc.y - h_plot - 10
    c.setStrokeColor(BORDER)
    c.setLineWidth(0.7)
    c.line(x0, base_y, x0 + plot_w, base_y)
    c.line(x0, base_y, x0, base_y + h_plot)
    vmax = max(v for _, v in bins)
    bw = max(3, plot_w / n - 3)
    for i, (tmin, v) in enumerate(bins[:200]):
        xx = x0 + i * (plot_w / n) + 1
        c.setFillColor(ACCENT if i % 2 == 0 else ACCENT_D)
        c.rect(xx, base_y + 1, bw, max(2, (h_plot - 8) * (v / vmax)), stroke=0, fill=1)
    c.setFillColor(MUTED)
    c.setFont("SNMono", 6.8)
    c.drawString(x0, base_y - 10, bins[0][0].replace("T", " "))
    c.drawRightString(x0 + plot_w, base_y - 10, bins[-1][0].replace("T", " "))
    c.setFillColor(MUTED)
    c.setFont("SNSans", 7)
    c.drawRightString(x0 + plot_w, base_y + h_plot + 3, f"máx {vmax} ev/min")
    doc.y = base_y - 24


def _cred_fg(r):
    t, pw = r[0], r[2]
    if pw and pw != "—":
        return "#2a1c10", AMBER.hexval()[2:] if hasattr(AMBER, "hexval") else "#fbbf24"
    return None, None


# --------------------------------------------------------------------------
def _build(c, ctx):
    snap, sections = ctx.snap, ctx.sections
    st = snap.get("stats", {})
    doc = _Doc(c, ctx)
    gen = datetime.now(tz=timezone.utc)

    # ----------------------------------------------------------- PORTADA ---
    c.setFillColor(BG)
    c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
    # retícula decorativa sutil
    c.setStrokeColor(HexColor("#131b25"))
    c.setLineWidth(0.5)
    yy = 0
    while yy < PAGE_H:
        c.line(0, yy, PAGE_W, yy)
        yy += 36
    xx = 0
    while xx < PAGE_W:
        c.line(xx, 0, xx, PAGE_H)
        xx += 36
    # banda superior de acento
    c.setFillColor(HexColor("#155e75"))
    c.rect(0, PAGE_H - 8, PAGE_W, 8, stroke=0, fill=1)
    c.setFillColor(ACCENT)
    c.rect(0, PAGE_H - 8, PAGE_W * 0.30, 8, stroke=0, fill=1)

    # chip logo
    c.setFillColor(ACCENT_D)
    c.roundRect(MARGIN, PAGE_H - 88, 30, 30, 6, stroke=0, fill=1)
    c.setFillColor(ACCENT)
    c.setFont("SNSans-Bold", 17)
    c.drawCentredString(MARGIN + 15, PAGE_H - 79, "S")
    c.setFillColor(MUTED)
    c.setFont("SNSans", 9.5)
    c.drawString(MARGIN + 40, PAGE_H - 78, "SNIFFNEX  ·  NETWORK FORENSICS  ·  v1.0")

    # título bicolour
    c.setFont("SNSans-Bold", 40)
    c.setFillColor(TEXT)
    c.drawString(MARGIN, PAGE_H - 174, "Informe forense")
    w = c.stringWidth("Informe forense ", "SNSans-Bold", 40)
    c.setFillColor(HexColor("#67e8f9"))
    c.drawString(MARGIN + w, PAGE_H - 174, "de red")

    c.setFillColor(MUTED)
    c.setFont("SNSans", 12)
    c.drawString(MARGIN, PAGE_H - 202,
                 "Captura, análisis y correlación de tráfico de red")

    c.setFont("SNSans", 10.5)
    c.setFillColor(MUTED)
    c.drawString(MARGIN, PAGE_H - 252, f"Generado:  {gen.strftime('%d/%m/%Y · %H:%M:%S UTC')}")
    c.drawString(MARGIN, PAGE_H - 268, f"Paquetes:  {st.get('packets', 0):,}")
    if st.get("started"):
        c.drawString(MARGIN + 110, PAGE_H - 252,
                     f"Inicio de captura:  {datetime.fromtimestamp(st['started'], tz=timezone.utc).strftime('%d/%m/%Y %H:%M:%S')} UTC")

    # cards de métricas
    metrics = [("Paquetes", st.get("packets", 0), ACCENT),
               ("TCP", st.get("tcp", 0), HexColor("#60a5fa")),
               ("UDP", st.get("udp", 0), HexColor("#a78bfa")),
               ("ICMP", st.get("icmp", 0), AMBER),
               ("ARP", st.get("arp", 0), HexColor("#f472b6")),
               ("HTTP", st.get("http", 0), GREEN),
               ("DNS", st.get("dns", 0), HexColor("#38bdf8"))]
    cw, ch, gap = 96, 74, 10
    x = MARGIN
    for lab, val, col in metrics:
        top = PAGE_H - 312
        c.setFillColor(PANEL2)
        c.roundRect(x, top - ch, cw, ch, 8, stroke=0, fill=1)
        c.setStrokeColor(BORDER)
        c.setLineWidth(0.8)
        c.roundRect(x, top - ch, cw, ch, 8, stroke=1, fill=0)
        c.setFillColor(col)
        c.rect(x + 10, top - 24, 22, 3.5, stroke=0, fill=1)
        c.setFillColor(TEXT)
        c.setFont("SNSans-Bold", 20)
        c.drawString(x + 10, top - 52, f"{val:,}")
        c.setFillColor(MUTED)
        c.setFont("SNSans", 8)
        c.drawString(x + 10, top - ch + 12, lab.upper())
        x += cw + gap

    # índice navegable
    toc_top = PAGE_H - 440
    c.setFillColor(TEXT)
    c.setFont("SNSans-Bold", 11.5)
    c.drawString(MARGIN, toc_top, "CONTENIDO DEL INFORME")
    c.setFillColor(HexColor("#2c3a4d"))
    c.rect(MARGIN + 178, toc_top + 3, CONTENT_W - 178, 0.8, stroke=0, fill=1)
    yy = toc_top - 26
    for i, name in enumerate(sections):
        if yy < 72:
            break
        c.setFillColor(ACCENT)
        c.setFont("SNMono", 10)
        c.drawString(MARGIN, yy, f"{i + 1:02d}")
        c.setFillColor(TEXT)
        c.setFont("SNSans", 10.5)
        c.drawString(MARGIN + 26, yy, SECTIONS_TITLES.get(name, name))
        c.setFillColor(MUTED)
        c.setFont("SNSans", 9)
        c.drawRightString(PAGE_W - MARGIN, yy, f"{len(snap.get(name, []))} registros")
        c.linkAbsolute("", f"sec_{name}", (MARGIN, yy - 4, PAGE_W - MARGIN, yy + 12))
        c.setStrokeColor(HexColor("#1c2633"))
        c.setLineWidth(0.6)
        c.line(MARGIN, yy - 9, PAGE_W - MARGIN, yy - 9)
        yy -= 21

    c.setFillColor(MUTED)
    c.setFont("SNSans", 8.5)
    c.drawString(MARGIN, 36, "SniffNex · github.com/d1se0/sniffnetx · GPL-3.0")
    c.drawRightString(PAGE_W - MARGIN, 36, f"report id  {gen.strftime('%Y%m%d-%H%M%S')}")

    # ----------------------------------------------------------- RESUMEN ---
    doc.new_page()
    c = doc.c
    c.setFillColor(ACCENT)
    c.rect(MARGIN, doc.y - 16, 3.5, 19, stroke=0, fill=1)
    c.setFillColor(TEXT)
    c.setFont("SNSans-Bold", 14.5)
    c.drawString(MARGIN + 12, doc.y - 12, "Resumen ejecutivo")
    doc.y -= 40

    proto = [("TCP", st.get("tcp", 0), HexColor("#60a5fa")),
             ("UDP", st.get("udp", 0), HexColor("#a78bfa")),
             ("ICMP", st.get("icmp", 0), AMBER),
             ("ARP", st.get("arp", 0), HexColor("#f472b6")),
             ("HTTP", st.get("http", 0), GREEN),
             ("DNS", st.get("dns", 0), HexColor("#38bdf8")),
             ("Otros", st.get("other_l4", 0), MUTED)]
    _bar_chart(c, doc, "Distribución de protocolos", proto, x0=MARGIN,
               width=CONTENT_W * 0.60, label_w=54)
    hosts_top = sorted(snap.get("hosts", []), key=lambda h: -h.get("bytes_count", 0))[:8]
    if hosts_top:
        _bar_chart(c, doc, "Top hosts por bytes",
                   [(h.get("ip", "?"), h.get("bytes_count", 0), ACCENT) for h in hosts_top],
                   x0=MARGIN + CONTENT_W * 0.63, width=CONTENT_W * 0.37,
                   label_w=126, mono=True)
    doc.y -= 12
    _timeline(c, doc, snap)

    # ------------------------------------------------------- SECCIONES -----
    for name in sections:
        doc.new_page()
        rows_src = snap.get(name, [])
        doc.section_header(name, len(rows_src))
        if not rows_src:
            doc.empty_note()
            continue
        lim = LIMITS.get(name, 50)
        shown = min(len(rows_src), lim)

        if name == "hosts":
            hs = ["IP", "MAC", "Fabricante", "Hostname", "SO", "TTL", "Env", "Recv", "Bytes", "Puertos"]
            ws = [90, 106, 84, 94, 66, 28, 40, 40, 60, 192]
            rows = [[h.get("ip", ""), (h.get("mac", "") or "—").lower(), h.get("nic_vendor") or "—",
                     h.get("hostname") or "—", str(h.get("os_guess") or "—"), str(h.get("ttl_min", "—")),
                     str(h.get("sent", 0)), str(h.get("recv", 0)), f"{h.get('bytes_count', 0):,}",
                     ", ".join(str(p) for p in (h.get("ports_open") or [])[:12]) or "—"]
                    for h in rows_src[:lim]]
            doc.table(hs, rows, ws, size=7.6, mono=(0, 1, 6, 7, 8))

        elif name == "sessions":
            hs = ["Origen", "Destino", "Servicio", "Estado", "Pkts", "Bytes", "Inicio → Fin"]
            ws = [118, 118, 80, 96, 38, 62, 246]
            rows = [[f"{s.get('src')}:{s.get('sport')}", f"{s.get('dst')}:{s.get('dport')}",
                     s.get("service", ""), s.get("state", ""), str(s.get("packets", 0)),
                     f"{s.get('bytes', 0):,}",
                     f"{(s.get('start') or '')[11:19]} → {(s.get('end') or '')[11:19]}"]
                    for s in rows_src[:lim]]
            doc.table(hs, rows, ws, size=7.8, mono=(0, 1, 4, 5, 6),
                      color_rules=lambda r: (None, "#fbbf24" if r[3] == "ESTABLISHED" else None))

        elif name == "files":
            hs = ["Fichero", "MIME", "Tamaño", "Origen → Destino", "Hora"]
            ws = [210, 150, 60, 254, 86]
            rows = [[f.get("filename", "?"), (f.get("mime", "") or f.get("content_type", ""))[:30],
                     _fmt_size(f.get("size", 0)), f"{f.get('src', '—')} → {f.get('dst', '—')}",
                     (f.get("ts", "") or "")[11:19]]
                    for f in rows_src[:lim]]
            doc.table(hs, rows, ws, size=7.8, mono=(1, 2, 4))

        elif name == "credentials":
            hs = ["Tipo", "Usuario", "Password", "Dominio / Servidor", "Origen", "Hora"]
            ws = [92, 118, 140, 170, 110, 128]
            rows = [[(c.get("type", "") or "?").upper(), c.get("user") or "—",
                     c.get("password") or c.get("hash") or "—",
                     c.get("domain") or (str(c.get("port")) if c.get("port") else "—"),
                     c.get("src") or "—", (c.get("ts", "") or "")[11:19]]
                    for c in rows_src[:lim]]
            doc.table(hs, rows, ws, size=7.8, mono=(2, 5),
                      color_rules=lambda r: ("#2a1c10", "#fbbf24") if r[2] != "—" else (None, None))

        elif name == "dns":
            hs = ["Hora", "Consultor", "Servidor", "Tipo", "Dominio consultado", "Respuesta"]
            ws = [52, 104, 104, 40, 220, 238]
            rows = []
            for d in rows_src[:min(lim, 45)]:
                qs = d.get("questions") or [{}]
                for q in qs:
                    answ = "; ".join(_clean(a.get("data") or a.get("type"))
                                     for a in (d.get("answers") or [])[:3]) or "—"
                    host, srv = ((d.get("src"), d.get("dst")) if not d.get("is_response")
                                 else (d.get("dst"), d.get("src")))
                    rows.append([(d.get("ts", "") or "")[11:19], host or "—", srv or "—",
                                 q.get("type", "—"), q.get("name") or "—", answ])
            doc.table(hs, rows, ws, size=7.6, mono=(0, 1, 2, 3))

        elif name == "messages":
            hs = ["Tipo", "Origen", "Destino", "Detalle"]
            ws = [84, 112, 112, 450]
            rows = [[m.get("type", ""), m.get("src") or "—", m.get("dst") or "—",
                     _clean((m.get("method", "") or "") + " " +
                            _clean(m.get("path") or m.get("subject") or
                                   _clean(m.get("body", ""))[:70]))[:96]]
                    for m in rows_src[:lim]]
            doc.table(hs, rows, ws, size=7.8, mono=(0,))

        elif name == "parameters":
            hs = ["Parámetro", "Valor", "Contexto", "Origen", "Hora"]
            ws = [110, 210, 140, 150, 148]
            rows = [[p.get("key", ""), _clean(p.get("value", ""))[:46], p.get("kind", ""),
                     p.get("src") or "—", (p.get("ts", "") or "")[11:19]]
                    for p in rows_src[:lim]]
            doc.table(hs, rows, ws, size=7.8, mono=(2, 4),
                      color_rules=lambda r: ("#2a1c10", "#fbbf24")
                      if r[0].lower() in ("password", "passwd", "pwd", "token", "pass") else (None, None))

        elif name == "keywords":
            hs = ["Keyword", "Servicio", "Origen", "Destino", "Contexto alrededor"]
            ws = [84, 82, 114, 114, 364]
            rows = [[(k.get("keyword", "") or "").upper(), k.get("service", ""), k.get("src") or "—",
                     k.get("dst") or "—", _clean(k.get("context", ""))[:86]]
                    for k in rows_src[:lim]]
            doc.table(hs, rows, ws, size=7.6, mono=(0, 1),
                      color_rules=lambda r: (None, "#f87171"))

        if len(rows_src) > shown:
            doc.need(18)
            doc.c.setFillColor(MUTED)
            doc.c.setFont("SNSans", 8)
            doc.c.drawString(MARGIN, doc.y - 2,
                             f"… {len(rows_src) - shown} registros más disponibles en la exportación completa (JSON/CSV).")
            doc.y -= 14


# --------------------------------------------------------------------------
class _FooterCanvas(rl_canvas.Canvas):
    """Redibuja el pie en cada página al final para escribir 'página X de Y'."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        gen = datetime.now(tz=timezone.utc).strftime("%d/%m/%Y %H:%M UTC")
        for i, state in enumerate(self._saved):
            self.__dict__.update(state)
            if i > 0:                      # la portada no lleva pie estándar
                self.setFillColor(PANEL)
                self.rect(0, 0, PAGE_W, 24, stroke=0, fill=1)
                self.setFillColor(HexColor("#1c2633"))
                self.rect(0, 23.4, PAGE_W, 0.6, stroke=0, fill=1)
                self.setFillColor(ACCENT)
                self.setFont("SNSans-Bold", 8)
                self.drawString(MARGIN, 9, "SniffNex")
                self.setFillColor(MUTED)
                self.setFont("SNSans", 7.5)
                self.drawCentredString(PAGE_W / 2, 9, "Informe forense de red")
                self.setFillColor(TEXT)
                self.setFont("SNSans", 8)
                self.drawRightString(PAGE_W - MARGIN, 9, f"página {i + 1} / {total}   ·   {gen}")
            rl_canvas.Canvas.showPage(self)
        rl_canvas.Canvas.save(self)


def make_pdf(sections, snap: dict) -> bytes:
    _register_fonts()
    buf = BytesIO()
    real = _FooterCanvas(buf, pagesize=(PAGE_W, PAGE_H))
    real.setTitle("SniffNex — Informe forense de red")
    real.setAuthor("SniffNex")
    real.setSubject("Captura y análisis de tráfico de red")
    real.setCreator("SniffNex · github.com/d1se0/sniffnetx")
    real.setKeywords(["sniffer", "forense", "red", "pcap", "sniffnex"])
    _build(real, _Ctx(snap, list(sections)))
    real.save()
    return buf.getvalue()
