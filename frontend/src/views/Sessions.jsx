import React, { useState } from "react";
import { MessagesSquare, Loader2, X } from "lucide-react";

const STATE_COLORS = {
  ESTABLISHED: "c-green",
  SYN_SENT: "c-amber",
  SYN_ACK: "c-cyan",
  FIN_WAIT: "c-violet",
  RST: "c-red",
};

/** Convierte payload UTF-8 en segmentos legibles para el chat:
 *  HTTP: pinta petición/respuesta en bloque; texto libre: una línea por línea. */
function Bubble({ side, text }) {
  const isHttp = /GET |POST |PUT |HEAD |DELETE |HTTP\/1/.test(text.slice(0, 8));
  const blocks = isHttp ? splitHttp(text) : [text];
  return blocks.map((b, i) => (
    <div key={i} className={`chat-msg ${side === "C" ? "from-client" : "from-server"}`}>
      <span className="chat-who mono">{side === "C" ? "CLIENTE →" : "← SERVIDOR"}</span>
      <pre className="chat-body mono">{b}</pre>
    </div>
  ));
}

function splitHttp(text) {
  // separa peticiones/respuestas HTTP concatenadas en el stream
  const parts = text.split(/(?=GET |POST |PUT |HEAD |DELETE |HTTP\/1\.\d \d{3})/);
  return parts.filter(Boolean).slice(0, 24);
}

function StreamPanel({ sess, onClose }) {
  const [d, setD] = useState(null);
  const [busy, setBusy] = useState(true);
  const [err, setErr] = useState("");
  const load = async () => {
    setBusy(true); setErr("");
    try {
      const r = await fetch(`/api/stream?src=${encodeURIComponent(sess.src)}&sport=${sess.sport}&dst=${encodeURIComponent(sess.dst)}&dport=${sess.dport}&limit=600`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setD(await r.json());
    } catch (e) {
      setErr(String(e.message || e));
    } finally {
      setBusy(false);
    }
  };
  if (busy && !d && !err) load();
  const tot = d ? (d.segments || []).reduce((a, s) => a + s.len, 0) : 0;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="stream-modal card" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div className="section-title" style={{ margin: 0 }}>
            <MessagesSquare size={14} /> Follow stream · {sess.service}
          </div>
          <button className="close-x" onClick={onClose}><X size={13} /></button>
        </div>
        <div className="mono dim" style={{ fontSize: 11, margin: "6px 0 10px" }}>
          {sess.src}:{sess.sport} ⇄ {sess.dst}:{sess.dport} · {d ? `${(d.segments || []).length} segmentos · ${tot} B payload` : ""}
        </div>
        {err && <div className="alert-detail">{err}</div>}
        {busy && !d && <div className="mono dim">reensamblando stream… <Loader2 size={12} style={{ verticalAlign: "-2px" }} /></div>}
        {d && !(d.segments || []).length && (
          <div className="empty-note">No hay payload TCP en el buffer para esta sesión (UDP o ya depurado).
          El follow-stream funciona sobre la captura que esté en curso en este momento.</div>
        )}
        {d && (d.segments || []).map((s, i) => (
          s.len > 0 && (
            <Bubble key={`${s.n}-${i}`} side={s.side} text={hexToText(s.payload_hex)} />
          )
        ))}
      </div>
    </div>
  );
}

function hexToText(hex) {
  const bytes = (hex.match(/../g) || []).map((b) => parseInt(b, 16));
  return bytes.map((b) =>
    (b >= 32 && b < 127) || b === 10 || b === 13 || b === 9 ? String.fromCharCode(b) : "·"
  ).join("");
}

export default function Sessions({ data }) {
  const [q, setQ] = useState("");
  const [svc, setSvc] = useState("all");
  const [follow, setFollow] = useState(null);
  const [textOnly, setTextOnly] = useState(false);

  const rows = (data?.sessions || [])
    .filter((s) => svc === "all" || s.service === svc)
    .filter((s) => !q.trim() || `${s.src}:${s.sport} ${s.dst}:${s.dport} ${s.service} ${s.state}`.toLowerCase().includes(q.toLowerCase()));

  const services = [...new Set((data?.sessions || []).map((s) => s.service))].sort();

  return (
    <div>
      <div className="section-title">Sesiones TCP / UDP</div>
      <div className="section-sub">
        Quién habla con quién, por qué servicio y en qué estado. Pulsa <b>follow</b> en las TCP para leer la conversación reensamblada.
      </div>

      <div className="filters">
        <div style={{ position: "relative" }}>
          <Search size={14} style={{ position: "absolute", left: 10, top: 10, color: "var(--dim)" }} />
          <input className="f-input" placeholder="ip:port / servicio / estado …" value={q} onChange={(e) => setQ(e.target.value)}
            style={{ paddingLeft: 30, width: 280 }} spellCheck={false} />
        </div>
        <select className="f-select" value={svc} onChange={(e) => setSvc(e.target.value)}>
          <option value="all">Todos los servicios</option>
          {services.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="f-count">{rows.length} sesiones</span>
      </div>

      <div className="card">
        {!rows.length ? (
          <div className="empty"><div className="big">⇄</div>Sin sesiones registradas todavía.</div>
        ) : (
          <div className="tablewrap" style={{ maxHeight: "calc(100vh - 290px)" }}>
            <table className="data">
              <thead>
                <tr><th>Estado</th><th>Origen</th><th>Destino</th><th>Servicio</th><th>Pkts</th><th>Bytes</th><th>Inicio</th><th>Seguir</th></tr>
              </thead>
              <tbody>
                {rows.map((s, i) => (
                  <motion.tr key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: Math.min(i * 0.012, 0.25) }}>
                    <td><span className={`badge ${STATE_COLORS[s.state] || "c-dim"}`}>{s.state}</span></td>
                    <td className="mono" style={{ color: "var(--accent)" }}>{s.src}:{s.sport}</td>
                    <td className="mono" style={{ color: "var(--accent2)" }}>{s.dst}:{s.dport}</td>
                    <td>{s.service}</td>
                    <td className="mono">{s.packets}</td>
                    <td className="mono">{s.bytes?.toLocaleString?.() ?? s.bytes}</td>
                    <td className="mono dim" style={{ fontSize: 10.5 }}>{(s.start || "").slice(11, 19)}</td>
                    <td>
                      {s.sport === 443 || s.dport === 443 ? (
                        <span className="dim" style={{ fontSize: 10 }}>TLS cifrado</span>
                      ) : (
                        <button className="follow-btn" onClick={() => setFollow(s)}><MessagesSquare size={12} /> follow</button>
                      )}
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {follow && <StreamPanel sess={follow} onClose={() => setFollow(null)} />}
    </div>
  );
}
