import { useEffect, useState } from "react";
import { FileClock, Loader2, X, Plus, Trash2, StickyNote } from "lucide-react";

const KIND_META = {
  dns:    { cls: "k-dns",  label: "DNS" },
  http:   { cls: "k-http", label: "HTTP" },
  file:   { cls: "k-file", label: "FICHERO" },
  cred:   { cls: "k-cred", label: "CREDENCIAL" },
  kw:     { cls: "k-kw",   label: "KEYWORD" },
  alert:  { cls: "k-alert", label: "ALERTA" },
  session:{ cls: "k-session", label: "SESIÓN" },
};

export default function Dossier({ ip, onClose }) {
  const [d, setD] = useState(null);
  const [busy, setBusy] = useState(true);
  const [err, setErr] = useState("");
  const [filter, setFilter] = useState("all");
  const [tag, setTag] = useState("");
  const [text, setText] = useState("");

  const load = async () => {
    setBusy(true); setErr("");
    try {
      const r = await fetch(`/api/host/${encodeURIComponent(ip)}/dossier`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setD(await r.json());
    } catch (e) {
      setErr(String(e.message || e));
    } finally {
      setBusy(false);
    }
  };
  // la carga del dossier vive en un efecto, NUNCA en el cuerpo del render:
  // setState durante el render mete el componente en el bucle de updates de
  // fase de render (React #301) y desmonta todo el árbol sin error visible.
  useEffect(() => { load(); }, [ip]);

  const addNote = async () => {
    if (!text.trim()) return;
    await fetch("/api/notes", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: `host:${ip}`, tag: tag || "nota", text }),
    });
    setText(""); setTag("");
    setBusy(true); setD(null); load();
  };
  const delNote = async (id) => {
    await fetch(`/api/notes/${id}`, { method: "DELETE" });
    setD((prev) => prev && { ...prev, notes: (prev.notes || []).filter((n) => n.id !== id) });
  };

  const kinds = d ? [...new Set((d.timeline || []).map((e) => e.kind))] : [];
  const all = (d?.timeline || []).filter((e) => filter === "all" || e.kind === filter);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="stream-modal dossier" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div className="section-title" style={{ margin: 0, display: "flex", gap: 8, alignItems: "center" }}>
            <FileClock size={16} /> Dossier 360° de <span style={{ color: "var(--accent)" }}>{ip}</span>
          </div>
          <button className="close-x" onClick={onClose}><X size={13} /></button>
        </div>
        {d && (
          <div className="mono dim" style={{ fontSize: 11, margin: "6px 0" }}>
            {d.total} eventos totales · mostrando {d.timeline?.length} · notas: {(d.notes || []).length}
          </div>
        )}

        {/* notas */}
        <div className="notes-box">
          <StickyNote size={13} style={{ verticalAlign: "-2px", color: "var(--warn)" }} />
          {(d?.notes || []).map((n) => (
            <div key={n.id} className="note-row">
              <span className="note-tag">{n.tag}</span>
              <span style={{ flex: 1 }}>{n.text}</span>
              <button className="mini-del" onClick={() => delNote(n.id)}><Trash2 size={11} /></button>
            </div>
          ))}
          <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
            <input className="f-input" style={{ width: 130 }} placeholder="etiqueta…" value={tag}
                   onChange={(e) => setTag(e.target.value)} spellCheck={false} />
            <input className="f-input" style={{ flex: 1 }} placeholder="nota del analista (aparece en el PDF)…"
                   value={text} onChange={(e) => setText(e.target.value)} spellCheck={false}
                   onKeyDown={(e) => e.key === "Enter" && addNote()} />
            <button className="follow-btn" onClick={addNote}><Plus size={11} /> añadir</button>
          </div>
        </div>

        {/* filtros por tipo */}
        <div className="filter-row" style={{ marginTop: 6 }}>
          <button className={`chip ${filter === "all" ? "on" : ""}`} onClick={() => setFilter("all")}>todas</button>
          {kinds.map((k) => (
            <button key={k} className={`chip ${filter === k ? "on" : ""}`} onClick={() => setFilter(k)}>
              {KIND_META[k]?.label || k}
            </button>
          ))}
        </div>

        {err && <div className="alert-detail">{err}</div>}
        {busy && !d && <div className="mono dim">montando dossier… <Loader2 size={12} style={{ verticalAlign: "-2px" }} /></div>}

        {/* timeline */}
        <div className="timeline">
          {all.map((e, i) => {
            const meta = KIND_META[e.kind] || {};
            return (
              <div key={i} className={`tl-row ${meta.cls || ""}`}>
                <div className="tl-dot" />
                <div className="tl-time mono">{(e.ts || "").slice(11, 19)}</div>
                <div className="tl-body">
                  <div className="tl-title">
                    <span className={`tl-kind ${meta.cls}`}>{meta.label || e.kind}</span>
                    {e.title}
                  </div>
                  {e.detail && <div className="tl-detail">{e.detail}</div>}
                </div>
              </div>
            );
          })}
          {!all.length && !busy && <div className="empty-note">Sin eventos de este tipo para el host.</div>}
        </div>
      </div>
    </div>
  );
}
