import { useEffect, useMemo, useRef, useState } from "react";
import { Search, X, CornerDownLeft } from "lucide-react";

/** Resultados unificados sobre el snapshot ya cargado en memoria. */
function searchAll(data, q) {
  const lq = q.toLowerCase();
  if (!lq) return [];
  const out = [];
  const push = (section, icon, label, sub, n) => out.push({ section, icon, label, sub, n, weight: 0 });

  for (const h of data?.hosts || []) {
    const hay = `${h.ip} ${h.mac} ${h.hostname} ${h.nic_vendor} ${h.os_guess} ${(h.tls_names || []).join(" ")}`;
    if (hay.toLowerCase().includes(lq))
      push("hosts", "🌐", `${h.ip}${h.hostname ? " · " + h.hostname : ""}`,
           `${h.nic_vendor || "MAC sin tablas"} · ${(h.bytes_count || 0).toLocaleString()} B`, h.ip);
  }
  for (const d of data?.dns || []) {
    for (const qq of d.questions || []) {
      if ((qq.name || "").toLowerCase().includes(lq))
        push("dns", "🔎", qq.name, `→ ${(d.answers || []).map((a) => a.data || a.type).slice(0, 3).join(", ")}`, qq.name);
    }
  }
  for (const c of data?.credentials || []) {
    const hay = `${c.user} ${c.domain} ${c.password} ${c.hash} ${c.type}`;
    if (hay.toLowerCase().includes(lq))
      push("credentials", "🔑", `${c.user || "(sin usuario)"} @ ${c.domain || c.port}`, `${c.type} · ${c.src}`, String(c.id ?? ""));
  }
  for (const m of data?.messages || []) {
    const hay = `${m.method} ${m.path} ${m.host} ${m.subject || ""} ${m.body || ""}`;
    if (hay.toLowerCase().includes(lq))
      push("messages", "✉️", `${m.method || ""} ${m.path || m.subject || (m.body || "").slice(0, 40)}`.trim(),
           `${m.src} → ${m.dst}`, String(m.n ?? ""));
  }
  for (const f of data?.files || []) {
    if ((f.filename || "").toLowerCase().includes(lq))
      push("files", "📄", f.filename, `${f.mime || ""} · ${f.size} B`, String(f.id ?? ""));
  }
  for (const p of data?.parameters || []) {
    if (`${p.key} ${p.value}`.toLowerCase().includes(lq))
      push("parameters", "🔧", `${p.key} = ${String(p.value || "").slice(0, 40)}`, `${p.kind} · ${p.src}`, String(p.key));
  }
  for (const k of data?.keywords || []) {
    if (`${k.keyword} ${k.context || ""}`.toLowerCase().includes(lq))
      push("keywords", "🎯", k.keyword, (k.context || "").slice(0, 90), k.keyword);
  }
  for (const t of data?.tls || []) {
    if ((t.sni || "").toLowerCase().includes(lq))
      push("tls", "🛡️", `SNI ${t.sni}`, `${t.src} → ${t.dst} · ${t.tls_version}`, t.sni);
  }
  for (const a of data?.alerts || []) {
    if (`${a.title} ${a.detail}`.toLowerCase().includes(lq))
      push("alerts", "🚨", a.title, a.detail, String(a.id));
  }
  for (const s of data?.sessions || []) {
    const hay = `${s.src}:${s.sport} ${s.dst}:${s.dport} ${s.service} ${s.state}`;
    if (hay.toLowerCase().includes(lq))
      push("sessions", " ⇄", hay, `${s.packets} pkt · ${s.bytes} B`, hay);
  }
  return out.slice(0, 40);
}

export default function SearchPalette({ data, open, onClose, go }) {
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const inputRef = useRef(null);
  const results = useMemo(() => searchAll(data, q), [data, q]);

  useEffect(() => {
    if (open) {
      setQ("");
      setIdx(0);
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);
  useEffect(() => { setIdx(0); }, [q]);

  if (!open) return null;
  const accept = (r) => {
    if (!r) return;
    go(r.section, r.n ? { focus: r.n } : undefined);
    onClose();
  };
  const onKey = (e) => {
    if (e.key === "Escape") onClose();
    else if (e.key === "ArrowDown") { setIdx((i) => Math.min(i + 1, results.length - 1)); e.preventDefault(); }
    else if (e.key === "ArrowUp") { setIdx((i) => Math.max(i - 1, 0)); e.preventDefault(); }
    else if (e.key === "Enter") accept(results[idx]);
  };

  return (
    <div className="modal-backdrop palette-bg" onClick={onClose}>
      <div className="palette card" onClick={(e) => e.stopPropagation()}>
        <div className="palette-head">
          <Search size={15} />
          <input ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey}
                 placeholder="Buscar en hosts, DNS, credenciales, ficheros, TLS, alertas…" spellCheck={false} />
          {q && <button className="close-x" onClick={() => setQ("")}><X size={12} /></button>}
        </div>
        <div className="palette-list">
          {!results.length && q && <div className="palette-item dim">sin resultados para “{q}”</div>}
          {!q && <div className="palette-item dim">escribe para buscar en {["hosts", "dns", "credentials", "messages", "files", "parameters", "keywords", "tls", "sessions"].length} fuentes…</div>}
          {results.map((r, i) => (
            <div key={`${r.section}-${r.label}-${i}`}
                 className={`palette-item ${i === idx ? "sel" : ""}`}
                 onClick={() => accept(r)}
                 onMouseEnter={() => setIdx(i)}>
              <span className="palette-ic">{r.icon}</span>
              <span className="palette-label">{r.label}</span>
              <span className="palette-sub">{r.sub}</span>
              <span className="palette-sec mono">{r.section}</span>
            </div>
          ))}
        </div>
        <div className="palette-foot mono">
          <CornerDownLeft size={11} /> abrir · ↑↓ navegar · Esc cerrar · {results.length} resultados
        </div>
      </div>
    </div>
  );
}
