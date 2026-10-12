import React, { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Search, ShieldAlert } from "lucide-react";

const TYPE_COLORS = {
  "form/urlencoded": "c-red",
  "plaintext-protocol": "c-amber",
  "basic-b64": "c-violet",
  "http-cookie": "c-cyan",
  "http-auth-header": "c-violet",
  "ftp": "c-red",
};

export default function Credentials({ data }) {
  const [q, setQ] = useState("");
  const [showEv, setShowEv] = useState(true);

  const rows = useMemo(() => {
    let list = data?.credentials || [];
    if (q.trim()) {
      const lq = q.toLowerCase();
      list = list.filter((c) => [c.user, c.password, c.hash, c.src, c.dst, c.type, c.domain].join(" ").toLowerCase().includes(lq));
    }
    return list;
  }, [data?.credentials, q]);

  return (
    <div>
      <div className="section-title">Credenciales detectadas</div>
      <div className="section-sub">
        <span style={{ color: "var(--warn)" }}>⚠</span> Todo lo hallado en texto claro en la red: formularios HTTP, USER/PASS de FTP y correos, cookies y cabeceras Authorization.
      </div>

      <div className="filters">
        <div style={{ position: "relative" }}>
          <Search size={14} style={{ position: "absolute", left: 10, top: 10, color: "var(--dim)" }} />
          <input
            className="f-input" placeholder="filtrar usuario / hash / host …"
            value={q} onChange={(e) => setQ(e.target.value)} style={{ paddingLeft: 30, width: 300 }}
            spellCheck={false}
          />
        </div>
        <label style={{ fontSize: 12, color: "var(--muted)", display: "flex", gap: 6, alignItems: "center", cursor: "pointer" }}>
          <input type="checkbox" checked={showEv} onChange={(e) => setShowEv(e.target.checked)} /> mostrar evidencia
        </label>
        <span className="f-count"><ShieldAlert size={11} style={{ verticalAlign: "-2px" }} /> {rows.length} hallazgos</span>
      </div>

      <div className="card">
        {!rows.length ? (
          <div className="empty"><div className="big">🔐</div>Ninguna credencial interceptada todavía. (Buen síntoma en tu red, malo en la demo.)</div>
        ) : (
          <div className="tablewrap" style={{ maxHeight: "calc(100vh - 290px)" }}>
            <table className="data">
              <thead>
                <tr><th>Tipo</th><th>Usuario</th><th>Password / Hash</th><th>Dominio / Puerto</th><th>Origen → Destino</th><th>Hora</th>{showEv && <th>Evidencia</th>}</tr>
              </thead>
              <tbody>
                {rows.map((c, i) => (
                  <motion.tr key={i} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: Math.min(i * 0.015, 0.3) }}>
                    <td><span className={`badge ${TYPE_COLORS[c.type] || "c-dim"}`}>{c.type}</span></td>
                    <td className="mono" style={{ color: c.user ? "var(--danger)" : "var(--dim)" }}>{c.user || "—"}</td>
                    <td className="mono" style={{ color: (c.password || c.hash) ? "var(--warn)" : "var(--dim)" }}>
                      {c.password || c.hash ? (c.hash && c.hash.length > 40 ? c.hash.slice(0, 40) + "…" : (c.password || c.hash)) : "—"}
                    </td>
                    <td className="mono">{c.domain || c.port || "—"}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{c.src} <span className="dim">→</span> {c.dst}</td>
                    <td className="mono dim" style={{ fontSize: 10.5 }}>{(c.ts || "").slice(11, 19)}</td>
                    {showEv && <td className="mono dim" style={{ fontSize: 10, maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.evidence}</td>}
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
