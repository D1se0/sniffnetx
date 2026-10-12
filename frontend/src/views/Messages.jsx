import React, { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Search } from "lucide-react";

export default function Messages({ data }) {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(null);

  const rows = useMemo(() => {
    let list = data?.messages || [];
    if (q.trim()) {
      const lq = q.toLowerCase();
      list = list.filter((m) =>
        [m.type, m.method, m.path, m.host, m.src, m.dst, m.status, m.user_agent, JSON.stringify(m.body || "")].join(" ").toLowerCase().includes(lq)
      );
    }
    return list;
  }, [data?.messages, q]);

  const title = (m) => {
    if (m.type === "request") return `${m.method} ${m.path}`;
    if (m.type === "response") return `${m.status_text || m.status} ⇒ ${m.path || ""}`;
    if (m.type === "smtp-meta") return "SMTP · interacción de correo";
    return m.type || "—";
  };

  return (
    <div>
      <div className="section-title">Mensajes obtenidos por la red</div>
      <div className="section-sub">
        Conversaciones HTTP (peticiones/respuestas), metadatos SMTP/POP3/IMAP y otras interacciones textualizadas de la sesión.
      </div>

      <div className="filters">
        <div style={{ position: "relative" }}>
          <Search size={14} style={{ position: "absolute", left: 10, top: 10, color: "var(--dim)" }} />
          <input
            className="f-input" placeholder="filtrar path / host / UA / contenido …"
            value={q} onChange={(e) => setQ(e.target.value)} style={{ paddingLeft: 30, width: 320 }}
            spellCheck={false}
          />
        </div>
        <span className="f-count">{rows.length} mensajes</span>
      </div>

      <div className="card">
        {!rows.length ? (
          <div className="empty"><div className="big">✉</div>Sin mensajes aún. Navega por HTTP en la red capturada y aparecerán aquí.</div>
        ) : (
          <div className="tablewrap" style={{ maxHeight: "calc(100vh - 290px)" }}>
            <table className="data">
              <thead>
                <tr><th>Hora</th><th>Tipo</th><th>Descripción</th><th>Origen → Destino</th><th>Detalles</th></tr>
              </thead>
              <tbody>
                {rows.map((m, i) => (
                  <React.Fragment key={i}>
                    <tr className="rowlink" onClick={() => setOpen(open === i ? null : i)}>
                      <td className="mono dim" style={{ fontSize: 10.5 }}>{(m.ts || "").slice(11, 19)}</td>
                      <td>
                        <span className={`badge ${(m.type || "").includes("response") ? "c-green" : (m.type || "").includes("smtp") ? "c-amber" : "c-cyan"}`}>
                          {m.type}
                        </span>
                      </td>
                      <td className="mono" style={{ maxWidth: 420, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {title(m)}
                      </td>
                      <td className="mono" style={{ fontSize: 11 }}>{m.src} <span className="dim">→</span> {m.dst}</td>
                      <td className="mono dim" style={{ fontSize: 10.5 }}>
                        {m.content_type || m.http_version || ""}
                      </td>
                    </tr>
                    <AnimatePresence>
                      {open === i && (
                        <tr key="d">
                          <td colSpan={5} style={{ padding: 0, borderBottom: "none" }}>
                            <motion.div
                              className="host-detail"
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: "auto" }}
                              exit={{ opacity: 0, height: 0 }}
                              transition={{ duration: 0.22 }}
                              style={{ overflow: "hidden", margin: 10 }}
                            >
                              <div style={{ padding: 14 }}>
                                <div className="att-grid" style={{ marginBottom: 12 }}>
                                  {m.method && <Att k="Método" v={m.method} />}
                                  {m.path && <Att k="Path" v={m.path} />}
                                  {m.host && <Att k="Host" v={m.host} />}
                                  {m.status_text && <Att k="Status" v={m.status_text} />}
                                  {m.user_agent && <Att k="User-Agent" v={m.user_agent} />}
                                  {m.content_type && <Att k="Content-Type" v={m.content_type} />}
                                  {m.cookie && <Att k="Cookie" v={m.cookie} />}
                                  {m.authorization && <Att k="Authorization" v={m.authorization} />}
                                </div>
                                <div className="card" style={{ marginBottom: 0 }}>
                                  <h3>Cuerpo / encabezados</h3>
                                  <pre className="mono" style={{ fontSize: 10.5, color: "var(--muted)", whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.6 }}>
                                    {JSON.stringify({ headers: m.headers, body: m.body, size: m.size }, null, 2)}
                                  </pre>
                                </div>
                              </div>
                            </motion.div>
                          </td>
                        </tr>
                      )}
                    </AnimatePresence>
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function Att({ k, v }) {
  return <div className="att"><div className="k">{k}</div><div className="v">{String(v)}</div></div>;
}
