import React, { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Search } from "lucide-react";

const RCODES = { 0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED" };

export default function DNSView({ data }) {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(null);

  const rows = useMemo(() => {
    let list = data?.dns || [];
    if (q.trim()) {
      const lq = q.toLowerCase();
      list = list.filter((d) => JSON.stringify(d).toLowerCase().includes(lq));
    }
    return list;
  }, [data?.dns, q]);

  const mainName = (d) => d.questions?.[0]?.name || "—";
  const mainType = (d) => d.questions?.[0]?.type || "—";
  const answersTxt = (d) => (d.answers || []).map((a) => `${a.type}=${a.data || "?"}`).join(" · ") || "—";

  return (
    <div>
      <div className="section-title">Consultas DNS</div>
      <div className="section-sub">Todo lo que tu red pregunta a los servidores de nombres: dominios, tipos, TTLs, respuestas — incluidos mDNS y LLMNR.</div>

      <div className="filters">
        <div style={{ position: "relative" }}>
          <Search size={14} style={{ position: "absolute", left: 10, top: 10, color: "var(--dim)" }} />
          <input className="f-input" placeholder="filtrar dominio / ip / tipo …" value={q} onChange={(e) => setQ(e.target.value)}
            style={{ paddingLeft: 30, width: 300 }} spellCheck={false} />
        </div>
        <span className="f-count">{rows.length} consultas</span>
      </div>

      <div className="card">
        {!rows.length ? (
          <div className="empty"><div className="big">ⓓ</div>Sin tráfico DNS capturado todavía.</div>
        ) : (
          <div className="tablewrap" style={{ maxHeight: "calc(100vh - 290px)" }}>
            <table className="data">
              <thead>
                <tr><th>Hora</th><th>Tipo</th><th>Dominio</th><th>Consulta desde → hacia</th><th>Respuesta</th><th>Rcode</th></tr>
              </thead>
              <tbody>
                {rows.map((d, i) => (
                  <React.Fragment key={i}>
                    <tr className="rowlink" onClick={() => setOpen(open === i ? null : i)}>
                      <td className="mono dim" style={{ fontSize: 10.5 }}>{(d.ts || "").slice(11, 19)}</td>
                      <td>
                        <span className={`badge ${d.is_response ? "c-green" : "c-cyan"}`}>
                          {d.is_response ? `RESP ${mainType(d)}` : `QRY ${mainType(d)}`}
                        </span>
                      </td>
                      <td className="mono" style={{ color: "var(--accent)" }}>{mainName(d)}</td>
                      <td className="mono" style={{ fontSize: 11 }}>
                        {!d.is_response ? d.src : d.dst} <span className="dim">→</span> {!d.is_response ? d.dst : d.src}
                      </td>
                      <td className="mono" style={{ fontSize: 11, maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{answersTxt(d)}</td>
                      <td className="mono dim">{d.is_response ? (RCODES[d.rcode] || d.rcode) : "—"}</td>
                    </tr>
                    <AnimatePresence>
                      {open === i && (
                        <tr key="x"><td colSpan={6} style={{ padding: 0, borderBottom: "none" }}>
                          <motion.div className="host-detail" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }}
                            style={{ overflow: "hidden", margin: 10 }}>
                            <div style={{ padding: 14 }}>
                              <div className="card">
                                <h3>Preguntas ({d.questions?.length || 0})</h3>
                                {d.questions?.map((qq, j) => (
                                  <div key={j} className="att-grid" style={{ marginBottom: 6 }}>
                                    <Att k="Nombre" v={qq.name} />
                                    <Att k="Tipo" v={qq.type} />
                                  </div>
                                )) || "—"}
                                {!d.questions?.length && <span className="dim mono" style={{ fontSize: 11 }}>—</span>}
                              </div>
                              <div className="card" style={{ marginBottom: 0 }}>
                                <h3>Respuestas ({d.answers?.length || 0})</h3>
                                {d.answers?.map((a, j) => (
                                  <div key={j} className="att-grid" style={{ marginBottom: 6 }}>
                                    <Att k="Nombre" v={a.name} />
                                    <Att k="Tipo" v={a.type} />
                                    <Att k="TTL" v={a.ttl} />
                                    <Att k="Dato" v={a.data || "—"} />
                                  </div>
                                ))}
                                {!d.answers?.length && <span className="dim mono" style={{ fontSize: 11 }}>— sin respuestas —</span>}
                              </div>
                            </div>
                          </motion.div>
                        </td></tr>
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
