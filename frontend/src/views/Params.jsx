import React, { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Search } from "lucide-react";

export default function Params({ data }) {
  const [qp, setQp] = useState("");
  const [qk, setQk] = useState("");

  const params = useMemo(() => {
    let l = data?.parameters || [];
    if (qp.trim()) {
      const lq = qp.toLowerCase();
      l = l.filter((p) => `${p.key}=${p.value} ${p.kind} ${p.src} ${p.host}`.toLowerCase().includes(lq));
    }
    return l;
  }, [data?.parameters, qp]);

  const kws = useMemo(() => {
    let l = data?.keywords || [];
    if (qk.trim()) {
      const lq = qk.toLowerCase();
      l = l.filter((k) => `${k.keyword} ${k.src} ${k.dst} ${k.service} ${k.context}`.toLowerCase().includes(lq));
    }
    return l;
  }, [data?.keywords, qk]);

  return (
    <div>
      <div className="section-title">Parámetros y keywords</div>
      <div className="section-sub">
        Parámetros extraídos de URLs, cuerpos POST y JSON — y las <strong>keywords</strong> sensibles que aparecen en texto claro por la red.
      </div>

      <div className="card">
        <h3>Parámetros</h3>
        <div className="filters">
          <div style={{ position: "relative" }}>
            <Search size={14} style={{ position: "absolute", left: 10, top: 10, color: "var(--dim)" }} />
            <input className="f-input" placeholder="filtrar clave / valor / host …" value={qp} onChange={(e) => setQp(e.target.value)}
              style={{ paddingLeft: 30, width: 280 }} spellCheck={false} />
          </div>
          <span className="f-count">{params.length}</span>
        </div>
        {!params.length ? (
          <div className="empty"><div className="big">?</div>Sin parámetros aún. Se extraen de URLs con querystring y cuerpos POST.</div>
        ) : (
          <div className="tablewrap" style={{ maxHeight: 340 }}>
            <table className="data">
              <thead><tr><th>Param</th><th>Valor</th><th>Contexto</th><th>Origen</th><th>Host</th><th>Hora</th></tr></thead>
              <tbody>
                {params.map((p, i) => (
                  <motion.tr key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                    <td className="mono" style={{ color: "var(--accent)" }}>{p.key}</td>
                    <td className="mono" style={{ color: "var(--accent2)" }}>{p.value}</td>
                    <td><span className={`badge c-violet`}>{p.kind}</span></td>
                    <td className="mono" style={{ fontSize: 11 }}>{p.src}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{p.host || "—"}</td>
                    <td className="mono dim" style={{ fontSize: 10.5 }}>{(p.ts || "").slice(11, 19)}</td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <h3>Keywords detectadas en el tráfico</h3>
        <div className="filters">
          <div style={{ position: "relative" }}>
            <Search size={14} style={{ position: "absolute", left: 10, top: 10, color: "var(--dim)" }} />
            <input className="f-input" placeholder="filtrar keyword / contexto …" value={qk} onChange={(e) => setQk(e.target.value)}
              style={{ paddingLeft: 30, width: 280 }} spellCheck={false} />
          </div>
          <span className="f-count">{kws.length}</span>
        </div>
        {!kws.length ? (
          <div className="empty"><div className="big">⚑</div>Sin coincidencias de keywords todavía.</div>
        ) : (
          <div className="tablewrap" style={{ maxHeight: 420 }}>
            <table className="data">
              <thead><tr><th>Keyword</th><th>Servicio</th><th>Origen → Destino</th><th>Contexto</th><th>Hora</th></tr></thead>
              <tbody>
                {kws.map((k, i) => (
                  <motion.tr key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                    <td><span className="badge c-red">{k.keyword}</span></td>
                    <td className="mono">{k.service}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{k.src} <span className="dim">→</span> {k.dst}</td>
                    <td className="mono dim" style={{ fontSize: 10, maxWidth: 460, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{k.context}</td>
                    <td className="mono dim" style={{ fontSize: 10.5 }}>{(k.ts || "").slice(11, 19)}</td>
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
