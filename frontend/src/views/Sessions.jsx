import React, { useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Search } from "lucide-react";

const STATE_COLORS = {
  ESTABLISHED: "c-green",
  SYN_SENT: "c-amber",
  SYN_ACK: "c-cyan",
  FIN_WAIT: "c-violet",
  RST: "c-red",
};

export default function Sessions({ data }) {
  const [q, setQ] = useState("");
  const [svc, setSvc] = useState("all");

  const rows = useMemo(() => {
    let list = data?.sessions || [];
    if (svc !== "all") list = list.filter((s) => s.service === svc);
    if (q.trim()) {
      const lq = q.toLowerCase();
      list = list.filter((s) => `${s.src}:${s.sport} ${s.dst}:${s.dport} ${s.service} ${s.state}`.toLowerCase().includes(lq));
    }
    return list;
  }, [data?.sessions, q, svc]);

  const services = useMemo(() => [...new Set((data?.sessions || []).map((s) => s.service))].sort(), [data?.sessions]);

  return (
    <div>
      <div className="section-title">Sesiones TCP / UDP</div>
      <div className="section-sub">
        Cada flujo visto en la red: quién habla con quién, por qué servicio, en qué estado y cuántos bytes se han movido.
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
                <tr><th>Estado</th><th>Origen</th><th>Destino</th><th>Servicio</th><th>Pkts</th><th>Bytes</th><th>Inicio</th><th>Último</th></tr>
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
                    <td className="mono dim" style={{ fontSize: 10.5 }}>{(s.end || "").slice(11, 19)}</td>
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
