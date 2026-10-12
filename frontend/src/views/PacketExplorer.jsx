import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Loader2 } from "lucide-react";

export default function PacketExplorer({ status }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const refresh = async () => {
    setLoading(true);
    setErr("");
    try {
      const r = await fetch("/api/packets/recent");
      if (!r.ok) throw new Error(await r.text());
      const d = await r.json();
      setRows(d.packets || []);
    } catch (e) {
      setErr("no disponible en esta build");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { refresh(); }, []);
  useEffect(() => {
    if (status.running) {
      const iv = setInterval(refresh, 2500);
      return () => clearInterval(iv);
    }
  }, [status.running]);

  return (
    <div>
      <div className="section-title">Explorador de paquetes (buffer en vivo)</div>
      <div className="section-sub">Resumen de los {rows.length} últimos paquetes disponibles en el buffer interno.</div>

      <button className="btn" style={{ marginBottom: 14 }} onClick={refresh} disabled={loading}>
        {loading ? <Loader2 size={14} /> : "↻"} Refrescar
      </button>
      {err && <div className="dim mono" style={{ fontSize: 11, marginBottom: 12 }}>{err}</div>}

      <div className="card">
        {!rows.length ? (
          <div className="empty"><div className="big">␥</div>Buffer vacío. Inicia el sniffer y vuelve a refrescar.</div>
        ) : (
          <div className="tablewrap" style={{ maxHeight: "calc(100vh - 270px)" }}>
            <table className="data">
              <thead><tr><th>#</th><th>Resumen</th></tr></thead>
              <tbody>
                {rows.map((p, i) => (
                  <motion.tr key={`${p.n}-${i}`} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                    <td className="mono dim">{p.n}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{p.summary}</td>
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
