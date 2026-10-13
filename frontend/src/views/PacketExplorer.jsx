import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Loader2, ChevronRight, ChevronDown, Binary, X } from "lucide-react";

async function pktDetail(n) {
  const r = await fetch(`/api/packets/${n}`);
  if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`);
  return r.json();
}

function LayerNode({ layer, depth = 0 }) {
  const [open, setOpen] = useState(depth < 2);
  if (!layer) return null;
  const Icon = open ? ChevronDown : ChevronRight;
  return (
    <div style={{ marginLeft: depth * 14 }}>
      <div className="pkt-layer" onClick={() => setOpen(!open)}>
        <Icon size={12} />
        <b>{layer.name}</b>
        {layer.fields && (
          <span className="mono dim" style={{ fontSize: 10.4, marginLeft: 6 }}>
            {Object.entries(layer.fields).slice(0, 3).map(([k, v]) => `${k}=${String(v).slice(0, 22)}`).join("  ")}
          </span>
        )}
      </div>
      {open && layer.fields && (
        <table className="pkt-fields" style={{ marginLeft: 20 }}>
          <tbody>
            {Object.entries(layer.fields).map(([k, v]) => (
              <tr key={k}><td className="mono">{k}</td><td className="mono">{String(v)}</td></tr>
            ))}
          </tbody>
        </table>
      )}
      {open && layer.next && <LayerNode layer={layer.next} depth={depth + 1} />}
    </div>
  );
}

export default function PacketExplorer({ status }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [sel, setSel] = useState(null);       // número de paquete seleccionado
  const [detail, setDetail] = useState(null);
  const [dErr, setDErr] = useState("");

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

  const openPkt = async (n) => {
    setSel(n);
    setDErr("");
    setDetail(null);
    try {
      setDetail(await pktDetail(n));
    } catch (e) {
      setDErr(String(e.message || e).slice(0, 160));
    }
  };

  return (
    <div>
      <div className="section-title">Explorador de paquetes (buffer en vivo)</div>
      <div className="section-sub">Pulsa un paquete para abrir el detalle forense: árbol de protocolos + hexdump.</div>

      <button className="btn" style={{ marginBottom: 14 }} onClick={refresh} disabled={loading}>
        {loading ? <Loader2 size={14} /> : "↻"} Refrescar
      </button>
      {err && <div className="dim mono" style={{ fontSize: 11, marginBottom: 12 }}>{err}</div>}

      <div style={{ display: "grid", gridTemplateColumns: sel ? "minmax(280px, 1fr) minmax(330px, 1.1fr)" : "1fr", gap: 12 }}>
        <div className="card">
          {!rows.length ? (
            <div className="empty"><div className="big">␥</div>Buffer vacío. Inicia el sniffer y refresca.</div>
          ) : (
            <div className="tablewrap" style={{ maxHeight: "calc(100vh - 270px)" }}>
              <table className="data">
                <thead><tr><th>#</th><th>Resumen</th></tr></thead>
                <tbody>
                  {rows.map((p, i) => (
                    <motion.tr key={`${p.n}-${i}`} initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                      className={sel === p.n ? "row-sel" : ""}
                      onClick={() => openPkt(p.n)} style={{ cursor: "pointer" }}>
                      <td className="mono dim">{p.n}</td>
                      <td className="mono" style={{ fontSize: 11 }}>{p.summary}</td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {sel && (
          <div className="card pkt-detail">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div className="section-title" style={{ margin: 0, display: "flex", gap: 7, alignItems: "center" }}>
                <Binary size={14} /> Paquete #{sel} {detail ? `· ${detail.proto} · ${detail.length} B` : ""}
              </div>
              <button className="close-x" onClick={() => { setSel(null); setDetail(null); }}><X size={13} /></button>
            </div>
            {detail && <div className="mono dim" style={{ fontSize: 10.5, margin: "4px 0 8px" }}>{detail.summary}</div>}
            {dErr && <div className="alert-detail">{dErr}</div>}
            {!detail && !dErr && <div className="mono dim">cargando detalle…</div>}
            {detail && (
              <>
                <div className="pkt-layers">
                  <LayerNode layer={detail.layers} />
                </div>
                <div className="hex-title">hexdump ({detail.length} bytes)</div>
                <pre className="hexdump mono">{detail.hexdump.join("\n")}</pre>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
