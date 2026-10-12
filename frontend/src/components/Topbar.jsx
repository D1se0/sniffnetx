import React, { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronDown, Download, Loader2, Pause, Play, Wifi, WifiOff } from "lucide-react";
import { api, download } from "../api.js";

export default function Topbar({ data, status }) {
  const [ifaces, setIfaces] = useState([]);
  const [iface, setIface] = useState("");
  const [bpf, setBpf] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [recentPkts, setRecentPkts] = useState(0);
  const lastPkts = useRef(0);

  useEffect(() => {
    api("/api/interfaces")
      .then((d) => {
        const list = d.interfaces || [];
        setIfaces(list);
        const def = list.find((i) => i.default) || list[0];
        if (def) setIface(def.name);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const n = data?.stats?.packets || 0;
    setRecentPkts(n - lastPkts.current);
    lastPkts.current = n;
  }, [data?.stats?.packets]);

  const toggle = async () => {
    setBusy(true); setErr("");
    try {
      if (status.running) {
        await api("/api/capture/stop", { method: "POST" });
      } else {
        await api("/api/capture/start", {
          method: "POST",
          body: JSON.stringify({ iface, bpf, promisc: true, snaplen: 65535 }),
        });
      }
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const s = data?.stats || {};
  const exportItems = [
    { label: "PCAP (crudo)", what: null, fmt: "pcap" },
    { label: "Todo → PDF", what: "all", fmt: "pdf" },
    { label: "Todo → JSON", what: "all", fmt: "json" },
    { label: "Hosts → CSV", what: "hosts", fmt: "csv" },
    { label: "Credenciales → CSV", what: "credentials", fmt: "csv" },
    { label: "DNS → CSV", what: "dns", fmt: "csv" },
    { label: "Parámetros → CSV", what: "parameters", fmt: "csv" },
  ];

  return (
    <header className="topbar">
      <div className="logo">
        <motion.div
          animate={{ rotate: status.running ? 360 : 0 }}
          transition={{ repeat: status.running ? Infinity : 0, duration: 3, ease: "linear" }}
          style={{ display: "flex" }}
        >
          <Wifi size={22} color="var(--accent)" strokeWidth={2.4} />
        </motion.div>
        Sniff<span className="nex">Nex</span>
        <span className="logo-badge">FORENSICS</span>
      </div>

      <div className={`statuspill`}>
        <span className={`dot ${status.running ? "live" : err ? "err" : ""}`} />
        {status.running ? `LIVE · ${iface}` : err ? "ERROR" : "DETENIDO"}
        {status.running && (
          <span style={{ color: "var(--dim)" }}>
            · {Math.floor(status.elapsed)}s
          </span>
        )}
      </div>

      {recentPkts > 0 && status.running && (
        <motion.span
          key={recentPkts}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="stat-chip"
          style={{ color: "var(--ok)" }}
        >
          ▲ {recentPkts} pkts/s
        </motion.span>
      )}

      <select className="iface-select" value={iface} onChange={(e) => setIface(e.target.value)} disabled={status.running}>
        {ifaces.map((i) => (
          <option key={i.name} value={i.name}>
            {i.name} {i.ip ? `· ${i.ip}` : ""} {i.default ? "· (por defecto)" : ""} {!i.up ? "· down" : ""}
          </option>
        ))}
      </select>

      <input
        className="bpf-input"
        placeholder="filtro BPF: tcp port 80 …"
        value={bpf}
        onChange={(e) => setBpf(e.target.value)}
        disabled={status.running}
        spellCheck={false}
      />

      {busy ? (
        <button className="btn" disabled><Loader2 size={15} className="spin" /> …</button>
      ) : status.running ? (
        <button className="btn stop" onClick={toggle}><Pause size={15} /> Detener</button>
      ) : (
        <button className="btn start" onClick={toggle}><Play size={15} /> Iniciar sniffer</button>
      )}

      <div className="statbar">
        <span className="stat-chip"><b>{s.packets || 0}</b> pkts</span>
        <span className="stat-chip"><b>{(data?.hosts || []).length}</b> hosts</span>
        <span className="stat-chip"><b>{(data?.credentials || []).length}</b> creds</span>
        <span className="stat-chip"><b>{(data?.files || []).length}</b> files</span>
      </div>

      <ExportMenu items={exportItems} iface={iface} />
    </header>
  );
}

function ExportMenu({ items, iface }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState("");
  const ref = useRef(null);

  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    window.addEventListener("mousedown", h);
    return () => window.removeEventListener("mousedown", h);
  }, []);

  const doExport = async (it) => {
    setBusy(it.label);
    try {
      if (it.fmt === "pcap") {
        await download("/api/export/pcap", { limit: 50000 }, "sniffnex_capture.pcap");
      } else {
        await download(`/api/export/${it.what}/${it.fmt}`, {}, `sniffnex_${it.what}.${it.fmt}`);
      }
    } catch (e) { alert(e.message); }
    setBusy(""); setOpen(false);
  };

  return (
    <div className="exporter" ref={ref}>
      <button className="btn ghost" onClick={() => setOpen(!open)}>
        <Download size={15} /> Exportar <ChevronDown size={13} />
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            className="export-menu"
            initial={{ opacity: 0, y: -6, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -6, scale: 0.97 }}
            transition={{ duration: 0.16 }}
          >
            {items.map((it) => (
              <button key={it.label} className="export-item" onClick={() => doExport(it)} disabled={!!busy}>
                {busy === it.label ? <Loader2 size={14} /> : <Download size={14} />}
                {it.label}
              </button>
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
