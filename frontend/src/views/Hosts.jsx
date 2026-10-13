import React, { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronDown, Search } from "lucide-react";

function sortRows(rows, key, dir) {
  const r = [...rows].sort((a, b) => {
    const va = a[key]; const vb = b[key];
    let x = typeof va === "number" ? va : String(va || "").toLowerCase();
    let y = typeof vb === "number" ? vb : String(vb || "").toLowerCase();
    if (x < y) return -1; if (x > y) return 1; return 0;
  });
  return dir === "asc" ? r : r.reverse();
}

export default function Hosts({ data, selected, setSelected, openDossier }) {
  const [q, setQ] = useState("");
  const [sortKey, setSortKey] = useState("packet_count");
  const [dir, setDir] = useState("desc");
  const [onlyArp, setOnlyArp] = useState(false);
  const [onlyMac, setOnlyMac] = useState(false);

  const rows = useMemo(() => {
    let list = data?.hosts || [];
    if (q.trim()) {
      const lq = q.toLowerCase();
      list = list.filter((h) =>
        [h.ip, h.mac, h.hostname, h.nic_vendor, h.nic_vendor_long, h.os_guess].join(" ").toLowerCase().includes(lq)
      );
    }
    if (onlyArp) list = list.filter((h) => h.arp);
    if (onlyMac) list = list.filter((h) => h.mac);
    return sortRows(list, sortKey, dir);
  }, [data?.hosts, q, sortKey, dir, onlyArp, onlyMac]);

  const clickSort = (k) => {
    if (k === sortKey) setDir(dir === "asc" ? "desc" : "asc");
    else { setSortKey(k); setDir("desc"); }
  };

  const cols = [
    ["ip", "IP"], ["mac", "MAC"], ["nic_vendor", "NIC"], ["hostname", "Hostname"],
    ["os_guess", "SO (estimado)"], ["ttl_min", "TTL"], ["ports_open", "Puertos"],
    ["sent", "Env"], ["recv", "Rec"], ["packet_count", "Total"],
  ];
  const noteTargets = new Set((data?.notes || []).map((n) => n.target || ""));

  return (
    <div>
      <div className="section-title">Hosts detectados en la red</div>
      <div className="section-sub">
        Cada IP descubierta por ARP, DNS/mDNS, LLMNR, HTTP o tráfico IP directo. Pulsa una fila para desplegar toda su ficha.
      </div>

      <div className="filters">
        <div style={{ position: "relative" }}>
          <Search size={14} style={{ position: "absolute", left: 10, top: 10, color: "var(--dim)" }} />
          <input
            className="f-input" placeholder="filtrar ip / mac / hostname / vendor …"
            value={q} onChange={(e) => setQ(e.target.value)} style={{ paddingLeft: 30, width: 300 }}
            spellCheck={false}
          />
        </div>
        <label style={{ fontSize: 12, color: "var(--muted)", display: "flex", gap: 6, alignItems: "center", cursor: "pointer" }}>
          <input type="checkbox" checked={onlyArp} onChange={(e) => setOnlyArp(e.target.checked)} /> solo ARP
        </label>
        <label style={{ fontSize: 12, color: "var(--muted)", display: "flex", gap: 6, alignItems: "center", cursor: "pointer" }}>
          <input type="checkbox" checked={onlyMac} onChange={(e) => setOnlyMac(e.target.checked)} /> solo con MAC
        </label>
        <span className="f-count">{rows.length} hosts</span>
      </div>

      <div className="card">
        {!rows.length ? (
          <div className="empty"><div className="big">⌖</div>No hay hosts que coincidan con el filtro actual.</div>
        ) : (
          <div className="tablewrap" style={{ maxHeight: "calc(100vh - 300px)" }}>
            <table className="data">
              <thead>
                <tr>
                  {cols.map(([k, lbl]) => (
                    <th key={k} onClick={() => clickSort(k)}>{lbl}{sortKey === k ? (dir === "asc" ? " ↑" : " ↓") : ""}</th>
                  ))}
                  <th>Dossier</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((h) => (
                  <React.Fragment key={h.ip}>
                    <motion.tr
                      className="rowlink"
                      onClick={() => setSelected(selected === h.ip ? null : h.ip)}
                      layout
                    >
                      <td className="mono" style={{ color: "var(--accent)" }}>{h.ip}</td>
                      <td className="mono">{h.mac || "—"}</td>
                      <td>{h.nic_vendor || "—"}</td>
                      <td className="mono">{h.hostname || "—"}</td>
                      <td className="mut">{h.os_guess || "?"}</td>
                      <td className="mono">{h.ttl_min < 255 ? h.ttl_min : "—"}</td>
                      <td className="mono">{h.ports_open?.length ? h.ports_open.slice(0, 4).join(", ") + (h.ports_open.length > 4 ? "+" : "") : "—"}</td>
                      <td className="mono">{h.sent}</td>
                      <td className="mono">{h.recv}</td>
                      <td className="mono" style={{ color: "var(--accent2)" }}>{h.packet_count}</td>
                      <td style={{ whiteSpace: "nowrap" }}>
                        {noteTargets.has(`host:${h.ip}`) && <span className="badge c-amber" title="Tiene notas del analista">📝</span>}
                        {openDossier && (
                          <button className="follow-btn" onClick={(e) => { e.stopPropagation(); openDossier(h.ip); }}>
                            dossier
                          </button>
                        )}
                      </td>
                    </motion.tr>
                    <AnimatePresence>
                      {selected === h.ip && (
                        <tr key="detail">
                          <td colSpan={cols.length + 1} style={{ padding: 0, borderBottom: "none" }}>
                            <motion.div
                              className="host-detail"
                              initial={{ opacity: 0, height: 0 }}
                              animate={{ opacity: 1, height: "auto" }}
                              exit={{ opacity: 0, height: 0 }}
                              transition={{ duration: 0.25, ease: [0.2, 0.8, 0.2, 1] }}
                              style={{ overflow: "hidden", margin: 10 }}
                            >
                              <div style={{ padding: 14 }}>
                                <div className="att-grid" style={{ marginBottom: 12 }}>
                                  <Att k="IP" v={h.ip} />
                                  <Att k="MAC" v={h.mac || "—"} />
                                  <Att k="NIC vendor" v={h.nic_vendor_long || h.nic_vendor || "—"} />
                                  <Att k="MAC aleatorizada" v={h.randomized_mac ? "Sí (posible spoof/privacidad)" : "No"} />
                                  <Att k="Hostname" v={h.hostname || "—"} />
                                  <Att k="Dominio" v={h.domain || "—"} />
                                  <Att k="SO estimado (TTL)" v={`${h.os_guess} (TTL mín ${h.ttl_min})`} />
                                  <Att k="Detectado vía ARP" v={h.arp ? "Sí" : "No"} />
                                  <Att k="Paquetes enviados" v={h.sent} />
                                  <Att k="Paquetes recibidos" v={h.recv} />
                                  <Att k="Bytes totales" v={h.bytes_count?.toLocaleString?.() ?? h.bytes_count} />
                                  <Att k="Primera / última vez" v={`${(h.first_seen || "—").slice(11, 19)} → ${(h.last_seen || "—").slice(11, 19)}`} />
                                </div>
                                <div className="att-grid" style={{ marginBottom: 12 }}>
                                  <Att k="Open TCP ports (SYN/SYN-ACK)" v={h.ports_open?.length ? h.ports_open.join(", ") : "ninguno detectado"} />
                                  <Att k="mDNS names" v={h.mdns_names?.join(", ") || "—"} />
                                  <Att k="NBNS names" v={h.nbns_names?.join(", ") || "—"} />
                                </div>
                                <div className="card" style={{ marginBottom: 0 }}>
                                  <h3>DNS queries de este host</h3>
                                  <div className="mono" style={{ fontSize: 11.5, color: "var(--muted)", lineHeight: 1.7 }}>
                                    {h.dns_queries?.length ? h.dns_queries.map((d) => <span key={d} style={{ marginRight: 12 }}>◦ {d}</span>) : "— sin consultas DNS observadas —"}
                                  </div>
                                </div>
                                <div className="card" style={{ marginBottom: 0 }}>
                                  <h3>Keywords halladas en su tráfico</h3>
                                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                                    {h.keyword_hits?.length
                                      ? h.keyword_hits.map((k) => <span key={k} className="badge c-violet">{k}</span>)
                                      : <span className="dim mono" style={{ fontSize: 11.5 }}>— sin keywords —</span>}
                                  </div>
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
      <ChevronDown size={0} style={{ display: "none" }} />
    </div>
  );
}

function Att({ k, v }) {
  return (
    <motion.div className="att" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}>
      <div className="k">{k}</div>
      <div className="v">{String(v)}</div>
    </motion.div>
  );
}
