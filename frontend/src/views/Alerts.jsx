import { useMemo, useState } from "react";
import { AlertTriangle, Eye, Network, Fingerprint, Radio } from "lucide-react";

const KIND_ICON = {
  "portscan": Network,
  "arp-spoof": Radio,
  "tls-sni": Fingerprint,
};
const KIND_LABEL = {
  "portscan": "Escaneo de puertos",
  "arp-spoof": "Spoofing ARP",
  "tls-sni": "SNI sospechoso",
};
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_CLASS = { critical: "sev-critical", high: "sev-high", medium: "sev-medium", low: "sev-low", info: "sev-info" };

export default function Alerts({ data }) {
  const alerts = data?.alerts || [];
  const [filter, setFilter] = useState("all");

  const kinds = useMemo(
    () => [...new Set(alerts.map((a) => a.kind))],
    [alerts]);
  const filtered = useMemo(() => {
    const list = filter === "all" ? alerts : alerts.filter((a) => a.kind === filter);
    return [...list].sort((a, b) => a.severity.length !== b.severity.length
      ? SEV_ORDER[a.severity] - SEV_ORDER[b.severity]
      : b.id - a.id);
  }, [alerts, filter]);
  const counts = useMemo(() => {
    const c = {};
    for (const a of alerts) c[a.severity] = (c[a.severity] || 0) + 1;
    return c;
  }, [alerts]);

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <div className="alerts-summary">
        {Object.entries(counts).map(([sev, n]) => (
          <span key={sev} className={`sev-pill ${SEV_CLASS[sev] || "sev-info"}`}>{sev}: {n}</span>
        ))}
      </div>
      <div className="filter-row">
        <button className={`chip ${filter === "all" ? "on" : ""}`} onClick={() => setFilter("all")}>
          <Eye size={12} /> todas ({alerts.length})
        </button>
        {kinds.map((k) => (
          <button key={k} className={`chip ${filter === k ? "on" : ""}`} onClick={() => setFilter(k)}>
            {KIND_LABEL[k] || k}
          </button>
        ))}
      </div>
      {!filtered.length && (
        <div className="empty-note">
          <AlertTriangle style={{ verticalAlign: "-3px" }} /> Sin alertas todavía. La caza de amenazas
          detecta escaneos, ARP spoofing (dos MACs para una IP) y SNIs dudosos en tiempo real.
        </div>
      )}
      {filtered.map((a) => {
        const Icon = KIND_ICON[a.kind] || AlertTriangle;
        return (
          <div key={a.id} className={`alert-row ${SEV_CLASS[a.severity] || "sev-info"}`}>
            <Icon size={15} className="alert-ic" />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div className="alert-title">{a.title}</div>
              <div className="alert-detail">{a.detail}</div>
              <div className="alert-meta">
                <span className={`sev-tag ${SEV_CLASS[a.severity]}`}>{a.severity}</span>
                <span>{KIND_LABEL[a.kind] || a.kind}</span>
                <span>{a.ts}</span>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
