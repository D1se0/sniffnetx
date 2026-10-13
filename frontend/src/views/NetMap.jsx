import { useState, useMemo } from "react";
import { ShieldAlert, Wifi, Globe, Cpu, X } from "lucide-react";

/**
 * Mapa de red vivo: grafo interactivo.
 *  - Nodos = hosts (IPs), tamaño ∝ tráfico, color por tipo (LAN/gateway/externo).
 *  - Rojo = host implicado en alerta activa (ARP spoofing / portscan / …).
 *  - Aristas = sesiones con animación de flujo (dash) y grosor ∝ bytes.
 *  - Clic en nodo → ficha con MAC, OS, puertos, DNS, TLS SNI, keywords…
 */
const fmtBytes = (n) => {
  if (n == null) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
};

const isPrivate = (ip) =>
  /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip || "");

/** hash determinista para posiciones estables entre updates */
const h32 = (s) => {
  let x = 2166136261;
  for (let i = 0; i < s.length; i++) {
    x ^= s.charCodeAt(i);
    x = Math.imul(x, 16777619);
  }
  return (x >>> 0) / 4294967295;
};

export default function NetMap({ data }) {
  const hosts = data?.hosts || [];
  const sessions = data?.sessions || [];
  const alerts = data?.alerts || [];
  const [selIp, setSelIp] = useState(null);
  const [dim, setDim] = useState(false);

  const { nodes, edges, sel } = useMemo(() => {
    if (!hosts.length) return { nodes: [], edges: [], sel: null };
    const totalBytes = Math.max(1, ...hosts.map((h) => h.bytes_count || 0));
    const lanHosts = hosts.filter((h) => isPrivate(h.ip));
    const extHosts = hosts.filter((h) => !isPrivate(h.ip));

    // subredes LAN → columnas
    const nets = new Map();
    for (const h of lanHosts) {
      const net = h.ip.split(".").slice(0, 3).join(".");
      if (!nets.has(net)) nets.set(net, []);
      nets.get(net).push(h);
    }
    const nodes = [];
    const CX = 300, CY = 250;
    const netList = [...nets.keys()].sort((a, b) =>
      nets.get(b).length - nets.get(a).length);
    let colX = 90;
    for (const net of netList) {
      const group = nets.get(net);
      const step = 62;
      const startY = CY - ((group.length - 1) * step) / 2;
      group.forEach((h, i) => {
        nodes.push({
          ...h,
          kind: "lan",
          x: colX + ((h32(h.ip + "x") * 22) | 0),
          y: startY + i * step,
          r: 8 + 16 * ((h.bytes_count || 0) / totalBytes),
        });
      });
      colX += 150;
    }
    // externos: cluster derecha
    extHosts.forEach((h, i) => {
      const ang = (i / Math.max(1, extHosts.length)) * Math.PI * 2;
      const R = 150 + (h32(h.ip) * 40);
      nodes.push({
        ...h,
        kind: "ext",
        x: 640 + Math.cos(ang) * R * 0.55,
        y: 240 + Math.sin(ang) * R * 0.9,
        r: 7 + 12 * ((h.bytes_count || 0) / totalBytes),
      });
    });
    // gateway local: LAN node con más conexiones a externos
    const gwCount = new Map();
    for (const s of sessions) {
      if (isPrivate(s.src) && !isPrivate(s.dst))
        gwCount.set(s.src, (gwCount.get(s.src) || 0) + 1);
      if (isPrivate(s.dst) && !isPrivate(s.src))
        gwCount.set(s.dst, (gwCount.get(s.dst) || 0) + 1);
    }
    let gw = null, best = 0;
    for (const [ip, c] of gwCount) if (c > best) { best = c; gw = ip; }
    for (const n of nodes) n.gw = n.ip === gw;

    // IPs marcadas por alertas activas
    const alertIps = new Set();
    for (const a of alerts) {
      for (const m of (a.detail || "").matchAll(/\d+\.\d+\.\d+\.\d+/g))
        alertIps.add(m[0]);
      for (const m of (a.title || "").matchAll(/\d+\.\d+\.\d+\.\d+/g))
        alertIps.add(m[0]);
    }
    for (const n of nodes) n.alert = alertIps.has(n.ip);

    // edges por sesión, agregadas
    const byPair = new Map();
    for (const s of sessions) {
      const a = `${s.src}:${s.sport}`, b = `${s.dst}:${s.dport}`;
      const key = s.src < s.dst ? `${s.src}_${s.dst}` : `${s.dst}_${s.src}`;
      const agg = byPair.get(key) || { a: s.src, b: s.dst, bytes: 0, n: 0, services: new Set() };
      agg.bytes += s.bytes || 0;
      agg.n += 1;
      agg.services.add(s.service);
      byPair.set(key, agg);
    }
    const pos = new Map(nodes.map((n) => [n.ip, n]));
    const edges = [...byPair.values()].map((e) => {
      const na = pos.get(e.a), nb = pos.get(e.b);
      if (!na || !nb) return null;
      return { ...e, x1: na.x, y1: na.y, x2: nb.x, y2: nb.y,
               max: Math.max(1, ...[...byPair.values()].map((x) => x.bytes)) };
    }).filter(Boolean);
    for (const e of edges) e._max = Math.max(...edges.map((x) => x.bytes), 1);

    return { nodes, edges, sel: selIp ? nodes.find((n) => n.ip === selIp) : null };
  }, [hosts, sessions, alerts, selIp]);

  if (!hosts.length)
    return <div className="empty-note">Sin hosts aún: inicia la captura o carga un PCAP y el mapa cobrará vida aquí.</div>;

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <div className="map-toolbar">
        <span className="muted small">Mapa de red · {nodes.length} nodos · {edges.length} enlaces</span>
        <label><input type="checkbox" checked={dim} onChange={() => setDim(!dim)} /> atenuar sin selección</label>
      </div>
      <div style={{ display: "flex", gap: 14 }}>
        <svg className="netmap" viewBox="0 0 800 500" style={{ flex: 1, minHeight: 460 }}>
          <defs>
            <marker id="arrow" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto">
              <path d="M0,0 L7,3 L0,6 Z" fill="#3d4a5c" />
            </marker>
            <radialGradient id="glow">
              <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.28" />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
            </radialGradient>
          </defs>
          {edges.map((e, i) => {
            const w = 1 + 3 * (e.bytes / (e._max || 1));
            const act = !dim || !sel || sel.ip === e.a || sel.ip === e.b;
            return (
              <g key={i} opacity={act ? 1 : 0.14}>
                <line x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2} className="edge-flow"
                      stroke="#38bdf8" strokeWidth={w} markerEnd="url(#arrow)" />
              </g>
            );
          })}
          {nodes.map((n) => {
            const col = n.alert ? "#f87171" : n.gw ? "#22d3ee" : n.kind === "lan" ? "#4ade80" : "#a78bfa";
            const active = !dim || !sel || sel.ip === n.ip;
            return (
              <g key={n.ip} onClick={() => setSelIp(n.ip)} opacity={active ? 1 : 0.16}
                 style={{ cursor: "pointer" }}>
                {n.alert && <circle cx={n.x} cy={n.y} r={n.r + 10} fill="url(#glow)" />}
                <circle cx={n.x} cy={n.y} r={n.r} fill="#101720" stroke={col} strokeWidth={n.gw ? 2.6 : 1.6} />
                <circle cx={n.x} cy={n.y} r={3.4} fill={col} />
                <text x={n.x} y={n.y - n.r - 6} textAnchor="middle" className="nm-label"
                      fill={n.gw ? "#67e8f9" : "#c8d3e0"} fontSize={n.gw ? 11 : 9.5}>
                  {n.hostname || n.ip}
                </text>
                <text x={n.x} y={n.y + n.r + 12} textAnchor="middle" fill="#7b8798" fontSize="7.6">
                  {fmtBytes(n.bytes_count)}
                </text>
              </g>
            );
          })}
          <g fontSize="8.4" fill="#7b8798">
            <circle cx="14" cy="472" r="4" fill="#4ade80" /><text x="24" y="475">LAN</text>
            <circle cx="58" cy="472" r="4" fill="#22d3ee" /><text x="68" y="475">Gateway</text>
            <circle cx="132" cy="472" r="4" fill="#a78bfa" /><text x="142" y="475">Exterior</text>
            <circle cx="205" cy="472" r="4" fill="#f87171" /><text x="215" y="475">Alerta activa</text>
          </g>
        </svg>

        {sel && (
          <div className="host-card">
            <button className="close-x" onClick={() => setSelIp(null)}><X size={13} /></button>
            <div className="host-name">{sel.hostname || sel.ip}</div>
            <div className="tagline">{sel.ip} · {sel.nic_vendor_long || sel.nic_vendor || "MAC sin tablas"}</div>
            {sel.alert && <div className="alert-chip"><ShieldAlert size={11} /> implicado en alerta activa</div>}
            <div className="kv"><span>MAC</span><b>{sel.mac || "—"}</b></div>
            <div className="kv"><span>OG/SO</span><b>{sel.os_guess || "—"}</b></div>
            <div className="kv"><span>Tráfico</span><b>{fmtBytes(sel.bytes_count)} · {sel.packet_count} pkt</b></div>
            <div className="kv"><span>Puertos</span><b>{sel.ports_open?.length ? sel.ports_open.join(", ") : "—"}</b></div>
            <div className="kv"><span>DNS vistos</span><b>{sel.dns_queries?.length || 0}</b></div>
            <div className="kv"><span>TLS/SNI</span>{sel.tls_names?.length
              ? sel.tls_names.map((t) => <div key={t} className="mini-line">{t}</div>)
              : <b>—</b>}</div>
            <div className="kv"><span>Keywords</span>{sel.keyword_hits?.length
              ? sel.keyword_hits.map((k) => <div key={k} className="mini-line warn">{k}</div>)
              : <b>—</b>}</div>
          </div>
        )}
      </div>
    </div>
  );
}
