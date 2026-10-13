import { useMemo, useState } from "react";
import { X } from "lucide-react";

const fmtB = (n) => {
  if (n == null) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
};

export default function Matrix({ data }) {
  const sel = useState(null)[0];
  const [picked, setPicked] = useState(null);

  const { hosts, matrix, maxVal, totals } = useMemo(() => {
    const sess = data?.sessions || [];
    const set = new Set();
    const agg = new Map();          // "a|b" ordenado → {bytes, pkts, n, services:Set}
    for (const s of sess) {
      if (s.src === s.dst) continue;
      set.add(s.src); set.add(s.dst);
      const key = s.src < s.dst ? `${s.src}|${s.dst}` : `${s.dst}|${s.src}`;
      const e = agg.get(key) || { a: s.src < s.dst ? s.src : s.dst, b: s.src < s.dst ? s.dst : s.src, bytes: 0, pkts: 0, n: 0, services: [] };
      e.bytes += s.bytes || 0;
      e.pkts += s.packets || 0;
      e.n += 1;
      if (!e.services.includes(s.service)) e.services.push(s.service);
      agg.set(key, e);
    }
    const hosts = [...set].sort((x, y) => {
      const nb = (ip) => agg.entries ? false : false;
      return x.localeCompare(y);
    });
    // ordenar por volumen implicado (más activos arriba-izquierda)
    const vol = new Map();
    for (const ip of set) vol.set(ip, 0);
    for (const e of agg.values()) {
      vol.set(e.a, (vol.get(e.a) || 0) + e.bytes);
      vol.set(e.b, (vol.get(e.b) || 0) + e.bytes);
    }
    hosts.sort((x, y) => (vol.get(y) || 0) - (vol.get(x) || 0));
    const maxVal = Math.max(1, ...[...agg.values()].map((e) => e.bytes));
    const totals = {};
    for (const e of agg.values()) {
      totals[e.a] = (totals[e.a] || 0) + e.bytes;
      totals[e.b] = (totals[e.b] || 0) + e.bytes;
    }
    return { hosts: hosts.slice(0, 24), matrix: [...agg.values()], maxVal, totals };
  }, [data?.sessions]);

  if (!hosts.length)
    return <div className="empty-note">Sin conversaciones todavía: inicia captura o carga un PCAP.</div>;

  const cellSize = Math.min(30, Math.floor((900 - 160) / Math.max(8, hosts.length)));
  const gridW = 150 + hosts.length * (cellSize + 4);
  const gridH = 44 + hosts.length * (cellSize + 4);
  const idx = new Map(hosts.map((h, i) => [h, i]));

  const colorFor = (v) => {
    const t = Math.pow(v / maxVal, 0.35);
    if (t < 0.02) return "#131a24";
    return `rgba(34,211,238,${0.18 + 0.78 * t})`;
  };

  return (
    <div>
      <div className="section-title">Matriz de conversación</div>
      <div className="section-sub">
        Quién habla con quién y cuánto. Intensidad cian ∝ bytes del par; clic en una celda para el detalle.
      </div>
      <div style={{ overflow: "auto" }}>
        <svg width={Math.max(gridW, 640)} height={gridH + 60} className="matrix-svg">
          {hosts.map((h, i) => (
            <text key={`r${i}`} x={142} y={44 + i * (cellSize + 4) + cellSize / 2 + 4}
                  textAnchor="end" fontSize="9.6" fill="#c8d3e0" className="mono">{h}</text>
          ))}
          {hosts.map((h, i) => (
            <text key={`c${i}`} x={158 + i * (cellSize + 4) + cellSize / 2}
                  y={40} fontSize="9" fill="#7b8798" transform={`rotate(-58, ${158 + i * (cellSize + 4) + cellSize / 2}, 40)`}>
              {h.split(".").slice(-2).join(".")}
            </text>
          ))}
          {matrix.map((e) => {
            const i = idx.get(e.a), j = idx.get(e.b);
            if (i === undefined || j === undefined) return null;
            const selOn = !picked || (picked.a === e.a && picked.b === e.b);
            return (
              <g key={`${e.a}|${e.b}`} onClick={() => setPicked(e)}
                 opacity={selOn ? 1 : 0.25} style={{ cursor: "pointer" }}>
                <rect x={158 + j * (cellSize + 4)} y={44 + i * (cellSize + 4)} width={cellSize}
                      height={cellSize} rx={3} fill={colorFor(e.bytes)} stroke="#263041" strokeWidth={0.6} />
                {/* simétrico: la conversación es bidireccional */}
                <rect x={158 + i * (cellSize + 4)} y={44 + j * (cellSize + 4)} width={cellSize}
                      height={cellSize} rx={3} fill={colorFor(e.bytes)} stroke="#263041" strokeWidth={0.6} />
              </g>
            );
          })}
          <text x={158} y={gridH + 12} fontSize="9.6" fill="#7b8798">
            {matrix.length} pares · máximo {fmtB(maxVal)} ·ordenados por volumen implicado
          </text>
        </svg>
      </div>

      {picked && (
        <div className="host-card" style={{ position: "fixed", right: 26, top: 96, zIndex: 120, width: 320 }}>
          <button className="close-x" onClick={() => setPicked(null)}><X size={13} /></button>
          <div className="host-name">{picked.a} ⇄ {picked.b}</div>
          <div className="kv"><span>Bytes</span><b>{fmtB(picked.bytes)}</b></div>
          <div className="kv"><span>Paquetes</span><b>{picked.pkts.toLocaleString()}</b></div>
          <div className="kv"><span>Sesiones</span><b>{picked.n}</b></div>
          <div className="kv"><span>Servicios</span><b>{picked.services.join(", ")}</b></div>
        </div>
      )}
    </div>
  );
}
