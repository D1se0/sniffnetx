import React from "react";
import { motion } from "framer-motion";
import { BarChart, Bar, ResponsiveContainer, XAxis, YAxis, Tooltip, PieChart, Pie, Cell } from "recharts";
import { ArrowRight } from "lucide-react";

const PROTO_COLORS = ["#22d3ee", "#a78bfa", "#34d399", "#fbbf24", "#fb7185", "#60a5fa", "#f472b6"];

export default function Overview({ data, status, go }) {
  const s = data?.stats || { packets: 0, tcp: 0, udp: 0, icmp: 0, arp: 0, http: 0, dns: 0 };
  const hosts = data?.hosts || [];
  const protoData = [
    { name: "TCP", value: s.tcp },
    { name: "UDP", value: s.udp },
    { name: "ICMP", value: s.icmp },
    { name: "ARP", value: s.arp },
    { name: "HTTP", value: s.http },
    { name: "DNS", value: s.dns },
  ].filter((d) => d.value > 0);

  const topHosts = hosts.slice(0, 7).map((h) => ({ name: h.ip, value: h.packet_count }));

  const kpis = [
    { lbl: "Paquetes capturados", val: s.packets ?? 0, cls: "" },
    { lbl: "Hosts en la red", val: hosts.length, cls: "violet" },
    { lbl: "Sesiones TCP/UDP", val: (data?.sessions || []).length, cls: "green" },
    { lbl: "Credenciales", val: (data?.credentials || []).length, cls: "red" },
    { lbl: "Archivos", val: (data?.files || []).length, cls: "" },
    { lbl: "Peticiones DNS", val: (data?.dns || []).length, cls: "violet" },
  ];

  return (
    <div>
      <div className="section-title">Overview forense en vivo</div>
      <div className="section-sub">
        {status.running
          ? `Capturando en ${status.iface} — los datos se refrescan cada 1.5 s.`
          : "Sniffer detenido. Elige un adaptador arriba y pulsa «Iniciar sniffer», o exporta / examina datos previos."}
      </div>

      <div className="kpi-grid">
        {kpis.map((k, i) => (
          <motion.div
            className={`kpi ${k.cls}`}
            key={k.lbl}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05, duration: 0.35, ease: [0.2, 0.8, 0.2, 1] }}
          >
            <div className="val">{k.val.toLocaleString("es")}</div>
            <div className="lbl">{k.lbl}</div>
          </motion.div>
        ))}
      </div>

      <div className="over-grid">
        <div className="card">
          <h3>Tráfico por protocolo</h3>
          {protoData.length ? (
            <ResponsiveContainer width="100%" height={230}>
              <PieChart>
                <Pie
                  data={protoData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={62}
                  outerRadius={94}
                  paddingAngle={4}
                  animationDuration={700}
                >
                  {protoData.map((_, i) => (
                    <Cell key={i} fill={PROTO_COLORS[i % PROTO_COLORS.length]} stroke="#0b0e15" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#141926", border: "1px solid #2a3550", borderRadius: 10, fontFamily: "JetBrains Mono", fontSize: 12 }}
                  itemStyle={{ color: "#e7ecf5" }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty"><div className="big">∅</div>Sin datos aún — inicia el sniffer.</div>
          )}
          <div className="spark-note">
            TCP {s.tcp} · UDP {s.udp} · ICMP {s.icmp} · ARP {s.arp} · HTTP {s.http} · DNS {s.dns}
          </div>
        </div>

        <div className="card">
          <h3>Hosts más activos</h3>
          {topHosts.length ? (
            <>
              <ResponsiveContainer width="100%" height={230}>
                <BarChart data={topHosts} layout="vertical" margin={{ left: 8, right: 20 }}>
                  <XAxis type="number" hide />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={110}
                    tick={{ fill: "#8b96ad", fontFamily: "JetBrains Mono", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{ background: "#141926", border: "1px solid #2a3550", borderRadius: 10, fontFamily: "JetBrains Mono", fontSize: 12 }}
                    itemStyle={{ color: "#e7ecf5" }}
                    cursor={{ fill: "rgba(34,211,238,0.06)" }}
                  />
                  <Bar dataKey="value" fill="#22d3ee" radius={[0, 6, 6, 0]} animationDuration={700} />
                </BarChart>
              </ResponsiveContainer>
              <button className="btn ghost" onClick={() => go("hosts")} style={{ marginTop: 6 }}>
                Ver todos los hosts <ArrowRight size={13} />
              </button>
            </>
          ) : (
            <div className="empty"><div className="big">⌁</div>Todavía no hay hosts detectados.</div>
          )}
        </div>
      </div>
    </div>
  );
}
