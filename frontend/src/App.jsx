import React, { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity, ArrowDownToLine, FileSearch, Globe, Image, KeyRound, MessageSquare,
  Network, Play, Radio, Settings2, Square, Terminal
} from "lucide-react";

import { api } from "./api.js";
import Topbar from "./components/Topbar.jsx";
import Overview from "./views/Overview.jsx";
import Hosts from "./views/Hosts.jsx";
import FilesView from "./views/Files.jsx";
import Credentials from "./views/Credentials.jsx";
import Messages from "./views/Messages.jsx";
import Sessions from "./views/Sessions.jsx";
import DNSView from "./views/DNS.jsx";
import Params from "./views/Params.jsx";
import PacketExplorer from "./views/PacketExplorer.jsx";

const SECTIONS = [
  { id: "overview", label: "Overview", icon: Activity, countKey: null },
  { id: "hosts", label: "Hosts", icon: Network, countKey: "hosts" },
  { id: "sessions", label: "Sesiones", icon: Radio, countKey: "sessions" },
  { id: "files", label: "Archivos", icon: FileSearch, countKey: "files" },
  { id: "messages", label: "Mensajes", icon: MessageSquare, countKey: "messages" },
  { id: "credentials", label: "Credenciales", icon: KeyRound, countKey: "credentials" },
  { id: "dns", label: "DNS", icon: Globe, countKey: "dns" },
  { id: "params", label: "Parámetros", icon: Settings2, countKey: "parameters" },
  { id: "packets", label: "Paquetes", icon: Terminal, countKey: null },
];

export default function App() {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState({ running: false });
  const [section, setSection] = useState("overview");
  const [selectedHost, setSelectedHost] = useState(null);
  const [lightbox, setLightbox] = useState(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const d = await api("/api/data");
        if (alive) setData(d);
        const s = await api("/api/capture/status");
        if (alive) setStatus(s);
      } catch { /* backend caido */ }
    };
    tick();
    const iv = setInterval(tick, 1500);
    return () => { alive = false; clearInterval(iv); };
  }, []);

  const stats = data?.stats || {};

  return (
    <div className="app">
      <Topbar data={data} status={status} />
      <div className="main">
        <aside className="sidebar">
          {SECTIONS.map((s) => {
            const count = s.countKey && data ? (data[s.countKey]?.length ?? 0) : null;
            return (
              <button
                key={s.id}
                className={`nav-item ${section === s.id ? "active" : ""}`}
                onClick={() => setSection(s.id)}
              >
                <s.icon size={17} strokeWidth={2} />
                {s.label}
                {count !== null && <span className="count">{count}</span>}
              </button>
            );
          })}
        </aside>
        <main className="content">
          <AnimatePresence mode="wait">
            <motion.div
              key={section}
              initial={{ opacity: 0, y: 14 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.28, ease: [0.2, 0.8, 0.2, 1] }}
            >
              {section === "overview" && <Overview data={data} status={status} go={setSection} />}
              {section === "hosts" && <Hosts data={data} selected={selectedHost} setSelected={setSelectedHost} />}
              {section === "sessions" && <Sessions data={data} />}
              {section === "files" && <FilesView data={data} setLightbox={setLightbox} />}
              {section === "messages" && <Messages data={data} />}
              {section === "credentials" && <Credentials data={data} />}
              {section === "dns" && <DNSView data={data} />}
              {section === "params" && <Params data={data} />}
              {section === "packets" && <PacketExplorer status={status} />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <AnimatePresence>
        {lightbox && (
          <motion.div
            className="lightbox"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setLightbox(null)}
          >
            <motion.img
              src={lightbox}
              initial={{ scale: 0.85, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              transition={{ type: "spring", damping: 22, stiffness: 260 }}
            />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
