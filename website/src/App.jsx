import React from "react";
import { motion } from "framer-motion";
import {
  Activity, Download, FileSearch, Globe, ImageIcon, KeyRound, MessageSquare,
  Network, Radio, Server, Settings2, Shield, Terminal, Wifi, FileDown, Gauge,
  AppWindow, FileQuestion,
} from "lucide-react";

const fadeUp = (delay = 0) => ({
  initial: { opacity: 0, y: 26 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-60px" },
  transition: { duration: 0.55, delay, ease: [0.2, 0.8, 0.2, 1] },
});

const FEATURES = [
  { icon: Network, t: "Hosts de la red", d: "Descubre cada IP viva por ARP, DNS/mDNS/LLMNR, HTTP y tráfico directo. Ficha completa: MAC, fabricante de la NIC, TTL mínimo y SO estimado, puertos TCP observados, paquetes enviados/recibidos y las keywords que viajan por su tráfico.", cls: "" },
  { icon: FileSearch, t: "Archivos reconstruidos", d: "Objetos extraídos del tráfico HTTP con nombre, MIME, tamaño, SHA-256, origen y destino. Descarga el original o examínalo en la propia tabla.", cls: "violet" },
  { icon: ImageIcon, t: "Imágenes con preview", d: "Las imágenes capturadas (PNG/JPEG/GIF/WebP) se reconstruyen y se previsualizan en miniaturas con lightbox — como el Images de NetworkMiner, pero en vivo.", cls: "green" },
  { icon: MessageSquare, t: "Mensajes de la red", d: "Peticiones y respuestas HTTP completas, metadatos de correo SMTP y cualquier conversación de protocolo en claro, con cabeceras y cuerpos expandibles.", cls: "red" },
  { icon: KeyRound, t: "Credenciales interceptadas", d: "Formularios URL-encoded, USER/PASS de FTP, cabeceras Authorization y cookies: usuario, password o hash, dominio, extremos y la evidencia textual.", cls: "red" },
  { icon: Radio, t: "Sesiones TCP/UDP", d: "Cada flujo con estado (SYN → ESTABLISHED → FIN/RST), servicio identificado, bytes y paquetes por dirección y timeline de inicio/fin.", cls: "" },
  { icon: Globe, t: "DNS / mDNS / LLMNR", d: "Consultas y respuestas con registros A/AAAA/CNAME/MX/TXT/PTR, rcodes y TTL. Los .local y LLMNR delatan hostnames de la red local automáticamente.", cls: "violet" },
  { icon: Settings2, t: "Parámetros y keywords", d: "GET/POST/JSON extraídos parámetro a parámetro, y un radar de palabras sensibles (password, token, secret…) con contexto textual de cada aparición.", cls: "green" },
  { icon: AppWindow, t: "App de escritorio portable", d: "La misma aplicación, en ventana nativa Electron: sudo ./start-desktop.sh arriba y a trabajar. Sin navegador, sin configurar nada, con venv Python aislado del sistema y backend auto-gestionado.", cls: "" },
];

const FAQ = [
  ["¿Necesito root?", "Para capturar en interfaces reales sí: la captura cruda requiere CAP_NET_RAW/CAP_NET_ADMIN. En Kali, un simple `sudo` basta. Ver docs para arranque con sudo o setcap."],
  ["¿Es legal?", "Capturar tráfico de redes que administras o tienes autorización escrita para auditar, sí. Sniffer a redes ajenas = delito. Úsalo en labs, CTFs y auditorías autorizadas."],
  ["¿Ve HTTPS?", "El cifrado impide leer contenido: SniffNex ve IPs, dominios SNI/DNS, tamaños y patrones. Credenciales y archivos solo aparecen en protocolos en claro (HTTP, FTP, SMTP…)."],
  ["¿Hay versión de escritorio?", "Sí: `sudo ./start-desktop.sh` abre la app en ventana nativa Electron con el mismo diseño de la web, sin navegador, con un venv Python portable e integrado y todo auto-gestionado. Se cierra limpiamente al cerrar la ventana."],
  ["¿Incluye datos de demo para probar?", "Sí: la carpeta `tools/` trae un generador de tráfico (`demo_traffic.py`) que crea un PCAP completo para cargar desde la UI y testear todas las secciones sin necesidad de una red real."],
  ["¿Puedo cargar un PCAP que ya tengo?", "Sí, desde la UI («Cargar PCAP») o por API: `curl -F file=@evidencia.pcap :8099/api/upload/pcap`. Toda la suite funciona igual que en vivo."],
];

export default function App() {
  return (
    <div>
      <nav className="nav">
        <div className="nav-logo">
          <Wifi size={20} color="var(--accent)" /> Sniff<span className="nex">Nex</span>
        </div>
        <div className="nav-links">
          <a href="#features">Características</a>
          <a href="#desktop">Escritorio</a>
          <a href="#quickstart">Inicio rápido</a>
          <a href="/docs.html" className="docs-link-strong">Documentación</a>
          <a href="#faq">FAQ</a>
          <a href="https://github.com/D1se0/sniffnetx" target="_blank" rel="noreferrer" className="nav-cta">
            <Download size={15} /> Repositorio
          </a>
        </div>
      </nav>

      <header className="hero">
        <div className="hero-grid" />
        <div className="hero-inner">
          <motion.div className="hero-tagline" {...fadeUp(0)}>
            <Activity size={13} /> NETWORK FORENSICS · LINUX PORTABLE · GPL
          </motion.div>
          <motion.h1 {...fadeUp(0.08)}>
            Escucha tu red.<br />
            <span className="grad">Reconstruye la verdad.</span>
          </motion.h1>
          <motion.p className="sub" {...fadeUp(0.16)}>
            SniffNex es un analizador de tráfico pasivo tipo <strong>NetworkMiner</strong> construido en Python + React:
            hosts, archivos e imágenes reconstruidas, mensajes, credenciales, sesiones, DNS y parámetros — todo en vivo,
            con exportación a PCAP, CSV, JSON y <strong>informes PDF</strong>, también como <strong>app de escritorio</strong>.
          </motion.p>
          <motion.div className="hero-actions" {...fadeUp(0.24)}>
            <a href="#quickstart" className="btn-xl primary"><Terminal size={17} /> Empezar en 60 segundos</a>
            <a href="/docs.html" className="btn-xl outline docs-btn-outline"><FileQuestion size={17} /> Documentación completa</a>
          </motion.div>

          <motion.div className="terminal" {...fadeUp(0.32)}>
            <div className="bar">
              <span className="dot" style={{ background: "#fb7185" }} />
              <span className="dot" style={{ background: "#fbbf24" }} />
              <span className="dot" style={{ background: "#34d399" }} />
              <span style={{ color: "var(--dim)", fontFamily: "var(--mono)", fontSize: 11.5, marginLeft: 8 }}>kali@auditoria: ~/sniffnetx</span>
            </div>
            <pre>
              <span className="tcmd">kali ➜ sudo ./start-desktop.sh</span>{"\n"}
              <span className="tout">[*] venv portable en backend/venv · deps instaladas</span>{"\n"}
              <span className="tout">[*] Backend  → http://localhost:8099  (FastAPI + WS en vivo)</span>{"\n"}
              <span className="tout">[✓] Ventana  → app de escritorio Electron abierta</span>{"\n"}
              <span className="thi">[✓] HOSTS: 8  · CREDENCIALES: 7  · ARCHIVOS: 1  · DNS: 11</span>{"\n"}
              <span className="twarn">[!] POST /login  user=auditor-tiana  password=Tr4xBDu1987</span>
            </pre>
          </motion.div>
        </div>
      </header>

      <div className="marquee">
        <div className="marquee-track">
          {[...Array(2)].map((_, k) => (
            <React.Fragment key={k}>
              {["HOSTS", "ARCHIVOS", "IMÁGENES", "MENSAJES", "CREDENCIALES", "SESIONES", "DNS", "PARÁMETROS", "KEYWORDS", "PCAP", "PDF REPORT", "APP ESCRITORIO"].map((x) => (
                <span key={x}>◆ <b>{x}</b></span>
              ))}
            </React.Fragment>
          ))}
        </div>
      </div>

      <section className="section" id="features">
        <motion.div {...fadeUp()}>
          <div className="section-tag">Features</div>
          <h2>Nueve instrumentos, un panel</h2>
          <p className="lead">
            Cada protocolo que viaja por la red deja rastros. SniffNex los reensambla y los presenta por secciones,
            con filtros, ordenación y detalle expandible en cada una — pensado para auditorías reales.
          </p>
        </motion.div>
        <div className="cards">
          {FEATURES.map((f, i) => (
            <motion.div key={f.t} className={`card ${f.cls}`} {...fadeUp(0.05 * (i % 4))}>
              <div className="icon-box"><f.icon size={21} /></div>
              <h3>{f.t}</h3>
              <p>{f.d}</p>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="section" id="desktop" style={{ background: "var(--bg2)" }}>
        <motion.div {...fadeUp()}>
          <div className="section-tag">Desktop app</div>
          <h2>Una ventana, no un navegador</h2>
          <p className="lead">
            La aplicación de escritorio Electron utiliza exactamente la misma UI React que ya conoces, pero ejecutada
            en ventana nativa. Se autogestiona: crea su propio entorno Python en <code>backend/venv</code>, arranca el
            backend como proceso hijo, y cierra todo limpiamente cuando cierras la ventana. Perfecta para uso en
            auditorías donde no quieres un navegador masivamente abierto.
          </p>
        </motion.div>
        <div className="steps">
          <pre style={{
            background: "var(--panel)", padding: "19px 22px", borderRadius: 15,
            border: "1px solid var(--line)", fontFamily: "var(--mono)",
            fontSize: 13.5, lineHeight: 1.85, overflowX: "auto", color: "#c9d5ea",
          }}>
<span className="tcmd">kali ➜ sudo ./start-desktop.sh</span>{"\n"}{"\n"}
<span className="tout">   ┌─┐┌─┐┌┐┌┌─┐┬─┐┌─┐┌┐┌</span>{"\n"}
<span className="tout">   │  ├─┤│││├┤ ├┬┘├─┤│││   DESKTOP</span>{"\n"}
<span className="tout">   └─┘┴ ┴┘└┘└─┘┴└─┴ ┴┘└┘   v1.0 · portable</span>{"\n"}{"\n"}
<span className="thi">[✓] venv backend/venv creado (scapy+fastapi+uvicorn auto-instalados)</span>{"\n"}
<span className="thi">[✓] backend uvicorn escuchando en 127.0.0.1:8099</span>{"\n"}
<span className="thi">[✓] ventana Electron abierta — cerrar la ventana = cerrar todo limpio</span>{"\n"}{"\n"}
<span className="m"># También disponible:</span>{"\n"}
<span className="tout">./start-desktop.sh build   </span><span className="m"># genera paquete portable + AppImage</span>
          </pre>
        </div>
      </section>

      <section className="section" id="quickstart">
        <motion.div {...fadeUp()}>
          <div className="section-tag">Inicio rápido</div>
          <h2>Operativo en 60 segundos</h2>
          <p className="lead">
            Portable: no toca tu sistema, solo necesita Python 3.11+ con scapy y Node opcional para la UI compilada
            (que ya viene generada en el repositorio).
          </p>
        </motion.div>
        <div className="steps">
          {[
            {
              t: "Clona el repositorio e instala dependencias",
              c: (
                <>
                  <span className="m"># Kali / Debian / Ubuntu</span>{"\n"}
                  <span className="c">git clone</span> https://github.com/D1se0/sniffnetx.git{"\n"}
                  <span className="c">cd</span> sniffnetx/backend{"\n"}
                  pip install scapy fastapi "uvicorn[standard]" python-multipart reportlab{"\n"}
                  <span className="m"># (la UI ya viene compilada en frontend/dist)</span>
                </>
              ),
            },
            {
              t: "Arranca SniffNex (con permisos de captura)",
              c: (
                <>
                  <span className="m"># Opción A — app de escritorio (recomendada en Kali)</span>{"\n"}
                  sudo ./start-desktop.sh{"\n"}
                  <span className="m"># Opción B — en navegador</span>{"\n"}
                  sudo ./run.sh{"\n"}
                  <span className="m"># Opción C — capacidades sin root</span>{"\n"}
                  sudo setcap cap_net_raw,cap_net_admin=eip $(which python3.11){"\n"}
                  ./run.sh
                </>
              ),
            },
            {
              t: "Abre la consola y elige adaptador",
              c: (
                <>
                  xdg-open http://localhost:8099{"\n"}
                  <span className="m"># 1) elige interfaz (eth0, wlan0…)</span>{"\n"}
                  <span className="m"># 2) opcional: filtro BPF (tcp port 80)</span>{"\n"}
                  <span className="m"># 3) pulsa «Iniciar sniffer»</span>
                </>
              ),
            },
            {
              t: "Genera o carga tráfico de ejemplo",
              c: (
                <>
                  <span className="m"># Genera un PCAP de demo con TODAS las secciones activas:</span>{"\n"}
                  python3 tools/demo_traffic.py pcap /tmp/demo.pcap{"\n"}
                  <span className="m"># …y cárgalo en la UI (botón «Cargar PCAP»)</span>{"\n"}
                  <span className="m"># …o vuélcalo en vivo a tu loopback:</span>{"\n"}
                  sudo python3 tools/demo_traffic.py lo
                </>
              ),
            },
            {
              t: "Exporta tu evidencia",
              c: (
                <>
                  <span className="m"># Desde la UI: Exportar ▾</span>{"\n"}
                  <span className="g">PCAP</span>  crudo para Wireshark{"\n"}
                  <span className="g">CSV</span>   hosts / creds / DNS / params{"\n"}
                  <span className="g">JSON</span>  todo jerárquico{"\n"}
                  <span className="g">PDF</span>   informe forense paginado
                </>
              ),
            },
          ].map((s, i) => (
            <motion.div key={i} className="step" {...fadeUp(0.07 * i)}>
              <div className="num">{String(i + 1).padStart(2, "0")}</div>
              <div style={{ flex: 1 }}>
                <h3>{s.t}</h3>
                <pre>{s.c}</pre>
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="section" id="docs-preview" style={{ background: "none", paddingTop: 20 }}>
        <motion.div {...fadeUp()}>
          <div className="section-tag">Documentación</div>
          <h2>Sección aparte, súper detallada</h2>
          <p className="lead">
            La documentación técnica completa — cada sección de la App con su teoría de fondo, cómo lo calcula
            internamente SniffNex, qué esperar y qué NO esperar, ejemplos visuales de cómo se ve en la interfaz,
            y recetas paso a paso con comandos — vive en una página separada para que la puedas consultar sin
            interrumpir la lectura de la portada.
          </p>
          <motion.a
            href="/docs.html"
            className="btn-xl primary"
            style={{ marginTop: 22, display: "inline-flex" }}
            {...fadeUp(0.1)}
          >
            <FileQuestion size={17} /> Abrir la documentación ultra detallada
          </motion.a>
        </motion.div>
      </section>

      <section className="section" id="faq" style={{ background: "var(--bg2)" }}>
        <motion.div {...fadeUp()}>
          <div className="section-tag">FAQ</div>
          <h2>Preguntas frecuentes</h2>
        </motion.div>
        <div className="cards">
          {FAQ.map(([q, a], i) => (
            <motion.div key={q} className="card" {...fadeUp(0.06 * i)}>
              <h3>{q}</h3>
              <p>{a}</p>
            </motion.div>
          ))}
        </div>
      </section>

      <footer>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Wifi size={16} color="var(--accent)" />
          <strong style={{ color: "var(--txt)" }}>SniffNex</strong>
          <span className="mono">v1.0 · GPL-3.0 · by D1se0</span>
        </div>
        <div className="mono">Herramienta educativa/no intrusiva — úsala solo en redes propias o autorizadas.</div>
      </footer>
    </div>
  );
}
