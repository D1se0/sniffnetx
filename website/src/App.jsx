import React from "react";
import { motion } from "framer-motion";
import {
  Activity, Download, FileSearch, Globe, ImageIcon, KeyRound, MessageSquare,
  Network, Radio, Server, Settings2, Shield, Terminal, Wifi, FileDown, Gauge,
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
  { icon: Settings2, t: "Parámetros y keywords", d: "GET/POST/JSON extraídos parámetro a parámetro, y un radar de keywords sensibles (password, token, secret…) con contexto textual de cada aparición.", cls: "green" },
];

const PARAMS_DOC = [
  ["IP", "Dirección IP del host detectado. Puede ser unicast de la LAN, el gateway, un servidor remoto o una dirección multicast (224.0.0.251 = mDNS). SniffNex registra un host por cada IP origen o destino que ve pasar, aunque solo escuche tráfico propio."],
  ["MAC", "Dirección física de nivel 2 aprendida de las tramas Ethernet o de ARP. Si el host nunca emite ARP/frame local puede ser «—» (p. ej. IPs de Internet vistas por su tráfico de respuesta)."],
  ["NIC vendor", "Fabricante de la tarjeta de red, resuelto por los 3 primeros octetos de la MAC (OUI) contra una base local (wireshark-manuf compatible). «Locally administered» indica MAC virtual o aleatorizada (anti-tracking, posible spoofing)."],
  ["MAC age / randomized", "SniffNex marca las MAC con el bit «locally administered» (2º dígito par 2/6/A/E) como aleatorizadas — típico de móviles modernos en modo privacidad o de herramientas de spoofing."],
  ["Hostname", "Nombre de equipo deducido de peticiones mDNS (*.local), LLMNR, NBNS o de cabeceras HTTP. Es best-effort: no todos los hosts revelan su nombre por la red."],
  ["OS / SO estimado", "Heurística basada en el TTL IP mínimo observado: ≈64 → Linux/Unix/Android; ≈128 → Windows; ≈255 → routers/embebidos. Se refina con el User-Agent HTTP cuando está disponible."],
  ["TTL (mín)", "El valor de TTL más pequeño visto para ese host. Cuantos menos saltos, más cerca del TTL real del SO; por eso se guarda el mínimo en lugar del último."],
  ["Open TCP ports", "Puertos donde se observó SYN+ACK (apertura) o tráfico de sesión activo. Es observación pasiva: no se envía ningún paquete de escaneo."],
  ["Paquetes enviados / recibidos", "Contadores de paquetes IP por dirección respecto a ese host: «Env» son los que el host origins (src = host) y «Rec» los que llegan a él (dst = host)."],
  ["En proceso (buffer)", "Los paquetes se acumulan en un buffer circular interno (para exportar PCAP) y en el analizador en vivo; «en proceso» es ese material aún en memoria listo para reconstrucción y export."],
  ["Content-Type / MIME", "Tipo MIME del archivo reconstruido según la cabecera HTTP. SniffNex lo usa para decidir vista previa (imágenes) o descarga binaria."],
  ["SHA-256", "Huella criptográfica del archivo reconstruido: sirve para correlacionar muestras en la investigación (mismo fichero en varias sesiones = mismo hash)."],
  ["Rcode DNS", "Código de resultado DNS: NOERROR (0), NXDOMAIN (3), SERVFAIL (2)… Ráfagas de NXDOMAIN pueden indicar túnel DNS o malware generando consultas masivas."],
  ["Sesión (estado)", "Estado del flujo TCP deducido de los flags: SYN_SENT (apertura), ESTABLISHED (S/A), FIN_WAIT (cierre limpio), RST (rechazo). En UDP no hay estado: se muestra el servicio."],
  ["BPF (filtro de captura)", "Sintaxis tcpdump aplicada dentro del kernel para descartar tráfico antes de tocar el user-space: «tcp port 443», «host 192.168.1.10 and not arp», «net 10.0.0.0/8»…"],
  ["Snaplen", "Longitud máxima de instantánea por paquete. 65535 = paquete completo (recomendado para reconstruir archivos); valores bajos (96) solo capturan cabeceras."],
  ["Modo promiscuo", "Hace que la NIC acepte tramas no dirigidas a su MAC — imprescindible para ver el tráfico de los demás en la LAN (conmutada, solo verás broadcast/multicast y tu tráfico salvo ARP-spoof)."],
];

const FAQ = [
  ["¿Necesito root?", "Para capturar en interfaces reales sí: la captura cruda requiere CAP_NET_RAW/CAP_NET_ADMIN. En Kali, un simple `sudo` basta. Ver docs para arranque con sudo o setcap."],
  ["¿Es legal?", "Capturar tráfico de redes que administras o tienes autorización escrita para auditar, sí. Sniffer a redes ajenas = delito. Úsalo en labs, CTFs y auditorías autorizadas."],
  ["¿Ve HTTPS?", "El cifrado impide leer contenido: SniffNex ve IPs, dominios SNI/DNS, tamaños y patrones. Credenciales y archivos solo aparecen en protocolos en claro (HTTP, FTP, SMTP…)."],
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
          <a href="#quickstart">Inicio rápido</a>
          <a href="#params">Documentación</a>
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
            con exportación a PCAP, CSV, JSON y <strong>informes PDF</strong>.
          </motion.p>
          <motion.div className="hero-actions" {...fadeUp(0.24)}>
            <a href="#quickstart" className="btn-xl primary"><Terminal size={17} /> Empezar en 60 segundos</a>
            <a href="#params" className="btn-xl outline">Documentación completa</a>
          </motion.div>

          <motion.div className="terminal" {...fadeUp(0.32)}>
            <div className="bar">
              <span className="dot" style={{ background: "#fb7185" }} />
              <span className="dot" style={{ background: "#fbbf24" }} />
              <span className="dot" style={{ background: "#34d399" }} />
              <span style={{ color: "var(--dim)", fontFamily: "var(--mono)", fontSize: 11.5, marginLeft: 8 }}>kali@auditoria: ~/sniffnetx</span>
            </div>
            <pre>
              <span className={"tcmd"}>kali ➜ ./sniffnetx.sh</span>{"\n"}
              <span className={"tout"}>[*] Interfaz por defecto: eth0 · 192.168.5.131 [VMware]</span>{"\n"}
              <span className={"tout"}>[*] Backend  → http://localhost:8099  (FastAPI + WS en vivo)</span>{"\n"}
              <span className={"tout"}>[*] Frontend → http://localhost:8099/  (UI React embebida)</span>{"\n"}
              <span className={"tout"}>[*] Escuchando… pulsa «Iniciar sniffer» en la UI. [PERM iso OK]</span>{"\n"}
              <span className={"thi"}>[✓] HOSTS: 4  · CREDENCIALES: 2  · ARCHIVOS: 1  · DNS: 38</span>{"\n"}
              <span className={"twarn"}>[!] POST /login  user=admin  password=S3cr3t123  (192.168.5.60)</span>
            </pre>
          </motion.div>
        </div>
      </header>

      <div className="marquee">
        <div className="marquee-track">
          {[...Array(2)].map((_, k) => (
            <React.Fragment key={k}>
              {["HOSTS", "ARCHIVOS", "IMÁGENES", "MENSAJES", "CREDENCIALES", "SESIONES", "DNS", "PARÁMETROS", "KEYWORDS", "PCAP", "PDF REPORT", "LIVE WebSocket"].map((x) => (
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
            con filtros, ordenación y detalle expandible en cada one — pensado para auditorías reales.
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

      <section className="section" id="quickstart" style={{ background: "var(--bg2)" }}>
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
                  pip install scapy fastapi "uvicorn[standard]"{"\n"}
                  <span className="m"># (la UI ya viene compilada en frontend/dist)</span>
                </>
              ),
            },
            {
              t: "Arranca SniffNex (con permisos de captura)",
              c: (
                <>
                  <span className="m"># Opción A — sudo (lo normal en Kali)</span>{"\n"}
                  sudo ./run.sh{"\n"}
                  <span className="m"># Opción B — capacidades sin root</span>{"\n"}
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
                <p>{s.p || ""}</p>
                {s.c && <pre>{s.c}</pre>}
              </div>
            </motion.div>
          ))}
        </div>
      </section>

      <section className="section" id="params">
        <motion.div {...fadeUp()}>
          <div className="section-tag">Documentación</div>
          <h2>Cada parámetro, explicado</h2>
          <p className="lead">
            Referencia ultra detallada de todos los campos que verás en la interfaz: qué significan, de dónde salen
            y cómo usarlos en una investigación.
          </p>
        </motion.div>
        <motion.table className="doc-table" {...fadeUp(0.1)}>
          <thead><tr><th>Parámetro</th><th>Significado y uso forense</th></tr></thead>
          <tbody>
            {PARAMS_DOC.map(([k, d]) => (
              <tr key={k}><td>{k}</td><td className="mut">{d}</td></tr>
            ))}
          </tbody>
        </motion.table>
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
