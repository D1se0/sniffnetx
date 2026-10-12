import React, { useState } from "react";
import { motion } from "framer-motion";
import {
  Network, FileSearch, ImageIcon, MessageSquare, KeyRound, Radio, Globe,
  Settings2, Search, ArrowLeft, Terminal, Download,
} from "lucide-react";

const fadeUp = (delay = 0) => ({
  initial: { opacity: 0, y: 26 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-60px" },
  transition: { duration: 0.55, delay, ease: [0.2, 0.8, 0.2, 1] },
});

// ─────────────────────────────────────────────────────────────────────────────────
// DATA: teoría + ejemplos reales de cada sección de la App
// ─────────────────────────────────────────────────────────────────────────────────
const SECTIONS = [
  {
    id: "hosts", icon: Network, title: "Hosts",
    theory: [
      "Qué es: la sección Hosts construye un inventario vivo de TODA estación que participa en el tráfico capturado: cada dirección IP que aparece como origen o destino se registra como «host», aunque nunca hable directamente con tu equipo.",
      "Cómo lo descubre: SniffNex es pasivo. No lanza ni un ping. Un host entra en la tabla por cualquiera de estas vías: (1) tramas ARP locales, la más fiable; (2) cualquier paquete IP cuyo src/dst se observe; (3) respuestas DNS que resuelven dominios; (4) anuncios mDNS/LLMNR/NBNS que destapan hostnames; (5) cabeceras HTTP con hostnames de servidores internos.",
      "MAC y fabricante: la MAC se aprende de la capa Ethernet o de ARP. Los 3 primeros bytes (OUI) se consultan contra una base de fabricantes compatible con el manuf de Wireshark — así distingues a golpe de vista «Apple», «Raspberry Pi Foundation» o «VMware» de una NIC genérica.",
      "SO estimado: el campo TTL del IP delata el SO del emisor original (64→Linux/Unix/Android, 128→Windows, 255→routers/embebidos) porque cada salo resta 1. SniffNex guarda el TTL mínimo visto, no el último, para minimizar el error por saltos.",
      "Puertos observados: únicamente donde viste tráfico real (SYN+ACK entrantes, sesiones vivas). No es un escaneo activo: si nadie conectó al puerto :8080, no aparecerá.",
      "Keywords por host: las palabras sensibles («password», «token», «database»…) que viajaron HOSTIA서 en paquetes con ese host se asocian a su ficha. Un servidor que tenga «password» + «database» en su tráfico merece revisión manual.",
    ],
    example: {
      task: "Ejemplo real: en la LAN hay 4. wifi, 1 TV Samsung, 1 Raspberry, 1 cámara barata.",
      rows: [
        { ip: "192.168.1.10", detail: "MAC 60:57:18:11:22:33 · Azurewave (módulo de móviles Android) · TTL 64 · SO: Linux/Android · puertos :5228 (FCM Google) · keywords: token" },
        { ip: "192.168.1.25", detail: "MAC B8:27:EB:99:88:77 · Raspberry Pi Foundation · hostname srv-home.local (mDNS) · TTL 64 · puertos :22 :8000 · keywords: database, ssh" },
        { ip: "192.168.1.30", detail: "MAC 00:16:79:AA:BB:CC · Sveon (cámara IP barata) · TTL 128 · puertos :80 :554 · keywords: admin, pass — ᴛɪᴘɪᴄᴀ ᴄᴀᴍ con credenciales en claro" },
      ],
    },
  },
  {
    id: "files", icon: FileSearch, title: "Archivos reconstruidos",
    theory: [
      "Qué es: cada fichero que pasó por la red en claro (HTTP) puede reensamblarse. SniffNex añade el nombre (Content-Disposition o la URL), su tamaño, MIME y el hash SHA-256 para correlación.",
      "Cómo lo hace: reensamblado de streams TCP por sesión; detecta Content-Disposition filename=…; en respuestas sin filename usa la heurística «¿el body parece un binario?»: firma mágica (PNG \\x89PNG, JPEG \\xff\\xd8, PDF %PDF, ZIP PK).",
      "Por qué el SHA-256 importa: el mismo fichero visto en 3 sesiones diferentes tendrá el mismo hash → «alguien reenvió el mismo adjunto». Si el hash cambia, descargaron dos versiones distintas.",
      "Limitación honesta: solo HTTP en claro y solo si el cuerpo llega completo; TLS/L7 cifrado no es reversible sin las claves.",
    ],
    example: {
      task: "Ejemplo real: alguien descarga el acta de la reunión por HTTP:",
      rows: [
        { ip: "acta_enero.pdf", detail: "412 KB · application/pdf · SHA-256 9f2c…a41b · GET /docs/acta_enero.pdf desde 10.0.0.7 → cdn.interno" },
        { ip: "equipo.exe", detail: "58 MB · application/octet-stream · SHA-256 00ab…9d · GET /setup/equipo.exe · ⚠️ alertlo: ejecutable por HTTP en claro" },
      ],
    },
  },
  {
    id: "images", icon: ImageIcon, title: "Imágenes (preview + lightbox)",
    theory: [
      "Qué es: subconjunto de «Archivos» especializado: cualquier imagen capturada (PNG/JPEG/GIF/WebP) con preview de miniatura y visor a pantalla completa.",
      "Cómo lo hace: valida la firma mágica bytes a bytes, no confía solo en el Content-Type que declara el servidor. Eso evita que un .exe renombrado a .jpg pase como imagen.",
      "Uso forense: en tráfico de tiendas online, chats en claro o webcams HTTP, ver la miniatura de una imagen con solo pasar el ratón evita abrirla en otra herramienta.",
    ],
    example: {
      task: "Ejemplo real: la app de una cámara IP barata manda JPEGs por HTTP:",
      rows: [
        { ip: "snapshot_2026-10-11_23h.jpg", detail: "212 KB · image/jpeg · firma validada ✓ · de 192.168.1.30 (cámara) hacia 192.168.1.5 (NVR)" },
      ],
    },
  },
  {
    id: "messages", icon: MessageSquare, title: "Mensajes HTTP / SMTP",
    theory: [
      "Qué es: transcripciones de cada petición HTTP y respuesta, y de diálogos SMTP que hayan pasado en claro: método, path, versión, host, User-Agent, cookies, referer, status…",
      "Cómo lo hace: si el paquete lleva la capa HTTPRequest/HTTPResponse de scapy se parsea estructurado; si un payload de una sesión «no-HTTP» contiene MAIL FROM/RCPT TO/DATA se identifica como diálogo SMTP y se registra como mensaje.",
      "Para qué sirve: literalmente lees la conversación que la máquina sostuvo con un servidor web o de correo. Los headers de User-Agent delatan scripts de atacantes (python-requests, sqlmap).",
    ],
    example: {
      task: "Ejemplo real — petición POST sospechosa:",
      rows: [
        { ip: "POST /login", detail: "HTTP/1.1 · Host: intranet.local · UA: sqlmap/1.8 ⚠️ (herramienta de inyección) · body: user=admin&password=… · de 192.168.1.77 (desconocido)" },
      ],
    },
  },
  {
    id: "credentials", icon: KeyRound, title: "Credenciales",
    theory: [
      "Qué es: toda credencial interceptada en claro: formularios login (user=…&password=…), USER/PASS de FTP, cabeceras Authorization (Basic/Bearer), cookies de sesión y contraseñas de protocolos de texto plano.",
      "Cómo lo hace: tres caminos: (1) regex de formularios URL-encoded en bodies POST; (2) parser de diálogos FTP (USER <u>\\r\\n PASS <p>); (3) detección de Authorization o Cookie HTTP; todo queda con su evidencia textual exacta para el informe.",
      "Regla de oro: si viajaba cifrado (HTTPS/SMTPS/SSH), aquí no aparecerá — eso NO es un fallo de la herramienta, es diseño (y lo mismo pasa en NetworkMiner, Wireshark o cualquier sniffer sin las claves).",
    ],
    example: {
      task: "Ejemplo real — el PCAP de demo que incluye la app:",
      rows: [
        { ip: "auditor-tiana / Tr4xBDu1987", detail: "form/urlencoded · POST /login · evidencia textual literal · 192.168.42.105 → 192.168.42.131" },
        { ip: "ftpbackup / H4rdC0re2026!", detail: "tipo ftp · USER/PASS detectados en conversación FTP · 192.168.42.60 → 192.168.42.131" },
        { ip: "Cookie secGxb29A1", detail: "tipo http-cookie · cabecera Cookie: session=… · host intranet.local" },
      ],
    },
  },
  {
    id: "sessions", icon: Radio, title: "Sesiones TCP/UDP",
    theory: [
      "Qué es: cada flujo (tupla IP:puerto ↔ IP:puerto) con su estado de mano TCP, servicio inferido, bytes y paquetes por dirección y ventana temporal.",
      "Estados: SYN_SENT (Cliente abrió), ESTABLISHED (review SYN/SYN-ACK/ACK), FIN_WAIT (cierre limpio), RST (rechazo brusco: típico puerto cerrado o kill forzado). En UDP no hay estado: se lista el servicio.",
      "Servicios: tabla de puertos conocidos (80→http, 443→https, 53→dns, 21→ftp, 25→smtp, 3306→mysql…) sobre la que se etiqueta el flujo. puertos no estándar aparecen tal cual (:8443, :9999).",
      "Uso: busca pares «puerto alto ↔ :22» para ver conexiones SSH entrantes; sesiones UDP largas delatan VPN/Tunnel; ráfagas cortas RST seguidas indican un escaneo de puertos.",
    ],
    example: {
      task: "Ejemplo real — la PC de accounting habla con un servidor extranjero por el puerto 9050:",
      rows: [
        { ip: "192.168.1.25:52100 → 91.219.237.22:9050", detail: "estado ESTABLISHED · bytes 2.1 MB ↑ / 0.4 MB ↓ · servicio desconocido · ⚠️ Torrent/Proxy SOCKS típico" },
      ],
    },
  },
  {
    id: "dns", icon: Globe, title: "DNS / mDNS / LLMNR / NBNS",
    theory: [
      "Qué es: cada consulta y respuesta DNS que circule: dominio, tipo de registro (A, AAAA, CNAME, MX, TXT, PTR), código de resultado y TTL.",
      "El x de los hostnames locales: los tres protocolos de «nombre local» (mDNS .local, LLMNR, NetBIOS Name Service) destapan nombres de máquina sin servidor DNS. Es como tener un mapa de la red sin escanear nada.",
      "RCodes: NOERROR (0) todo bien · NXDOMAIN (3) dominio no existe · SERVFAIL (2) servidor caído. Ráfagas de NXDOMAIN = intentos de exfil-tración DNS o malware pidiendo dominios DGA al azar.",
      "Query que SIEMPRE hay que mirar: TXT hacia dominios raros (exfiltros por DNS), PTR inversas de localhost (rasgos de scanner), resoluciones repetidas al mismo dominio pero con IP cambiante (fast-flux).",
    ],
    example: {
      task: "Ejemplo real — 8 consultas seguidas de una estación:",
      rows: [
        { ip: "api.github.com", detail: "A · NOERROR · resposta 140.82.121.4 · TTL 180" },
        { ip: "nonexistent-1.local", detail: "A · NXDOMAIN ⚠️ · la estación pregunta por equipos que no existen" },
        { ip: "kali-lab.local", detail: "mDNS A · respuesta anunciada: 192.168.42.131 · hostname revelado sin DNS server" },
      ],
    },
  },
  {
    id: "params", icon: Settings2, title: "Parámetros y Keywords",
    theory: [
      "Qué es: dos vistas complementarias del mismo «sabor de contenido». La primera extrae cada parámetro que viaja en URLs (GET), bodies de formularios (POST) o JSON; la segunda vigila 25+ palabras sensibles por TODO el tráfico.",
      "Parámetros: cada key=value se registra con su fuente (URL, body, JSON), origen y destino. Es como un «wireshark -Y http.request” pero sin escribir filtros: ya lo ves directo.",
      "Keywords: basadas en la lista por defecto: password, passwd, pwd, usuario, username, login, admin, secret, token, api_key, authorization, bearer, session, cookie, private key, ssh-rsa, database, mongodb://, mysql://, postgres://… Cada aparición se guarda con su contexto (60 chars antes, 80 después) para que no tengas que adivinar dónde estaba.",
      "Falso positivo honesto: la palabra «host» aparece en cada cabecera HTTP. Por eso el contexto es importante: «Host: grupos» ≠ «host: maindb».",
    ],
    example: {
      task: "Ejemplo real — una sola transacción AJAX destapa:",
      rows: [
        { ip: "session (JSON)", detail: "kind: http-body:json · valor eyJhbGciOi… · de 192.168.42.50 hacia apinube.net — ⚠️ JWT en claro" },
        { ip: "apikey (URL)", detail: "kind: http-url · valor SK-9f3A… · GET /v1/search?...&apikey=SK-9f3A — clave de API en la URL = se queda en logs de terceros" },
        { ip: "password (form)", detail: "kind: http-body · valor S3cr3t123 · POST /login — login clásico en claro" },
      ],
    },
  },
];

function Code({ children }) {
  return <pre className="docs-code">{children}</pre>;
}

export default function DocsPage() {
  const [q, setQ] = useState("");

  return (
    <div>
      <nav className="nav">
        <a href="/" className="nav-logo" style={{ color: "var(--txt)" }}>
          <Terminal size={18} color="var(--accent)" /> Sniff<span className="nex">Nex</span>
          <span style={{ color: "var(--dim)", fontSize: 12, fontWeight: 500 }}> · Documentación</span>
        </a>
        <div className="nav-links">
          <a href="#hosts">Hosts</a>
          <a href="#files">Archivos</a>
          <a href="#credentials">Credenciales</a>
          <a href="#dns">DNS</a>
          <a href="#params">Parámetros</a>
          <a href="/" className="docs-back"><ArrowLeft size={14} /> Volver a la portada</a>
        </div>
      </nav>

      <header className="hero" style={{ padding: "78px max(24px,6vw) 42px" }}>
        <div className="hero-grid" />
        <div className="hero-inner">
          <motion.div className="hero-tagline" {...fadeUp(0)}>
            <Search size={13} /> DOCUMENTACIÓN TÉCNICA · v1.0
          </motion.div>
          <motion.h1 {...fadeUp(0.08)} style={{ fontSize: "clamp(36px, 5.4vw, 62px)" }}>
            Cada sección,<br /><span className="grad">hasta el último byte.</span>
          </motion.h1>
          <motion.p className="sub" {...fadeUp(0.16)}>
            Teoría de por qué funciona cada módulo, cómo lo hace internamente SniffNex, qué esperar y qué NO esperar,
            y ejemplos reales con capturas de como lo intérpreta directamente la interfaz.
          </motion.p>
          <motion.div {...fadeUp(0.24)}>
            <input
              className="docs-search"
              placeholder="Buscar en la documentación…  (p. ej. «TTL», «mDNS», «SHA-256», « FTP»)"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              style={{
                width: "min(560px, 100%)", padding: "14px 20px",
                background: "var(--panel)", border: "1px solid var(--line2)",
                borderRadius: 12, color: "var(--txt)", fontSize: 14, outline: "none",
              }}
            />
          </motion.div>
        </div>
      </header>

      <div className="marquee" style={{ marginBottom: 8 }}>
        <div className="marquee-track">
          {[...Array(2)].map((_, k) => (
            <React.Fragment key={k}>
              {SECTIONS.map((s) => <span key={s.id}>◆ <b>{s.title}</b></span>)}
            </React.Fragment>
          ))}
        </div>
      </div>

      <div className="section" style={{ paddingTop: 30 }}>
        <div className="cards" style={{ marginTop: 8 }}>
          {SECTIONS.map((s, i) => (
            <motion.a key={s.id} href={`#${s.id}`} className="card" {...fadeUp(0.05 * (i % 4))} style={{ display: "block" }}>
              <div className="icon-box"><s.icon size={20} /></div>
              <h3>{s.title}</h3>
              <p>{s.theory[0].slice(0, 130)}…</p>
            </motion.a>
          ))}
        </div>
      </div>

      {SECTIONS.filter((s) => {
        if (!q.trim()) return true;
        const t = (s.title + " " + s.theory.join(" ")).toLowerCase();
        return t.includes(q.toLowerCase());
      }).map((s) => (
        <section key={s.id} id={s.id} className="section" style={{ background: "none" }}>
          <motion.div {...fadeUp()}>
            <div className="section-tag">Sección de la App</div>
            <h2 style={{ fontSize: "clamp(26px, 3.6vw, 38px)", display: "flex", alignItems: "center", gap: 14 }}>
              <span className="icon-box" style={{ width: 44, height: 44, marginBottom: 0 }}><s.icon size={22} /></span>
              {s.title}
            </h2>
          </motion.div>

          {s.theory.map((p, j) => (
            <motion.p key={j} className="docs-para" {...fadeUp(0.05 * j)}>{p}</motion.p>
          ))}

          <motion.div className="docs-example" {...fadeUp(0.12)}>
            <div className="docs-example-tag">▲ Ejemplo what la interfaz te mostraría</div>
            <p style={{ color: "var(--muted)", fontSize: 13.5, margin: "6px 0 14px" }}>{s.example.task}</p>
            <div className="docs-example-rows">
              {s.example.rows.map((r, k) => (
                <div key={k} className="docs-example-row">
                  <div className="mono">{r.ip}</div>
                  <div className="mut">{r.detail}</div>
                </div>
              ))}
            </div>
          </motion.div>
        </section>
      ))}

      <section className="section" style={{ background: "var(--bg2)" }}>
        <motion.div {...fadeUp()}>
          <div className="section-tag">Recetas</div>
          <h2>Casos de uso paso a paso con comandos</h2>
          <p className="lead">Tres flujos reales, de principio a fin, con el comando exacto.</p>
        </motion.div>
        <div className="steps">
          {[
            {
              t: "Auditar qué hace un dispositivo IoT sin tocarlo",
              c: (
                <>
                  <span className="m"># 1) arranca el sniffer en proves promiscuo y filtra por el host</span>{"\n"}
                  sudo ./start-desktop.sh{"\n"}
                  <span className="m"># 2) en UI: iface eth0 · BPF: "host 192.168.1.30" · Iniciar sniffer</span>{"\n"}
                  <span className="m"># 3) usa la cámara 10-15 min como lo harías normalmente</span>{"\n"}
                  <span className="m"># 4) mira:</span>{"\n"}
                  <span className="g">Hosts</span>    → su ficha MAC/vendor/SO/puertos{"\n"}
                  <span className="g">DNS</span>      → a qué servidores llama (¿dominios raros? ⚠️){"\n"}
                  <span className="g">Parámetros</span> → tokens en la URL {"\n"}
                  <span className="g">Credenciales</span> → login admin en claro (⇨ cámara barata típica)
                </>
              ),
            },
            {
              t: "Analizar un PCAP que te pasan de otra máquina",
              c: (
                <>
                  <span className="m"># sin capturar nada: cárgalo directo</span>{"\n"}
                  curl -F <span className="c">"file=@/evidence/casilla-17.pcap"</span> \\
                       http://localhost:8099/api/upload/pcap{"\n"}
                  <span className="m"># …o desde la UI: "Cargar PCAP" arriba a la derecha</span>{"\n"}
                  <span className="m"># luego: Exportar ▾ → PDF para tu informe ; CSV para la mesa de análisis</span>
                </>
              ),
            },
            {
              t: "Verificar qué contraseñas circulan por tu red corporativa",
              c: (
                <>
                  <span className="m"># sniffer sin filtro, durante la ventana de login matinal 08:30-09:00</span>{"\n"}
                  <span className="m"># después abre la sección Credenciales y filtra type=ftp o form/urlencoded</span>{"\n"}
                  <span className="m"># exporta CSV → cuenta cuántos viajaban en claro → instala/ENDSFTPS</span>
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

      <footer>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Terminal size={16} color="var(--accent)" />
          <strong style={{ color: "var(--txt)" }}>SniffNex</strong>
          <span className="mono">v1.0 · GPL-3.0 · docs</span>
        </div>
        <div className="mono">portada · <a href="/">← volver</a></div>
      </footer>
    </div>
  );
}
