# SniffNex 🦈

<div align="center">

**Network Forensics Toolkit — passive sniffer tipo NetworkMiner, portable para Linux**

`Python 3.11+` · `FastAPI` · `Scapy` · `React` · `PDF exporter` · `GPL-3.0`

[Website y documentación](https://d1se0.github.io/sniffnetx/) · [Descargar](https://github.com/D1se0/sniffnetx/archive/refs/heads/main.zip)

</div>

---

## ¿Qué es?

SniffNex escucha pasivamente la red que tú elijas y reconstituye, como NetworkMiner pero en vivo y con UI moderna:

| Sección | Qué obtienes |
|---|---|
| **Hosts** | IPs, MAC, fabricante NIC (OUI), MAC aleatorizada, hostname, SO estimado (TTL+UA), TTL mín, puertos TCP observados, pkts enviados/recibidos, mDNS/NBNS, DNS queries, keyword hits |
| **Archivos** | Ficheros reconstruidos del tráfico HTTP: nombre, MIME, tamaño, SHA-256, origen → destino, descarga del original |
| **Imágenes** | Previsualización en miniatura y lightbox de PNG/JPEG/GIF/WebP reconstruidas |
| **Mensajes** | Peticiones/respuestas HTTP completas, metadatos SMTP, cuerpos y cabeceras expandibles |
| **Credenciales** | Formularios URL-encoded, USER/PASS (FTP y otros), Authorization Basic, cookies, con evidencia textual |
| **Sesiones** | Flujos TCP/UDP con estado (SYN→ESTABLISHED→FIN/RST), servicio, bytes y timeline |
| **DNS** | Consultas/respuestas con registros, rcodes y TTL; mDNS/LLMNR delatan hostnames locales |
| **Parámetros** | GET/POST/JSON parámetro a parámetro + radar de keywords sensibles con contexto |
| **Paquetes** | Explorador del buffer en vivo para el resumen tipo `tcpdump -r` |

Todo **filtrable, ordenable y expandible**, con gráficas, animaciones y exportaciones:
**PCAP** (crudo para Wireshark), **CSV** por sección, **JSON** completo y **informe PDF** paginado con todas las tablas — ideal para adjuntar a tu auditoría.

## Captura de pantalla

```
┌─────────────────────────────────────────────────────────────────┐
│  ⌁ SniffNex  ● LIVE · eth0   [ iface ▾ ] [ bpf ] [■ Detener]    │
├──────────┬──────────────────────────────────────────────────────┤
│ Overview │  Paquetes: 1.204 · Hosts: 6 · Creds: 2 · Files: 3    │
│ Hosts    │  ┌────────┐  ┌──────────────────────────────────┐    │
│ Sesiones │  │ donut  │  │ hosts más activos (barras)       │    │
│ Archivos │  └────────┘  └──────────────────────────────────┘    │
│ ...      │  ▸ 192.168.5.1  B8:27:EB  RaspberryPi  TTL 64        │
└──────────┴──────────────────────────────────────────────────────┘
```

## Instalación (Linux)

```bash
git clone https://github.com/D1se0/sniffnetx.git
cd sniffnetx/backend
pip install scapy fastapi "uvicorn[standard]" python-multipart reportlab
cd ..
sudo ./run.sh          # arranca y abre http://localhost:8099
```

## App de escritorio (Electron, portable)

La misma aplicación, en ventana nativa, sin navegador:

```bash
sudo ./start-desktop.sh          # app de escritorio (crea venv portable en backend/venv)
./start-desktop.sh build         # genera paquete portable + AppImage en desktop/release/
```

El launcher crea todas las dependencias en un **venv propio** (`backend/venv`, no toca el sistema),
arranca el backend como hijo de la app y abre la ventana. Al cerrar la ventana se detiene todo limpiamente.

La interfaz React ya viene **compilada** en `frontend/dist`; si quieres regenerarla:

```bash
cd frontend && npm install && npm run build
```

### Permisos

Capturar tráfico crudo exige privilegios. Opciones:

1. **sudo** (recomendado en Kali): `sudo ./run.sh`
2. **Capacidades** sin root: `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`
3. Docker: `docker run --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW …`

## Uso

1. Elige el **adaptador** (eth0, wlan0, docker0…) y, si quieres, un **filtro BPF** (`tcp port 80`, `net 10.0.0.0/8…`).
2. **Iniciar sniffer** — el indicador pasa a `LIVE` y las estadísticas suben en vivo (WebSocket).
3. Navega por Hosts → expande una IP → MAC, vendor, SO, puertos, mDNS, DNS y keywords de ese host.
4. **Exportar ▾** → PCAP / CSV / JSON / **PDF** (informe forense paginado).
5. También puedes **cargar un PCAP** offline vía API y analizarlo sin capturar:

```bash
curl -F "file=@grabacion.pcap" http://localhost:8099/api/upload/pcap
```

## Arquitectura

```
┌────────────────────┐   WebSocket batches   ┌──────────────────┐
│  CaptureEngine     │ ────────────────────▶ │  UI React (Vite) │
│  scapy sniff()     │   REST /api/data      │  framer-motion   │
│  BPF · promisc     │   /api/export/*       │  recharts        │
└─────────┬──────────┘                       └──────────────────┘
          │ packets
          ▼
┌────────────────────┐
│  TrafficAnalyzer   │  hosts · sessions · HTTP files · creds
│  (puro Python)     │  DNS/mDNS/LLMNR · params · keywords
└────────────────────┘
```

- `backend/app/analysis.py` — todo el análisis (independiente de la captura, reutilizable con PCAP).
- `backend/app/capture.py` — hilo de captura con BPF, buffer circular y export PCAP.
- `backend/app/main.py` — API REST+WS y el generador **PDF sin dependencias externas**.
- `website/` — la página de GitHub Pages (desplegada con Actions automáticamente).

## Seguridad / ética

SniffNex es una herramienta **pasiva** de análisis defensivo: no escanea, no envía paquetes y no modifica tráfico.
Úsala exclusivamente en redes propias o con autorización explícita. Interceptación de comunicaciones ajenas es un delito en la mayoría de jurisdicciones.

## Licencia

GPL-3.0 — [D1se0](https://github.com/D1se0)
