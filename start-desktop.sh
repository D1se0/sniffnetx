#!/usr/bin/env bash
# SniffNex Desktop — launcher portable
# Uso normal:       ./start-desktop.sh
# Con privilegios:  sudo ./start-desktop.sh     (permite captura en ifaces reales)
set -e
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
ACTION=${1:-run}   # run | sudo | build

banner() {
  echo -e "\e[36m"
  cat <<'EOF'
   ┌─┐┌─┐┌┐┌┌─┐┬─┐┌─┐┌┐┌
   │  ├─┤│││├┤ ├┬┘├─┤│││   DESKTOP
   └─┘┴ ┴┘└┘└─┘┴└─┴ ┴┘└┘   v1.0 · portable
EOF
  echo -e "\e[0m"
}
banner

# ---------- venv del repo (no toca el sistema) ----------
if [ ! -x backend/venv/bin/python3 ]; then
  echo "[*] Creando venv en backend/venv (portable, no toca el sistema)…"
  $PY -m venv backend/venv
  backend/venv/bin/pip -q install --upgrade pip
  backend/venv/bin/pip -q install -r backend/requirements.txt
else
  backend/venv/bin/python3 -c "import scapy, fastapi, uvicorn, multipart" 2>/dev/null || {
    echo "[*] Reinstalando dependencias del venv…"
    backend/venv/bin/pip -q install -r backend/requirements.txt
  }
fi

# ---------- electron ----------
if [ ! -d desktop/node_modules ]; then
  echo "[*] Instalando Electron (una vez)…"
  (cd desktop && npm install --silent)
fi

# ---------- UI compilada ----------
if [ ! -f frontend/dist/index.html ]; then
  echo "[*] Compilando UI…"
  (cd frontend && npm install --silent && npm run build)
fi

case "$ACTION" in
  build)
    echo "[*] Generando paquetes portables (dir + AppImage)…"
    (cd desktop && npx electron-builder --linux dir AppImage)
    echo "[✓] Paquetes en desktop/release/"
    ;;
  sudo)
    echo "[*] Arrancando SniffNex Desktop con sudo (captura cruda OK)…"
    exec sudo -E env "PATH=$PATH" desktop/node_modules/.bin/electron desktop --no-sandbox
    ;;
  run)
    echo "[*] Arrancando SniffNex Desktop…"
    if [ "$(id -u)" != "0" ]; then
      echo "[i] Sin root. Captura en iface real ⇒ sudo ./start-desktop.sh"
    fi
    exec desktop/node_modules/.bin/electron desktop
    ;;
  *)
    echo "uso: ./start-desktop.sh [run|sudo|build]"; exit 1
    ;;
esac
