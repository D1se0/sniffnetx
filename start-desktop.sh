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

# Electron no arranca como root sin --no-sandbox (crbug.com/638180), y aun con él
# en VM/X11 la ventana se ve NEGRA. Solución fiable: la GUI SIEMPRE como el usuario
# del escritorio — solo el backend (scapy) corre con sudo.
ELECTRON_FLAGS=("--no-sandbox")
if [ "$(id -u)" = "0" ]; then
  export ELECTRON_DISABLE_SECURITY_WARNINGS=1
  # Si sudo lo invocó, dispone de orig UID/GID/HOME que main.js usará para "drop"
  export SUDO_UID="${SUDO_UID:-1000}"
  export SUDO_GID="${SUDO_GID:-1000}"
  export SUDO_HOME="${SUDO_HOME:-/home/kali}"
fi

# ---------- instancia previa? matarla (evita puertos ocupados y doble GUI) ----------
if pgrep -f "electron/dist/electron desktop" > /dev/null 2>&1; then
  echo "[*] Cerrando instancia previa de SniffNex Desktop…"
  pkill -f "electron/dist/electron desktop" 2>/dev/null
  sleep 2
fi

case "$ACTION" in
  build)
    echo "[*] Generando paquetes portables (dir + AppImage)…"
    (cd desktop && npx electron-builder --linux dir AppImage)
    echo "[✓] Paquetes en desktop/release/"
    ;;
  sudo)
    echo "[*] Arrancando SniffNex Desktop con sudo (captura cruda OK)…"
    exec sudo -E env "PATH=$PATH" desktop/node_modules/.bin/electron desktop "${ELECTRON_FLAGS[@]}"
    ;;
  run)
    echo "[*] Arrancando SniffNex Desktop…"
    if [ "$(id -u)" = "0" ]; then
      # root: lanzamos la GUI como tu usuario del escritorio (setpriv).
      # Chromium como root renderiza negro bajo X11 de otro usuario — evitamos
      # el problema de raíz: solo el backend corre con sudo.
      RUID="${SUDO_UID:-$(stat -c %u /home/kali)}"
      RGID="${SUDO_GID:-$(stat -c %g /home/kali)}"
      RHOME="${SUDO_HOME:-/home/kali}"
      echo "[i] Soy root: abro GUI como uid=$RUID ($(logname 2>/dev/null || echo kali)) y backend con sudo"
      if [ -z "$DISPLAY" ]; then export DISPLAY=:0; fi
      # setsid --wait: la GUI adopta una sesión nueva y sobrevive al sudo/terminal
      exec setpriv --reuid="$RUID" --regid="$RGID" --init-groups \
        env HOME="$RHOME" DISPLAY="$DISPLAY" \
        setsid --wait \
        desktop/node_modules/.bin/electron desktop "${ELECTRON_FLAGS[@]}"
    else
      echo "[i] Sin root. Captura en iface real ⇒ sudo ./start-desktop.sh"
      exec desktop/node_modules/.bin/electron desktop "${ELECTRON_FLAGS[@]}"
    fi
    ;;
  *)
    echo "uso: ./start-desktop.sh [run|sudo|build]"; exit 1
    ;;
esac
