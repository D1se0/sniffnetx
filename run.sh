#!/usr/bin/env bash
# SniffNex launcher portable (Linux)
set -e
cd "$(dirname "$0")"

PY=${PYTHON:-python3}
PORT=${PORT:-8099}

banner() {
  echo -e "\e[36m"
  cat <<'EOF'
   ┌─┐┌─┐┌┐┌┌─┐┬─┐┌─┐┌┐┌
   │  ├─┤│││├┤ ├┬┘├─┤│││   NETWORK FORENSICS
   └─┘┴ ┴┘└┘└─┘┴└─┴ ┴┘└┘   v1.0 · passive · GPL-3.0
EOF
  echo -e "\e[0m"
}

banner

command -v "$PY" >/dev/null || { echo "[!] Python 3 no encontrado"; exit 1; }
"$PY" -c "import scapy, fastapi, uvicorn" 2>/dev/null || {
  echo "[*] Instalando dependencias del backend…"
  $PY -m pip install scapy fastapi "uvicorn[standard]" || \
  $PY -m pip install --break-system-packages scapy fastapi "uvicorn[standard]"
}

if [ ! -f frontend/dist/index.html ]; then
  echo "[*] frontend/dist ausente — compilando UI…"
  command -v npm >/dev/null && (cd frontend && npm install && npm run build) || \
    echo "[!] npm no disponible: la UI no estará embebida (API/WS funcionan igual)"
fi

if [ "$(id -u)" != "0" ]; then
  echo "[i] Sin root: la captura requiere CAP_NET_RAW."
  echo "    → ejecuta  sudo ./run.sh   o otorga:  sudo setcap cap_net_raw,cap_net_admin=eip \$(readlink -f \$(which python3))"
fi

echo "[*] Backend+UI en http://localhost:$PORT"
( sleep 1.2; xdg-open "http://localhost:$PORT" >/dev/null 2>&1 || true ) &
cd backend
exec "$PY" -m uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
