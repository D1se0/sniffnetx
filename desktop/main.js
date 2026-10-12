// SniffNex Desktop — Electron main process
// Lanza el backend (uvicorn) como hijo, espera a que responda y abre la UI real.
//
// FUNDAMENTAL: la ventana (GUI) SIEMPRE corre como el usuario del escritorio.
// Solo el backend (scapy) necesita root. Como root el Chromium de Electron
// renderiza negro / crashea por arriba de X11 de otro usuario (mismo síntoma
// que NetworkMiner GUI as root: negro). Por eso:
//   - si Electron arrancó como root → muere y re-exec como usuario del SUDO_UID
//     (--no-sandbox funciona pero en VM X11 igual se ve negro);
//   - el BACKEND se lanza aparte con `sudo -n` solo para capturar.
const { app, BrowserWindow, shell, dialog } = require("electron");
const { spawn, execSync } = require("child_process");
const path = require("path");
const http = require("http");
const os = require("os");
const fs = require("fs");

app.disableHardwareAcceleration();

// ───────────────── нами root-drop: se re-ejecuta como usuario normal ──────────
function dropToDesktopUser() {
  if (typeof process.getuid !== "function" || process.getuid() !== 0) return; // no root: seguir
  const SUDO_UID = parseInt(process.env.SUDO_UID || "", 10);
  const SUDO_GID = parseInt(process.env.SUDO_GID || "", 10);
  const HOME = process.env.SUDO_HOME || "/home/kali";
  if (!Number.isFinite(SUDO_UID)) {
    dialog.showErrorBox(
      "SniffNex Desktop",
      "Ha arrancado el app como root y no hay usuario de escritorio (SUDO_UID).\n" +
        "Lanza de nuevo desde tu sesión con:\n  sudo ./start-desktop.sh"
    );
    app.exit(1);
    return;
  }
  // re-exec como usuario del escritorio: mantiene DISPLAY, cambia HOME/UID
  const argv = process.argv.slice(1).map((a) => JSON.stringify(a)).join(" ");
  const cmd =
    `env DISPLAY=${process.env.DISPLAY || ":0"} HOME=${HOME} ` +
    `setpriv --reuid=${SUDO_UID} --regid=${SUDO_GID} --init-groups ` +
    `${process.execPath} ${argv}`;
  fs.appendFileSync(path.join(os.tmpdir(), "sniffnex-desktop.log"),
    `[drop] root → uid=${SUDO_UID} (${cmd.replace(process.execPath, "electron bin")} )\n`);
  try {
    execSync(cmd, { stdio: "inherit", env: { ...process.env, HOME, DISPLAY: process.env.DISPLAY || ":0" } });
  } catch (e) {
    fs.appendFileSync(path.join(os.tmpdir(), "sniffnex-desktop.log"), `[drop] exec fallo: ${e.message}\n`);
  }
  app.exit(0);
}

// (drop lo hace el launcher vía setpriv — ver start-desktop.sh)

const isPackaged = app.isPackaged;
const PORT = process.env.SNIFFNEX_PORT || 8099;
let backendProc = null;
let win = null;

function logF() { return path.join(os.tmpdir(), "sniffnex-desktop.log"); }
function logLine(s) { try { fs.appendFileSync(logF(), s + "\n"); } catch {} }

function resPath(...p) {
  return isPackaged
    ? path.join(process.resourcesPath, ...p)
    : path.join(__dirname, "..", ...p);
}

function findPython() {
  const venvPy = resPath("backend", "venv", "bin", "python3");
  if (fs.existsSync(venvPy)) return venvPy;
  for (const c of [process.env.SNIFFNEX_PY, "/usr/bin/python3", "/usr/local/bin/python3"])
    if (c && fs.existsSync(c)) return c;
  return "python3";
}

// ───────────────────── backend: SIEMPRE con sudo si hace falta ───────────────
// en vivo: para capturar en eth0/wlan0 hace falta root; en lo y upload PCAP no.
// Arranca con `sudo -n` si no soy root y el binario lo permite (Kali: passwordless).
function startBackend() {
  logLine(`[backend] findPython → ${findPython()}`);
  const backendDir = resPath("backend");
  const args = ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", String(PORT)];

  const spawnFn = (cmdBase, extraEnv = {}) => {
    logLine(`[backend] ${cmdBase.join(" ")} cwd=${backendDir}`);
    backendProc = spawn(cmdBase[0], cmdBase.slice(1), {
      cwd: backendDir,
      stdio: ["ignore", "ignore", "pipe"],
      env: { ...process.env, PYTHONUNBUFFERED: "1", DISPLAY: process.env.DISPLAY || "", ...extraEnv },
    });
    backendProc.stderr.on("data", (d) => logLine(String(d)));
    backendProc.on("error", (e) => logLine("[backend] spawn error: " + e.message));
    backendProc.on("exit", (code) => logLine(`[backend] exited ${code}`));
  };

  if (typeof process.getuid === "function" && process.getuid() === 0) {
    spawnFn(["python3", ...args]);  // ya root: directo
  } else {
    // usuario normal: probar sudo -n (sin password). Kali tiene NOPASSWD.
    try {
      execSync(["sudo", "-n", "-v"].join(" "), { stdio: "ignore" });
      spawnFn(["sudo", "-n", "-E", findPython(), ...args]);
      logLine("[backend] spawned con sudo -n");
    } catch {
      spawnFn([findPython(), ...args]);
      logLine("[backend] spawned sin sudo (captura en iface real requerirá setcap)");
    }
  }
}

function waitForBackend(cb, tries = 60) {
  const ping = (n) => {
    if (n <= 0) return cb(new Error("backend no respondió"));
    const req = http.get(`http://127.0.0.1:${PORT}/api/health`, (r) => {
      r.resume();
      r.statusCode === 200 ? cb(null) : setTimeout(() => ping(n - 1), 500);
    });
    req.on("error", () => setTimeout(() => ping(n - 1), 500));
  };
  ping(tries);
}

function createWindow() {
  const win = (win = new BrowserWindow({
    width: 1560,
    height: 920,
    minWidth: 1080,
    minHeight: 680,
    backgroundColor: "#07090e",
    autoHideMenuBar: true,
    show: false,
    title: "SniffNex — Network Forensics",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  }));

  win.webContents.on("did-fail-load", (_e, code, desc, url) => {
    logLine(`did-fail-load(${code}) ${desc} ${url}`);
    setTimeout(() => { try { win.loadURL(`http://127.0.0.1:${PORT}/`); } catch {} }, 1500);
  });
  win.webContents.on("console-message", (_e, level, message, line, src) => {
    logLine(`[renderer-${level}] ${message} ${src}:${line}`);
  });
  win.webContents.on("render-process-gone", (_e, details) => logLine(`render-process-gone: ${details.reason}`));

  win.loadURL(`http://127.0.0.1:${PORT}/`);
  win.once("ready-to-show", () => { try { win.show(); } catch {} });
  setTimeout(() => { try { if (win && !win.isVisible()) win.show(); } catch {} }, 10000);

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith(`http://127.0.0.1:${PORT}`)) return { action: "allow" };
    shell.openExternal(url);
    return { action: "deny" };
  });
  win.on("closed", () => { win = null; });
}

app.whenReady().then(() => {
  startBackend();
  waitForBackend((err) => {
    if (err) {
      dialog.showErrorBox(
        "SniffNex no pudo arrancar el backend",
        `Falta algo en el venv. Ejecuta:\n  ${findPython()} -m pip install -r backend/requirements.txt\n\nLog:\n${fs.readFileSync(logF(), "utf8").slice(-1200)}`
      );
      app.quit();
      return;
    }
    createWindow();
  });
  app.on("activate", () => {});
});

app.on("window-all-closed", () => {
  if (backendProc) { try { backendProc.kill("SIGTERM"); } catch {} }
  setTimeout(() => { try { backendProc && backendProc.kill("SIGKILL"); } catch {} }, 1500);
  app.quit();
});
