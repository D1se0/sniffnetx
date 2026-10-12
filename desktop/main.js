// SniffNex Desktop — Electron main process
// Lanza el backend (uvicorn) como hijo, espera a que responda y abre la UI real.
const { app, BrowserWindow, shell, dialog } = require("electron");
const { spawn } = require("child_process");
const path = require("path");
const http = require("http");
const os = require("os");
const fs = require("fs");

const isPackaged = app.isPackaged;
const PORT = process.env.SNIFFNEX_PORT || 8099;
let backendProc = null;
let win = null;

// Al ejecutar como root, asegurar un HOME válido (Electron lo exige para userData):
// si sudo no propagó HOME, Electron escribiría en /undefined o /nonexistent → crash negro.
if ((typeof process.getuid === "function" && process.getuid() === 0) &&
    (!process.env.HOME || !fs.existsSync(process.env.HOME))) {
  process.env.HOME = "/root";
  try { fs.mkdirSync("/root/.config", { recursive: true }); } catch {}
}
app.setPath("userData", path.join(process.env.HOME || os.tmpdir(), ".config", "sniffnex-desktop"));

function resPath(...p) {
  return isPackaged
    ? path.join(process.resourcesPath, ...p)
    : path.join(__dirname, "..", ...p);
}

function findPython() {
  // 1) venv embebido junto a la app
  const venvPy = resPath("backend", "venv", "bin", "python3");
  if (fs.existsSync(venvPy)) return venvPy;
  // 2) sistema
  for (const c of [process.env.SNIFFNEX_PY, "/usr/bin/python3", "/usr/local/bin/python3"])
    if (c && fs.existsSync(c)) return c;
  return "python3";
}

function startBackend() {
  const py = findPython();
  const backendDir = resPath("backend");
  const args = ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", String(PORT)];
  const opts = { cwd: backendDir, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, PYTHONUNBUFFERED: "1" } };

  // En empaquetado, exec usa python del venv embebido si existe
  backendProc = spawn(py, args, opts);

  backendProc.stderr.on("data", (d) => {
    fs.appendFileSync(path.join(os.tmpdir(), "sniffnex-desktop.log"), String(d));
  });
  backendProc.on("error", (e) => {
    fs.appendFileSync(path.join(os.tmpdir(), "sniffnex-desktop.log"), "spawn error: " + e.message + "\n");
  });
  backendProc.on("exit", (code) => {
    fs.appendFileSync(path.join(os.tmpdir(), "sniffnex-desktop.log"), `backend exited ${code}\n`);
  });
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
  win = new BrowserWindow({
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
    },
  });

  // Log de errores JS del renderer al fichero en vez de ventanas emergentes
  const logF = () => path.join(os.tmpdir(), "sniffnex-desktop.log");
  win.webContents.on("did-fail-load", (_e, code, desc, url) => {
    fs.appendFileSync(logF(), `did-fail-load(${code}) ${desc} ${url}\n`);
    // Reintenta una vez pasado un momento — el backend recién spawneado a veces pierde la 1ª
    setTimeout(() => { try { win.loadURL(`http://127.0.0.1:${PORT}/`); } catch {} }, 1200);
  });
  win.webContents.on("console-message", (_e, level, message, line, src) => {
    fs.appendFileSync(logF(), `[renderer-${level}] ${message} ${src}:${line}\n`);
  });
  win.webContents.on("render-process-gone", (_e, details) => {
    fs.appendFileSync(logF(), `render-process-gone: ${details.reason}\n`);
  });
  // No popups de diálogo para JS errors — silencio y log
  win.webContents.on("unresponsive", () => { /* no-op */ });

  win.loadURL(`http://127.0.0.1:${PORT}/`);
  win.once("ready-to-show", () => { win.show(); });
  // fallback: si a los 10s aún no se mostró, fuerza show (evita ventana "negra")
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
      let log = "";
      try { log = fs.readFileSync(path.join(os.tmpdir(), "sniffnex-desktop.log"), "utf8").slice(-1600); } catch {}
      dialog.showErrorBox(
        "SniffNex no pudo arrancar el backend",
        `Falta algo en el venv. Ejecuta:\n  ${findPython()} -m pip install -r backend/requirements.txt\n\nÚltimas líneas del log:\n${log}`
      );
      app.quit();
      return;
    }
    createWindow();
  });
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0 && win === null) { /* noop */ } });
});

app.on("window-all-closed", () => {
  if (backendProc) { try { backendProc.kill("SIGTERM"); } catch {} }
  setTimeout(() => { if (backendProc) { try { backendProc.kill("SIGKILL"); } catch {} } }, 1500);
  app.quit();
});
