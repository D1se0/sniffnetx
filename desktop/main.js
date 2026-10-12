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
    title: "SniffNex — Network Forensics",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadURL(`http://127.0.0.1:${PORT}/`);
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
      const log = fs.readFileSync(path.join(os.tmpdir(), "sniffnex-desktop.log"), "utf8").slice(-2000);
      dialog.showErrorBox(
        "SniffNex no pudo arrancar el backend",
        `¿Tienes scapy/fastapi/uvicorn instalados para:\n${findPython()}\n\nSugerencia:\n  ${findPython()} -m pip install scapy fastapi "uvicorn[standard]"\n\nÚltimas líneas del log:\n\n${log}`
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
