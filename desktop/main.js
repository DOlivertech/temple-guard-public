// Project Temple Guard — Electron desktop shell.
//
// Boots the FastAPI backend and the Next.js frontend as child processes, waits
// for the UI to come up, then loads it in a native window. On quit, both
// child processes are torn down.
const { app, BrowserWindow, shell } = require("electron");
const { spawn } = require("child_process");
const http = require("http");
const path = require("path");
const fs = require("fs");

const ROOT = path.resolve(__dirname, "..");
const BACKEND = path.join(ROOT, "backend");
const FRONTEND = path.join(ROOT, "frontend");
const WEB_URL = "http://localhost:3000";
const API_PORT = 8000;

let procs = [];
let win = null;

function venvBin(name) {
  const win32 = process.platform === "win32";
  const p = path.join(BACKEND, ".venv", win32 ? "Scripts" : "bin", win32 ? `${name}.exe` : name);
  return fs.existsSync(p) ? p : name; // fall back to PATH
}

function startBackend() {
  const uvicorn = venvBin("uvicorn");
  const p = spawn(uvicorn, ["app.main:app", "--port", String(API_PORT)], {
    cwd: BACKEND,
    env: { ...process.env, TG_EXECUTION_MODE: process.env.TG_EXECUTION_MODE || "docker" },
  });
  p.stdout.on("data", (d) => process.stdout.write(`[api] ${d}`));
  p.stderr.on("data", (d) => process.stdout.write(`[api] ${d}`));
  procs.push(p);
}

function startFrontend() {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const p = spawn(npm, ["run", "dev"], { cwd: FRONTEND, env: { ...process.env } });
  p.stdout.on("data", (d) => process.stdout.write(`[web] ${d}`));
  p.stderr.on("data", (d) => process.stdout.write(`[web] ${d}`));
  procs.push(p);
}

function waitForUrl(url, timeoutMs = 60000) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      http.get(url, (res) => { res.destroy(); resolve(); })
        .on("error", () => {
          if (Date.now() - start > timeoutMs) reject(new Error("timeout waiting for UI"));
          else setTimeout(tick, 700);
        });
    };
    tick();
  });
}

function createWindow() {
  win = new BrowserWindow({
    width: 1440,
    height: 920,
    backgroundColor: "#0b1120",
    title: "Project Temple Guard",
    webPreferences: { contextIsolation: true },
  });
  // Open external links in the system browser, keep app links in-app.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (!url.startsWith(WEB_URL)) { shell.openExternal(url); return { action: "deny" }; }
    return { action: "allow" };
  });
  win.loadURL("data:text/html,<body style='background:#0b1120;color:#94a3b8;font-family:sans-serif;display:grid;place-items:center;height:100vh'><div>⛨ Starting Temple Guard…</div></body>");
  waitForUrl(WEB_URL).then(() => win.loadURL(WEB_URL))
    .catch((e) => win.loadURL("data:text/html,<body style='background:#0b1120;color:#f87171;padding:40px;font-family:sans-serif'>Failed to start: " + e.message + "</body>"));
}

app.whenReady().then(() => {
  startBackend();
  startFrontend();
  createWindow();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

function shutdown() {
  procs.forEach((p) => { try { p.kill("SIGTERM"); } catch {} });
  procs = [];
}
app.on("window-all-closed", () => { shutdown(); if (process.platform !== "darwin") app.quit(); });
app.on("before-quit", shutdown);
process.on("exit", shutdown);
