# Temple Guard — Desktop

Electron shell that launches the backend + frontend and opens the dashboard in a
native window.

```bash
# one-time: backend venv + frontend deps must exist
cd ../backend && python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt && ./.venv/bin/python -m app.seed
cd ../frontend && npm install

# run the desktop app
cd ../desktop && npm install && npm start
```

`npm start` boots uvicorn (port 8000) and Next.js (port 3000), waits for the UI,
then loads it. Closing the window stops both processes.

### Packaging (later)
`npm run dist` (electron-builder) produces an installer, but bundling the Python
backend for distribution still needs to be wired up (PyInstaller or a sidecar).
