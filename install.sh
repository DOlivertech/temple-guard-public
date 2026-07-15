#!/usr/bin/env bash
#
# Project Temple Guard — prerequisite installer & setup.
#
# Installs everything needed to run Temple Guard locally and sets up both apps.
# Idempotent: safe to re-run. Supports macOS (Homebrew) and Debian/Ubuntu (apt).
#
#   ./install.sh            # install prereqs + set up backend & frontend
#   ./install.sh --no-pull  # skip pulling Docker tool images (faster first run)
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PULL_IMAGES=1
[ "${1:-}" = "--no-pull" ] && PULL_IMAGES=0

say()  { printf "\033[1;36m⛨  %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32m✓ %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m! %s\033[0m\n" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

OS="$(uname -s)"

# ── Package manager bootstrap ───────────────────────────────────────────────
install_macos() {
  if ! have brew; then
    say "Installing Homebrew…"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || true)"
  fi
  ok "Homebrew present"

  have python3 || { say "Installing Python…"; brew install python; }
  have node    || { say "Installing Node…";   brew install node; }
  ok "Python $(python3 --version 2>&1 | awk '{print $2}') · Node $(node --version 2>/dev/null)"

  if ! have docker; then
    say "Installing Docker Desktop (cask)…"
    brew install --cask docker || warn "Docker cask install failed — install Docker Desktop manually."
  fi
  ok "Docker CLI present"
}

install_linux() {
  say "Installing prereqs via apt…"
  sudo apt-get update -y
  sudo apt-get install -y python3 python3-venv python3-pip curl
  if ! have node; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
  fi
  if ! have docker; then
    say "Installing Docker Engine…"
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$USER" || true
    warn "You may need to log out/in for docker group membership to apply."
  fi
  ok "Python $(python3 --version 2>&1 | awk '{print $2}') · Node $(node --version 2>/dev/null) · Docker"
}

case "$OS" in
  Darwin) install_macos ;;
  Linux)  install_linux ;;
  *) warn "Unsupported OS '$OS'. Install Python 3.10+, Node 18+, and Docker manually." ;;
esac

# ── Make sure the Docker daemon is up (best effort) ─────────────────────────
if have docker && ! docker info >/dev/null 2>&1; then
  if [ "$OS" = "Darwin" ]; then
    say "Starting Docker Desktop…"; open -a Docker || true
    printf "   waiting for Docker"
    for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; printf "."; sleep 2; done; echo
  fi
fi
docker info >/dev/null 2>&1 && ok "Docker daemon running" || warn "Docker daemon not running yet — start Docker Desktop before real scans."

# ── Backend setup ───────────────────────────────────────────────────────────
say "Setting up backend (Python venv)…"
cd "$ROOT/backend"
[ -d .venv ] || python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt
say "Installing Playwright browser (for web evidence capture)…"
python -m playwright install chromium
[ -f temple_guard.db ] || python -m app.seed
ok "Backend ready"
deactivate

# ── Frontend setup ──────────────────────────────────────────────────────────
say "Setting up frontend (npm)…"
cd "$ROOT/frontend"
npm install --silent
ok "Frontend ready"

# ── Build the Temple Guard Kali toolbox image ───────────────────────────────
# One image runs every containerized scan (nmap, nikto, nuclei, sqlmap,
# testssl) and boots the Kali consoles. Replaces the old per-tool images.
if docker info >/dev/null 2>&1; then
  say "Building Temple Guard Kali toolbox image (one image for all scans + consoles)…"
  say "  This pulls Kali + installs the toolset + bakes Nuclei templates — a few minutes the first time."
  docker build -t templeguard/kali:latest "$ROOT/backend/docker/kali" \
    || warn "kali image build failed (real scans won't run until it's built)"
  ok "Kali toolbox image ready"
  say "Building Temple Guard Metasploit image (separate — used for detection-only vuln scans)…"
  docker build -t templeguard/metasploit:latest "$ROOT/backend/docker/metasploit" \
    || warn "metasploit image build failed (the Metasploit vuln scan won't run until it's built)"
  ok "Metasploit image ready"
else
  warn "Docker not running — skipping Kali image build. Run ./install.sh again once Docker is up."
fi

cat <<EOF

$(say "Setup complete.")
  Start everything:   ./run.sh
  Or separately:
    backend:   cd backend && source .venv/bin/activate && uvicorn app.main:app --port 8000
    frontend:  cd frontend && npm run dev
  Then open http://localhost:3000

EOF
