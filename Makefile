# Temple Guard — task runner.
# Thin wrapper that exposes the project's shell scripts as `make` targets.
# Run `make` (or `make help`) to list everything.

.DEFAULT_GOAL := help
SHELL := /bin/bash
ARGS ?=

.PHONY: help run start up up-d down install install-no-pull backup vpn-sidecar \
        cli-install cli-build

help:  ## list the available targets
	@echo "Temple Guard — make targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[1;36m%-18s\033[0m %s\n", $$1, $$2}'

run:  ## run backend + frontend locally (SQLite, host processes) — ./run.sh
	@./run.sh

start:  ## bring up the full Docker stack in the foreground — ./start.sh
	@./start.sh

up: start  ## alias for `start`

up-d:  ## bring up the Docker stack detached (background) — ./start.sh -d
	@./start.sh -d

down:  ## stop the Docker stack
	@docker compose down

install:  ## install/build everything (pull images, build the Kali toolbox) — ./install.sh
	@./install.sh

install-no-pull:  ## install without pulling/building images — ./install.sh --no-pull
	@./install.sh --no-pull

backup:  ## back up the database / evidence — ./backup.sh
	@./backup.sh

vpn-sidecar:  ## run the VPN sidecar helper (pass ARGS="…") — ./scripts/vpn-sidecar.sh
	@./scripts/vpn-sidecar.sh $(ARGS)

cli-install:  ## install the temple-guard CLI from source (editable, via pipx)
	@pipx install --force --editable cli

cli-build:  ## build the CLI wheel + sdist into cli/dist
	@cd cli && python3 -m build --outdir dist 2>/dev/null || pipx run --spec build python -m build --outdir dist
