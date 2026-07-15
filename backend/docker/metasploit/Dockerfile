# Temple Guard Metasploit image — layered ON TOP of the shared Kali toolbox so it
# reuses every templeguard/kali layer (base + all tools) already on the host and
# adds ONLY the Metasploit packages. Lower footprint than a second independent base,
# and this image also has the full Kali toolset. Build templeguard/kali first.
# Used ONLY for detection-focused vulnerability identification (auxiliary/scanner +
# check modules) via headless msfconsole — no exploitation is wired into the platform.
FROM templeguard/kali:latest

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
