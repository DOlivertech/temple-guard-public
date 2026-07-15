# Temple Guard Kali toolbox — one image for all containerized scans, and the
# image the Kali consoles boot. Authentic CEH toolset in a single container.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      # scanning / enumeration
      nmap nikto whatweb dnsutils \
      # vulnerability analysis
      nuclei \
      # SQL injection
      sqlmap \
      # TLS / crypto
      testssl.sh \
      # content discovery + wordlists
      gobuster ffuf dirb wordlists \
      # recon / enumeration / web / tls (Full-Recon + WordPress playbooks)
      subfinder wpscan enum4linux-ng sslyze wafw00f \
      # OSINT / HUMINT exposure (recon-ng framework, SpiderFoot, theHarvester)
      recon-ng spiderfoot theharvester \
      # app-artifact static analysis helpers
      file binutils p7zip-full unzip xxd \
      # base
      curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# PhoneInfoga (phone-number OSINT) — not packaged in apt; install the release
# binary for the build arch.
RUN arch="$(dpkg --print-architecture)"; case "$arch" in amd64) a=x86_64;; arm64) a=arm64;; *) a="$arch";; esac; \
    curl -fsSL "https://github.com/sundowndev/phoneinfoga/releases/download/v2.11.0/phoneinfoga_Linux_${a}.tar.gz" -o /tmp/pi.tgz \
    && tar -xzf /tmp/pi.tgz -C /usr/local/bin phoneinfoga \
    && chmod +x /usr/local/bin/phoneinfoga && rm /tmp/pi.tgz

# Bake Nuclei templates into the image so ephemeral scan containers run offline
# and fast (the kali package ships only the engine). Cloned to the default
# templates dir nuclei reads (~/.local/nuclei-templates).
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates \
      /root/.local/nuclei-templates \
    && rm -rf /root/.local/nuclei-templates/.git

# VPN clients — let this image double as a VPN sidecar (scripts/vpn-sidecar.sh) so
# scan containers can route into a client's private network. Covers OpenVPN,
# WireGuard (incl. Proton/Mullvad configs; wireguard-go is the userspace fallback),
# and Tailscale (exit-node routes ALL traffic through a node you pick). Trailing
# layer so adding it doesn't rebuild the whole toolset.
RUN apt-get update && apt-get install -y --no-install-recommends \
      openvpn wireguard-tools wireguard-go openresolv tailscale \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
