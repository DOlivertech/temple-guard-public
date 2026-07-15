# Lightweight static-analysis toolbox for Temple Guard app audits.
# Downloads/extracts an installer and inspects it (no execution by default).
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      file binutils curl ca-certificates p7zip-full unzip xxd \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
