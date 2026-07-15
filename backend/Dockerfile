# Backend image — based on the Playwright/Python image so web-evidence capture
# and server-side PDF rendering work out of the box (Chromium is preinstalled).
# The Docker CLI lets the backend spin up scan/tool containers via the mounted
# host Docker socket (docker-out-of-docker).
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY docker ./docker

EXPOSE 8000
# Seed on first boot only (no-op if the DB already has data), then serve.
CMD ["sh", "-c", "python -m app.bootstrap && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
