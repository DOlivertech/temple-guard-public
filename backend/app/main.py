"""Temple Guard FastAPI application entrypoint."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .api.routes import router
from .config import settings
from .database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")

# Serve Playwright-captured evidence screenshots.
# NB: mounted at /evidence-img (not /evidence) so the frontend's /evidence/* page
# routes don't collide with the image-proxy rewrite.
_evidence_dir = os.path.join(os.path.dirname(__file__), "..", "evidence_out")
os.makedirs(_evidence_dir, exist_ok=True)
app.mount("/evidence-img", StaticFiles(directory=_evidence_dir), name="evidence-img")


@app.get("/")
def root():
    return {"app": settings.app_name, "docs": "/docs", "api": "/api"}
