"""ASGI application exposing ShadowTrap's collection intelligence."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from fastapi.staticfiles import StaticFiles

from api.routes import router
from core.database import initialize_database
from core.settings import get_settings


# Initialize database
initialize_database()


# Create FastAPI application

@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


settings = get_settings()
app = FastAPI(
    title="ShadowTrap API",
    description="Honeypot attack intelligence API. Captured credentials are redacted by default.",
    version="1.1.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["X-API-Key", "Content-Type"],
)


# -------------------------
# CORS
# -------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------------
# Routes
# -------------------------

app.include_router(router)


# -------------------------
# Root
# -------------------------

@app.get("/")
def root():
    return {
        "service": "ShadowTrap API",
        "version": "1.0.0",
        "status": "running",
    }
app.include_router(router)


@app.get("/", tags=["health"])
def root() -> dict[str, str]:
    return {"service": "ShadowTrap API", "version": "1.1.0", "status": "running", "dashboard": "/dashboard/"}


dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"
app.mount("/dashboard", StaticFiles(directory=dashboard_dir, html=True), name="dashboard")
