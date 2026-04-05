"""Secure Digital Voting System — web UI + API."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.api_routes import router as api_router
from src.bootstrap import ensure_bootstrap
from src.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("voting")

BASE_DIR = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "uploads").mkdir(parents=True, exist_ok=True)
    ensure_bootstrap(
        settings.db_file(),
        settings.admin_password,
        settings.election_starts_at,
        settings.election_ends_at,
    )
    logger.info("Application started; database at %s", settings.db_file())
    yield


app = FastAPI(title="Secure Digital Voting System", lifespan=lifespan)

app.include_router(api_router, prefix="/api")

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
_upload_root = settings.data_dir / "uploads"
_upload_root.mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(_upload_root)), name="uploads")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request,
        "app.html",
        {"app_name": "SecureVote"},
    )


@app.get("/health")
def health():
    return {"status": "ok"}
