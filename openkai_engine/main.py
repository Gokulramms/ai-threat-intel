"""OpenKai Enterprise SOC Intelligence Platform - Main Application Entrypoint."""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from openkai_engine.database import init_db, AsyncSessionLocal
from openkai_engine.services.threat_intel_service import threat_intel_service
from openkai_engine.services.asset_service import asset_service
from openkai_engine.services.scheduler_service import scheduler_service
from openkai_engine.api.routes_system import router as system_router
from openkai_engine.api.routes_threat_intel import router as ti_router
from openkai_engine.api.routes_assets import router as assets_router
from openkai_engine.api.routes_investigations import router as inv_router
from openkai_engine.api.routes_reports import router as reports_router
from openkai_engine.api.routes_connectors import router as connectors_router
from openkai_engine.api.routes_audit import router as audit_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup sequence
    await init_db()
    await threat_intel_service.initialize_feeds_table()

    scheduler_service.start()
    yield
    # Teardown
    scheduler_service.stop()

app = FastAPI(
    title="OpenKai Enterprise Security Intelligence Platform",
    description="Enterprise AI-Powered Threat Intelligence, EDR & SIEM Investigation Platform",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(system_router)
app.include_router(ti_router)
app.include_router(assets_router)
app.include_router(inv_router)
app.include_router(reports_router)
app.include_router(connectors_router)
app.include_router(audit_router)

# Mount Static UI directory
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(os.path.join(static_dir, "index.html"))
