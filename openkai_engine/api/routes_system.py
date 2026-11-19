"""System Health, Metrics, and Configuration API Endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from openkai_engine.config import settings
from openkai_engine.database import AsyncSessionLocal
from openkai_engine.models.threat_intel import ThreatIndicator, CVERecord, ThreatFeed
from openkai_engine.models.assets import Device, Application
from openkai_engine.models.investigations import Investigation
from openkai_engine.connectors.crowdstrike import crowdstrike_connector
from openkai_engine.connectors.elastic import elastic_siem_connector
from openkai_engine.services.scheduler_service import scheduler_service

router = APIRouter(prefix="/api/system", tags=["System"])

@router.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "platform": "OpenKai Enterprise SOC Intelligence",
        "version": "1.0.0"
    }

@router.get("/config")
async def get_system_config():
    return settings.get_sanitized_summary()

@router.get("/metrics")
async def get_dashboard_kpis():
    """Real-time production KPIs queried directly from application database."""
    async with AsyncSessionLocal() as session:
        total_ti = (await session.scalar(select(func.count(ThreatIndicator.id)))) or 0
        total_cves = (await session.scalar(select(func.count(CVERecord.id)))) or 0
        total_kev = (await session.scalar(select(func.count(CVERecord.id)).where(CVERecord.is_kev == True))) or 0
        total_devices = (await session.scalar(select(func.count(Device.id)))) or 0
        total_apps = (await session.scalar(select(func.count(Application.id)))) or 0
        total_invs = (await session.scalar(select(func.count(Investigation.id)))) or 0
        critical_incidents = (await session.scalar(
            select(func.count(Investigation.id)).where(Investigation.severity == "critical")
        )) or 0

        # Feed statuses
        feeds = (await session.execute(select(ThreatFeed))).scalars().all()
        feed_statuses = [
            {"id": f.id, "name": f.name, "status": f.status, "records": f.records_count}
            for f in feeds
        ]

    # Quick connector health check
    cs_status = "connected" if crowdstrike_connector.is_configured else "unconfigured"
    elastic_status = "connected" if elastic_siem_connector.is_configured else "unconfigured"

    return {
        "kpis": {
            "total_threat_records": total_ti + total_cves,
            "total_indicators": total_ti,
            "total_cves": total_cves,
            "known_exploited_vulnerabilities": total_kev,
            "total_enterprise_devices": total_devices,
            "total_applications": total_apps,
            "active_investigations": total_invs,
            "critical_soc_incidents": critical_incidents
        },
        "ai_engine": {
            "provider": settings.LLM_PROVIDER.upper(),
            "model": settings.GEMINI_MODEL if settings.LLM_PROVIDER == "gemini" else settings.OLLAMA_MODEL,
            "configured": bool(settings.GEMINI_API_KEY) if settings.LLM_PROVIDER == "gemini" else True
        },
        "connectors": {
            "crowdstrike": cs_status,
            "elastic_siem": elastic_status
        },
        "feeds": feed_statuses,
        "scheduler": scheduler_service.get_status()
    }
