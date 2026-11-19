"""Threat Intelligence API Routes."""

from fastapi import APIRouter, Query, HTTPException
from typing import Optional, List
from sqlalchemy import select, desc
from openkai_engine.database import AsyncSessionLocal
from openkai_engine.models.threat_intel import ThreatIndicator, CVERecord, SecurityAdvisory, ThreatFeed
from openkai_engine.services.threat_intel_service import threat_intel_service

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])

@router.get("/feeds")
async def list_threat_feeds():
    async with AsyncSessionLocal() as session:
        feeds = (await session.execute(select(ThreatFeed))).scalars().all()
        return [
            {
                "id": f.id,
                "name": f.name,
                "status": f.status,
                "records": f.records_count,
                "last_sync": f.last_sync_timestamp.isoformat() if f.last_sync_timestamp else None,
                "error": f.last_error
            }
            for f in feeds
        ]

@router.post("/sync/{source_id}")
async def sync_single_feed(source_id: str, limit: int = 100):
    result = await threat_intel_service.sync_source(source_id, limit=limit)
    return result

@router.post("/sync-all")
async def sync_all_feeds():
    return await threat_intel_service.sync_all_sources()

@router.get("/indicators")
async def list_indicators(
    q: Optional[str] = None,
    type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100
):
    async with AsyncSessionLocal() as session:
        stmt = select(ThreatIndicator).order_by(desc(ThreatIndicator.last_seen))
        if q:
            term = f"%{q.strip()}%"
            from sqlalchemy import or_
            stmt = stmt.where(or_(
                ThreatIndicator.value.ilike(term),
                ThreatIndicator.malware_family.ilike(term),
                ThreatIndicator.source.ilike(term)
            ))
        if type:
            stmt = stmt.where(ThreatIndicator.indicator_type == type.lower())
        if severity:
            stmt = stmt.where(ThreatIndicator.severity == severity.lower())
        stmt = stmt.limit(limit)
        indicators = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": i.id,
                "value": i.value,
                "indicator_type": i.indicator_type,
                "source": i.source,
                "confidence": i.confidence,
                "severity": i.severity,
                "malware_family": i.malware_family,
                "threat_actor": i.threat_actor,
                "tags": i.tags,
                "first_seen": i.first_seen.isoformat(),
                "last_seen": i.last_seen.isoformat()
            }
            for i in indicators
        ]

@router.get("/cves")
async def list_cves(
    q: Optional[str] = None,
    is_kev: Optional[bool] = None,
    severity: Optional[str] = None,
    limit: int = 100
):
    async with AsyncSessionLocal() as session:
        stmt = select(CVERecord).order_by(desc(CVERecord.last_modified_date))
        if q:
            term = f"%{q.strip()}%"
            from sqlalchemy import or_
            stmt = stmt.where(or_(
                CVERecord.id.ilike(term),
                CVERecord.description.ilike(term),
                CVERecord.affected_product.ilike(term),
                CVERecord.affected_vendor.ilike(term)
            ))
        if is_kev is not None:
            stmt = stmt.where(CVERecord.is_kev == is_kev)
        if severity:
            stmt = stmt.where(CVERecord.cvss_severity == severity.upper())
        stmt = stmt.limit(limit)
        cves = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": c.id,
                "description": c.description,
                "cvss_v3_score": c.cvss_v3_score,
                "cvss_severity": c.cvss_severity,
                "affected_vendor": c.affected_vendor,
                "affected_product": c.affected_product,
                "is_kev": c.is_kev,
                "has_exploit": c.has_exploit
            }
            for c in cves
        ]

@router.get("/advisories")
async def list_advisories(limit: int = 50):
    async with AsyncSessionLocal() as session:
        stmt = select(SecurityAdvisory).order_by(desc(SecurityAdvisory.published_date)).limit(limit)
        advisories = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": a.id,
                "source": a.source,
                "title": a.title,
                "summary": a.summary,
                "url": a.url,
                "severity": a.severity,
                "cves": a.cves
            }
            for a in advisories
        ]
