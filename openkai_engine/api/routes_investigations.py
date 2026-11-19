"""Security Investigation and Correlation API Routes."""

from fastapi import APIRouter, Body, HTTPException
from typing import Optional, List
from sqlalchemy import select, desc
from openkai_engine.database import AsyncSessionLocal
from openkai_engine.models.investigations import Investigation, EvidenceRecord, CorrelationFinding
from openkai_engine.services.ai_orchestrator import ai_orchestrator
from openkai_engine.services.notification_service import notification_service
from openkai_engine.schemas.threat_intel import InvestigationCreate

router = APIRouter(prefix="/api/investigations", tags=["Investigations"])

@router.post("/run")
async def run_investigation(payload: InvestigationCreate):
    """Trigger cross-platform AI & Deterministic Investigation for an IOC, CVE, or IP."""
    clean_val = payload.trigger_value.strip()
    if not clean_val:
        raise HTTPException(status_code=400, detail="Please provide a valid threat indicator or CVE.")

    result = await ai_orchestrator.execute_full_investigation(clean_val)

    # If critical or high, dispatch automated notification
    if result.get("severity") in ("critical", "high") or result.get("verdict") == "confirmed_match":
        await notification_service.dispatch_alert(result)

    return result

@router.get("")
async def list_investigations(limit: int = 50):
    async with AsyncSessionLocal() as session:
        stmt = select(Investigation).order_by(desc(Investigation.created_at)).limit(limit)
        invs = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": inv.id,
                "title": inv.title,
                "trigger_type": inv.trigger_type,
                "trigger_value": inv.trigger_value,
                "status": inv.status,
                "risk_score": inv.risk_score,
                "severity": inv.severity,
                "verdict": inv.verdict,
                "conclusion": inv.conclusion_summary,
                "created_at": inv.created_at.isoformat()
            }
            for inv in invs
        ]

@router.get("/{inv_id}")
async def get_investigation_details(inv_id: str):
    async with AsyncSessionLocal() as session:
        inv = await session.get(Investigation, inv_id)
        if not inv:
            # Flexible resolution: allow searching by "latest" or by indicator / CVE name
            stmt = select(Investigation).order_by(desc(Investigation.created_at))
            if inv_id.lower() != "latest":
                stmt = select(Investigation).where(Investigation.trigger_value.ilike(f"%{inv_id}%")).order_by(desc(Investigation.created_at))
            inv = (await session.execute(stmt)).scalars().first()

            if not inv:
                # Fallback to the latest record in database if available
                inv = (await session.execute(select(Investigation).order_by(desc(Investigation.created_at)))).scalars().first()

        if not inv:
            raise HTTPException(status_code=404, detail="Investigation not found. Please run an investigation first.")

        actual_id = inv.id
        ev_stmt = select(EvidenceRecord).where(EvidenceRecord.investigation_id == actual_id)
        evidence = (await session.execute(ev_stmt)).scalars().all()

        corr_stmt = select(CorrelationFinding).where(CorrelationFinding.investigation_id == actual_id)
        findings = (await session.execute(corr_stmt)).scalars().all()

        return {
            "investigation": {
                "id": inv.id,
                "title": inv.title,
                "trigger_type": inv.trigger_type,
                "trigger_value": inv.trigger_value,
                "status": inv.status,
                "risk_score": inv.risk_score,
                "severity": inv.severity,
                "verdict": inv.verdict,
                "conclusion": inv.conclusion_summary,
                "created_at": inv.created_at.isoformat()
            },
            "evidence": [
                {
                    "source": e.source,
                    "evidence_type": e.evidence_type,
                    "description": e.description,
                    "confidence": e.confidence,
                    "raw_data": e.raw_data
                }
                for e in evidence
            ],
            "findings": [
                {
                    "correlation_type": f.correlation_type,
                    "entity_id": f.entity_id,
                    "entity_name": f.entity_name,
                    "details": f.details
                }
                for f in findings
            ]
        }
