"""Audit Logs API Routes."""

from fastapi import APIRouter
from sqlalchemy import select, desc
from openkai_engine.database import AsyncSessionLocal
from openkai_engine.models.audit import AuditLog

router = APIRouter(prefix="/api/audit", tags=["Audit Logs"])

@router.get("/logs")
async def list_audit_logs(limit: int = 100):
    async with AsyncSessionLocal() as session:
        stmt = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)
        logs = (await session.execute(stmt)).scalars().all()
        return [
            {
                "id": l.id,
                "user": l.user,
                "action": l.action,
                "resource_type": l.resource_type,
                "resource_id": l.resource_id,
                "details": l.details,
                "timestamp": l.timestamp.isoformat()
            }
            for l in logs
        ]
