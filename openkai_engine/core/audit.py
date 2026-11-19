"""Audit Logging Engine."""

from datetime import datetime
from typing import Optional, Dict, Any
from openkai_engine.database import AsyncSessionLocal
from openkai_engine.models.audit import AuditLog

async def log_audit_event(
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    user: Optional[str] = "system",
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None
) -> None:
    """Record an audit event persistently in the database."""
    try:
        async with AsyncSessionLocal() as session:
            event = AuditLog(
                user=user,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details or {},
                ip_address=ip_address,
                timestamp=datetime.utcnow()
            )
            session.add(event)
            await session.commit()
    except Exception as e:
        print(f"[AUDIT LOGGING ERROR] Failed to record event {action}: {e}")
