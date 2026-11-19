"""Enterprise Security Notification and Alert Dispatch Engine."""

import httpx
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy import select
from openkai_engine.config import settings
from openkai_engine.database import AsyncSessionLocal
from openkai_engine.models.notifications import AlertDispatchLog, NotificationChannel

class NotificationService:
    """Dispatches formatted security alerts across Slack, Teams, Discord, and Email."""

    def __init__(self):
        self.slack_url = settings.SLACK_WEBHOOK_URL
        self.teams_url = settings.TEAMS_WEBHOOK_URL
        self.discord_url = settings.DISCORD_WEBHOOK_URL

    async def is_duplicate_alert(self, investigation_id: str, channel: str) -> bool:
        """Check if identical investigation alert was already dispatched within 60 minutes."""
        async with AsyncSessionLocal() as session:
            since = datetime.utcnow() - timedelta(minutes=60)
            stmt = select(AlertDispatchLog).where(
                AlertDispatchLog.investigation_id == investigation_id,
                AlertDispatchLog.channel_type == channel,
                AlertDispatchLog.status == "sent",
                AlertDispatchLog.sent_at >= since
            )
            res = await session.execute(stmt)
            return res.scalars().first() is not None

    async def dispatch_alert(self, investigation: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch security notification based on investigation severity and channels."""
        severity = investigation.get("severity", "medium").lower()
        inv_id = investigation.get("investigation_id", "INV-UNKNOWN")
        indicator = investigation.get("indicator", "UNKNOWN")
        verdict = investigation.get("verdict", "no_match_found")
        risk_score = investigation.get("risk_score", 0)

        results: Dict[str, Any] = {}

        # 1. Slack Dispatch
        if self.slack_url and not await self.is_duplicate_alert(inv_id, "slack"):
            payload = {
                "text": f"🛡️ *OpenKai SOC Alert* [{severity.upper()}] — Threat {indicator}",
                "attachments": [
                    {
                        "color": "#e01e5a" if severity == "critical" else "#ecb22e" if severity == "high" else "#2eb886",
                        "title": f"Investigation {inv_id} — Verdict: {verdict.upper()}",
                        "text": investigation.get("conclusion", ""),
                        "fields": [
                            {"title": "Risk Score", "value": f"{risk_score}/100", "short": True},
                            {"title": "Severity", "value": severity.upper(), "short": True},
                            {"title": "CrowdStrike Matches", "value": str(investigation.get("crowdstrike_matches", 0)), "short": True},
                            {"title": "SIEM Matches", "value": str(investigation.get("siem_matches", 0)), "short": True},
                            {"title": "Affected Devices", "value": str(investigation.get("affected_devices", 0)), "short": True}
                        ],
                        "footer": "OpenKai Enterprise Security Intelligence",
                        "ts": int(datetime.utcnow().timestamp())
                    }
                ]
            }
            results["slack"] = await self._send_http_webhook("slack", self.slack_url, payload, inv_id, severity)

        # 2. Microsoft Teams Dispatch
        if self.teams_url and not await self.is_duplicate_alert(inv_id, "teams"):
            teams_card = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "D63384" if severity == "critical" else "0078D7",
                "summary": f"OpenKai Security Alert: {indicator}",
                "sections": [
                    {
                        "activityTitle": f"OpenKai SOC Alert — {severity.upper()}",
                        "activitySubtitle": f"Verdict: {verdict.upper()} | Risk: {risk_score}/100",
                        "text": investigation.get("conclusion", ""),
                        "facts": [
                            {"name": "Indicator", "value": indicator},
                            {"name": "Investigation ID", "value": inv_id},
                            {"name": "CrowdStrike Detections", "value": str(investigation.get("crowdstrike_matches", 0))},
                            {"name": "SIEM Historical Events", "value": str(investigation.get("siem_matches", 0))}
                        ]
                    }
                ]
            }
            results["teams"] = await self._send_http_webhook("teams", self.teams_url, teams_card, inv_id, severity)

        # 3. Discord Dispatch
        if self.discord_url and not await self.is_duplicate_alert(inv_id, "discord"):
            discord_payload = {
                "username": "OpenKai SOC",
                "embeds": [
                    {
                        "title": f"🚨 OpenKai Alert [{severity.upper()}]: {indicator}",
                        "description": investigation.get("conclusion", ""),
                        "color": 15158332 if severity == "critical" else 15105570,
                        "fields": [
                            {"name": "Risk Score", "value": f"{risk_score}/100", "inline": True},
                            {"name": "Verdict", "value": verdict.upper(), "inline": True},
                            {"name": "Investigation", "value": inv_id, "inline": True}
                        ]
                    }
                ]
            }
            results["discord"] = await self._send_http_webhook("discord", self.discord_url, discord_payload, inv_id, severity)

        return results

    async def _send_http_webhook(
        self,
        channel: str,
        url: str,
        payload: Dict[str, Any],
        inv_id: str,
        severity: str
    ) -> Dict[str, Any]:
        """Send JSON webhook and log status."""
        status = "sent"
        error_msg = None
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
        except Exception as e:
            status = "failed"
            error_msg = str(e)

        async with AsyncSessionLocal() as session:
            log_entry = AlertDispatchLog(
                investigation_id=inv_id,
                channel_type=channel,
                title=f"Security Alert {inv_id}",
                severity=severity,
                status=status,
                message_payload=payload,
                error_message=error_msg,
                sent_at=datetime.utcnow()
            )
            session.add(log_entry)
            await session.commit()

        return {"status": status, "error": error_msg}

notification_service = NotificationService()
