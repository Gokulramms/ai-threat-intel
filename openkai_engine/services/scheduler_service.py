"""Background Scheduling & Monitoring Engine."""

import asyncio
from datetime import datetime
from typing import Dict, Any, List
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from openkai_engine.config import settings
from openkai_engine.services.threat_intel_service import threat_intel_service
from openkai_engine.services.asset_service import asset_service

class SchedulerService:
    """Orchestrates periodic background threat sync and correlation tasks."""

    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.job_history: List[Dict[str, Any]] = []
        self._is_running = False

    def _log_job_run(self, job_name: str, status: str, details: Any = None):
        self.job_history.append({
            "job_name": job_name,
            "status": status,
            "details": str(details) if details else "",
            "timestamp": datetime.utcnow().isoformat()
        })
        if len(self.job_history) > 100:
            self.job_history.pop(0)

    async def run_threat_intel_sync(self):
        try:
            results = await threat_intel_service.sync_all_sources()
            self._log_job_run("threat_intel_sync", "success", results)
        except Exception as e:
            self._log_job_run("threat_intel_sync", "failed", str(e))

    async def run_crowdstrike_sync(self):
        try:
            count = await asset_service.sync_with_crowdstrike()
            self._log_job_run("crowdstrike_asset_sync", "success", f"Enriched {count} hosts")
        except Exception as e:
            self._log_job_run("crowdstrike_asset_sync", "failed", str(e))

    def start(self):
        """Start the background scheduler."""
        if self._is_running:
            return

        # Add periodic jobs
        self.scheduler.add_job(
            self.run_threat_intel_sync,
            trigger=IntervalTrigger(minutes=settings.TI_SYNC_INTERVAL_MINUTES),
            id="threat_intel_sync",
            name="Threat Intelligence Multi-Feed Sync",
            replace_existing=True
        )

        self.scheduler.add_job(
            self.run_crowdstrike_sync,
            trigger=IntervalTrigger(minutes=settings.CROWDSTRIKE_SYNC_INTERVAL_MINUTES),
            id="crowdstrike_asset_sync",
            name="CrowdStrike Host Asset Sync",
            replace_existing=True
        )

        self.scheduler.start()
        self._is_running = True

    def stop(self):
        """Stop background scheduler."""
        if self._is_running:
            self.scheduler.shutdown()
            self._is_running = False

    def get_status(self) -> Dict[str, Any]:
        """Return running jobs and execution history."""
        jobs = []
        for j in self.scheduler.get_jobs():
            jobs.append({
                "id": j.id,
                "name": j.name,
                "next_run_time": j.next_run_time.isoformat() if j.next_run_time else None
            })
        return {
            "is_running": self._is_running,
            "active_jobs": jobs,
            "recent_history": self.job_history[-20:]
        }

scheduler_service = SchedulerService()
