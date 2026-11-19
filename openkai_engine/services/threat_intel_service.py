"""Threat Intelligence Management & Ingestion Service."""

from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import select, func, or_
from openkai_engine.database import AsyncSessionLocal
from openkai_engine.models.threat_intel import ThreatFeed, ThreatIndicator, CVERecord, SecurityAdvisory
from openkai_engine.connectors.threat_intel import get_all_connectors
from openkai_engine.core.audit import log_audit_event

class ThreatIntelService:
    def __init__(self):
        self.connectors = get_all_connectors()

    async def initialize_feeds_table(self):
        """Ensure all 14 connectors are registered in the database threat_feeds table."""
        async with AsyncSessionLocal() as session:
            for source_id, conn in self.connectors.items():
                existing = await session.get(ThreatFeed, source_id)
                if not existing:
                    feed = ThreatFeed(
                        id=source_id,
                        name=conn.name,
                        source_type="api",
                        url=conn.base_url,
                        requires_auth=conn.auth_required,
                        is_enabled=True,
                        status="idle",
                        records_count=0
                    )
                    session.add(feed)
            await session.commit()

    async def sync_source(self, source_id: str, limit: int = 100) -> Dict[str, Any]:
        """Synchronize a specific threat intel source, normalize, deduplicate, and persist."""
        connector = self.connectors.get(source_id)
        if not connector:
            return {"status": "error", "message": f"Source {source_id} not found."}

        sync_start = datetime.utcnow()
        try:
            raw_data = await connector.fetch_feed(limit=limit)
            indicators, cves, advisories = connector.normalize(raw_data)

            new_indicators_count = 0
            new_cves_count = 0
            new_advisories_count = 0

            async with AsyncSessionLocal() as session:
                # 1. Ingest & Deduplicate Indicators
                for ind in indicators:
                    val = ind["value"].strip()
                    ind_type = ind["indicator_type"]
                    stmt = select(ThreatIndicator).where(
                        ThreatIndicator.value == val,
                        ThreatIndicator.indicator_type == ind_type
                    )
                    res = await session.execute(stmt)
                    existing_ind = res.scalars().first()
                    if existing_ind:
                        existing_ind.last_seen = sync_start
                        existing_ind.confidence = max(existing_ind.confidence, ind.get("confidence", 50))
                    else:
                        new_ind = ThreatIndicator(
                            value=val,
                            indicator_type=ind_type,
                            source=ind["source"],
                            confidence=ind.get("confidence", 50),
                            severity=ind.get("severity", "medium"),
                            malware_family=ind.get("malware_family"),
                            threat_actor=ind.get("threat_actor"),
                            tags=ind.get("tags", []),
                            raw_data=ind.get("raw_data", {}),
                            first_seen=sync_start,
                            last_seen=sync_start
                        )
                        session.add(new_ind)
                        new_indicators_count += 1

                # 2. Ingest & Deduplicate CVEs
                for cve in cves:
                    cve_id = cve["id"].strip().upper()
                    existing_cve = await session.get(CVERecord, cve_id)
                    if existing_cve:
                        if cve.get("is_kev"):
                            existing_cve.is_kev = True
                        if cve.get("cvss_v3_score"):
                            existing_cve.cvss_v3_score = cve["cvss_v3_score"]
                        if cve.get("cvss_severity"):
                            existing_cve.cvss_severity = cve["cvss_severity"]
                        existing_cve.last_modified_date = sync_start
                    else:
                        new_cve = CVERecord(
                            id=cve_id,
                            description=cve.get("description"),
                            cvss_v3_score=cve.get("cvss_v3_score"),
                            cvss_severity=cve.get("cvss_severity"),
                            cwe_id=cve.get("cwe_id"),
                            affected_vendor=cve.get("affected_vendor"),
                            affected_product=cve.get("affected_product"),
                            affected_versions=cve.get("affected_versions", []),
                            fixed_versions=cve.get("fixed_versions", []),
                            is_kev=cve.get("is_kev", False),
                            has_exploit=cve.get("has_exploit", False),
                            mitre_techniques=cve.get("mitre_techniques", []),
                            published_date=sync_start,
                            last_modified_date=sync_start,
                            raw_data=cve.get("raw_data", {})
                        )
                        session.add(new_cve)
                        new_cves_count += 1

                # 3. Ingest & Deduplicate Advisories
                for adv in advisories:
                    adv_id = adv["id"]
                    existing_adv = await session.get(SecurityAdvisory, adv_id)
                    if not existing_adv:
                        new_adv = SecurityAdvisory(
                            id=adv_id,
                            source=adv["source"],
                            title=adv["title"],
                            summary=adv.get("summary"),
                            url=adv.get("url"),
                            published_date=sync_start,
                            cves=adv.get("cves", []),
                            iocs=adv.get("iocs", []),
                            severity=adv.get("severity", "medium"),
                            raw_data=adv.get("raw_data", {})
                        )
                        session.add(new_adv)
                        new_advisories_count += 1

                # Update feed record
                feed = await session.get(ThreatFeed, source_id)
                if feed:
                    feed.status = "healthy"
                    feed.last_sync_timestamp = sync_start
                    feed.records_count += (new_indicators_count + new_cves_count + new_advisories_count)
                    feed.last_error = None

                await session.commit()

            await log_audit_event(
                action="threat_intel_sync",
                resource_type="feed",
                resource_id=source_id,
                details={
                    "new_indicators": new_indicators_count,
                    "new_cves": new_cves_count,
                    "new_advisories": new_advisories_count
                }
            )

            return {
                "source_id": source_id,
                "status": "success",
                "new_indicators": new_indicators_count,
                "new_cves": new_cves_count,
                "new_advisories": new_advisories_count,
                "timestamp": sync_start.isoformat()
            }
        except Exception as e:
            async with AsyncSessionLocal() as session:
                feed = await session.get(ThreatFeed, source_id)
                if feed:
                    feed.status = "error"
                    feed.last_error = str(e)
                await session.commit()
            return {"source_id": source_id, "status": "error", "error": str(e)}

    async def sync_all_sources(self) -> Dict[str, Any]:
        """Synchronize all enabled threat intelligence connectors."""
        results = {}
        for source_id in self.connectors.keys():
            results[source_id] = await self.sync_source(source_id)
        return results

    async def get_metrics(self) -> Dict[str, Any]:
        """Aggregate Threat Intelligence KPIs."""
        async with AsyncSessionLocal() as session:
            total_indicators = await session.scalar(select(func.count(ThreatIndicator.id))) or 0
            total_cves = await session.scalar(select(func.count(CVERecord.id))) or 0
            total_kev = await session.scalar(select(func.count(CVERecord.id)).where(CVERecord.is_kev == True)) or 0
            total_advisories = await session.scalar(select(func.count(SecurityAdvisory.id))) or 0
            feeds_stmt = select(ThreatFeed)
            feeds_res = await session.execute(feeds_stmt)
            feeds = [
                {
                    "id": f.id,
                    "name": f.name,
                    "status": f.status,
                    "records": f.records_count,
                    "last_sync": f.last_sync_timestamp.isoformat() if f.last_sync_timestamp else None,
                    "error": f.last_error
                }
                for f in feeds_res.scalars().all()
            ]

        return {
            "total_indicators": total_indicators,
            "total_cves": total_cves,
            "total_kev": total_kev,
            "total_advisories": total_advisories,
            "feeds": feeds
        }

threat_intel_service = ThreatIntelService()
