"""Enterprise Asset, Application, and Infrastructure Inventory Service."""

import csv
import io
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import select, func, or_
from openkai_engine.database import AsyncSessionLocal
from openkai_engine.models.assets import Device, Application, DeviceApplicationMap, InfrastructureAsset
from openkai_engine.connectors.crowdstrike import crowdstrike_connector
from openkai_engine.core.audit import log_audit_event

class AssetService:
    """Manages devices, software inventory, infrastructure, and asset-vulnerability mapping."""

    async def list_devices(self, limit: int = 100, criticality: Optional[str] = None) -> List[Dict[str, Any]]:
        async with AsyncSessionLocal() as session:
            stmt = select(Device)
            if criticality:
                stmt = stmt.where(Device.criticality == criticality.lower())
            stmt = stmt.limit(limit)
            res = await session.execute(stmt)
            devices = res.scalars().all()
            return [
                {
                    "id": d.id,
                    "device_id": d.device_id,
                    "hostname": d.hostname,
                    "ip_address": d.ip_address,
                    "mac_address": d.mac_address,
                    "os_name": d.os_name,
                    "os_version": d.os_version,
                    "device_type": d.device_type,
                    "owner": d.owner,
                    "department": d.department,
                    "business_unit": d.business_unit,
                    "criticality": d.criticality,
                    "falcon_agent_id": d.falcon_agent_id,
                    "falcon_status": d.falcon_status,
                    "security_status": d.security_status,
                    "is_internet_facing": d.is_internet_facing,
                    "last_seen": d.last_seen.isoformat() if d.last_seen else None
                }
                for d in devices
            ]

    async def list_applications(self, limit: int = 100) -> List[Dict[str, Any]]:
        async with AsyncSessionLocal() as session:
            stmt = select(Application).limit(limit)
            res = await session.execute(stmt)
            apps = res.scalars().all()
            return [
                {
                    "id": a.id,
                    "name": a.name,
                    "publisher": a.publisher,
                    "version": a.version,
                    "category": a.category,
                    "risk_level": a.risk_level,
                    "business_criticality": a.business_criticality,
                    "owner": a.owner,
                    "end_of_life": a.end_of_life,
                    "known_cves": a.known_cves
                }
                for a in apps
            ]

    async def add_or_update_device(self, data: Dict[str, Any]) -> Device:
        async with AsyncSessionLocal() as session:
            stmt = select(Device).where(Device.device_id == data["device_id"])
            res = await session.execute(stmt)
            device = res.scalars().first()
            if not device:
                device = Device(**data)
                session.add(device)
            else:
                for k, v in data.items():
                    if hasattr(device, k):
                        setattr(device, k, v)
                device.last_seen = datetime.utcnow()
            await session.commit()
            await session.refresh(device)
            return device

    async def add_or_update_application(self, data: Dict[str, Any]) -> Application:
        async with AsyncSessionLocal() as session:
            stmt = select(Application).where(
                Application.name == data["name"],
                Application.version == data.get("version")
            )
            res = await session.execute(stmt)
            app = res.scalars().first()
            if not app:
                app = Application(**data)
                session.add(app)
            else:
                for k, v in data.items():
                    if hasattr(app, k):
                        setattr(app, k, v)
            await session.commit()
            await session.refresh(app)
            return app

    async def map_device_to_app(self, device_id: str, app_id: int, installed_version: Optional[str] = None) -> None:
        async with AsyncSessionLocal() as session:
            stmt = select(DeviceApplicationMap).where(
                DeviceApplicationMap.device_id == device_id,
                DeviceApplicationMap.application_id == app_id
            )
            res = await session.execute(stmt)
            mapping = res.scalars().first()
            if not mapping:
                mapping = DeviceApplicationMap(
                    device_id=device_id,
                    application_id=app_id,
                    installed_version=installed_version
                )
                session.add(mapping)
                await session.commit()

    async def import_devices_csv(self, csv_content: str) -> int:
        """Import devices from CSV string."""
        f = io.StringIO(csv_content.strip())
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            if not row.get("device_id") or not row.get("hostname"):
                continue
            device_data = {
                "device_id": row["device_id"].strip(),
                "hostname": row["hostname"].strip(),
                "ip_address": row.get("ip_address", "").strip(),
                "os_name": row.get("os_name", "Windows"),
                "os_version": row.get("os_version", ""),
                "device_type": row.get("device_type", "workstation"),
                "owner": row.get("owner", ""),
                "department": row.get("department", "IT"),
                "criticality": row.get("criticality", "medium").lower(),
                "is_internet_facing": row.get("is_internet_facing", "false").lower() in ("true", "1", "yes")
            }
            await self.add_or_update_device(device_data)
            count += 1
        await log_audit_event("import_devices_csv", "inventory", details={"imported_count": count})
        return count

    async def sync_with_crowdstrike(self) -> int:
        """Enrich enterprise device inventory directly from CrowdStrike Falcon API."""
        falcon_hosts = await crowdstrike_connector.get_hosts(limit=100)
        count = 0
        for h in falcon_hosts:
            dev_id = h.get("device_id")
            hostname = h.get("hostname")
            if not dev_id or not hostname:
                continue

            data = {
                "device_id": dev_id,
                "hostname": hostname,
                "ip_address": h.get("local_ip"),
                "os_name": h.get("platform_name"),
                "os_version": h.get("os_version"),
                "falcon_agent_id": dev_id,
                "falcon_status": h.get("status", "normal"),
                "device_type": "server" if "server" in (h.get("os_version") or "").lower() else "workstation",
                "department": (h.get("groups") or ["General"])[0] if h.get("groups") else "General",
                "security_status": "healthy"
            }
            await self.add_or_update_device(data)
            count += 1
        return count

    async def find_affected_assets_for_cve(
        self,
        cve_id: str,
        vendor: Optional[str] = None,
        product: Optional[str] = None
    ) -> Dict[str, Any]:
        """Correlate a vulnerability with installed applications and affected enterprise devices."""
        affected_apps = []
        affected_devices = []

        async with AsyncSessionLocal() as session:
            # Query applications matching product / vendor
            app_stmt = select(Application)
            if product:
                app_stmt = app_stmt.where(Application.name.ilike(f"%{product}%"))
            apps = (await session.execute(app_stmt)).scalars().all()

            for app in apps:
                affected_apps.append({
                    "app_id": app.id,
                    "name": app.name,
                    "publisher": app.publisher,
                    "version": app.version,
                    "criticality": app.business_criticality
                })

                # Find devices with this app installed
                dev_map_stmt = select(DeviceApplicationMap).where(DeviceApplicationMap.application_id == app.id)
                mappings = (await session.execute(dev_map_stmt)).scalars().all()
                for m in mappings:
                    dev_stmt = select(Device).where(Device.device_id == m.device_id)
                    dev = (await session.execute(dev_stmt)).scalars().first()
                    if dev:
                        affected_devices.append({
                            "device_id": dev.device_id,
                            "hostname": dev.hostname,
                            "ip_address": dev.ip_address,
                            "criticality": dev.criticality,
                            "owner": dev.owner,
                            "is_internet_facing": dev.is_internet_facing,
                            "installed_version": m.installed_version
                        })

        return {
            "cve_id": cve_id,
            "total_affected_applications": len(affected_apps),
            "total_affected_devices": len(affected_devices),
            "applications": affected_apps,
            "devices": affected_devices
        }

asset_service = AssetService()
