"""Enterprise Asset and Application Inventory API Routes."""

from fastapi import APIRouter, Body, UploadFile, File, HTTPException
from typing import Optional, List
from openkai_engine.services.asset_service import asset_service

router = APIRouter(prefix="/api/assets", tags=["Enterprise Assets"])

@router.get("/devices")
async def get_devices(limit: int = 100, criticality: Optional[str] = None):
    return await asset_service.list_devices(limit=limit, criticality=criticality)

@router.get("/applications")
async def get_applications(limit: int = 100):
    return await asset_service.list_applications(limit=limit)

@router.post("/device")
async def create_single_device(payload: dict = Body(...)):
    """Register or update an enterprise device."""
    if not payload.get("device_id") or not payload.get("hostname"):
        raise HTTPException(status_code=400, detail="device_id and hostname are required.")
    device = await asset_service.add_or_update_device(payload)
    return {"status": "success", "device_id": device.device_id}

@router.post("/import/csv")
async def import_devices_csv(file: UploadFile = File(...)):
    """Upload enterprise devices CSV."""
    content = await file.read()
    csv_str = content.decode("utf-8")
    count = await asset_service.import_devices_csv(csv_str)
    return {"status": "success", "imported_devices": count}

@router.post("/sync/crowdstrike")
async def sync_crowdstrike_assets():
    """Pull real host telemetry from CrowdStrike into inventory."""
    count = await asset_service.sync_with_crowdstrike()
    return {"status": "success", "synced_devices": count}
