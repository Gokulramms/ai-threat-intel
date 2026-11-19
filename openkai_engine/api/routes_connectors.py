"""Connector Health and Diagnostics API Routes."""

from fastapi import APIRouter
from openkai_engine.connectors.crowdstrike import crowdstrike_connector
from openkai_engine.connectors.elastic import elastic_siem_connector
from openkai_engine.connectors.threat_intel import get_all_connectors

router = APIRouter(prefix="/api/connectors", tags=["Connectors"])

@router.get("/status")
async def get_all_connector_status():
    ti_connectors = get_all_connectors()
    ti_status = {}
    for sid, conn in ti_connectors.items():
        ti_status[sid] = {
            "name": conn.name,
            "requires_auth": conn.auth_required,
            "base_url": conn.base_url,
            "status": conn.last_status,
            "error": conn.last_error
        }

    cs_status = await crowdstrike_connector.test_connection()
    elastic_status = await elastic_siem_connector.test_connection()

    return {
        "crowdstrike": cs_status,
        "elastic_siem": elastic_status,
        "threat_intel_connectors": ti_status
    }

@router.post("/crowdstrike/test")
async def test_crowdstrike():
    return await crowdstrike_connector.test_connection()

@router.post("/elastic/test")
async def test_elastic():
    return await elastic_siem_connector.test_connection()
