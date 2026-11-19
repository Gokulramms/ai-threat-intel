"""CrowdStrike Falcon Enterprise API Connector and Investigation Engine."""

import time
import httpx
from typing import Optional, Dict, Any, List
from datetime import datetime
from openkai_engine.config import settings

class CrowdStrikeFalconConnector:
    """Enterprise integration with CrowdStrike Falcon EDR API."""

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        base_url: Optional[str] = None
    ):
        self.client_id = client_id or settings.CROWDSTRIKE_CLIENT_ID
        self.client_secret = client_secret or settings.CROWDSTRIKE_CLIENT_SECRET
        self.base_url = (base_url or settings.CROWDSTRIKE_BASE_URL).rstrip("/")
        self.access_token: Optional[str] = None
        self.token_expiry: float = 0
        self.is_configured = bool(self.client_id and self.client_secret)

    async def authenticate(self) -> str:
        """Acquire or refresh OAuth2 Bearer token from Falcon API."""
        if not self.is_configured:
            raise ValueError("CrowdStrike credentials not configured.")

        if self.access_token and time.time() < self.token_expiry:
            return self.access_token

        url = f"{self.base_url}/oauth2/token"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, data=data, headers=headers)
            if resp.status_code == 401 or resp.status_code == 400:
                raise PermissionError(f"CrowdStrike Authentication Failed: HTTP {resp.status_code}")
            resp.raise_for_status()
            res_json = resp.json()
            self.access_token = res_json.get("access_token")
            expires_in = res_json.get("expires_in", 1800)
            self.token_expiry = time.time() + expires_in - 60  # 1 min safety buffer
            return self.access_token

    async def _api_call(self, endpoint: str, method: str = "GET", params: Optional[Dict[str, Any]] = None, json_body: Optional[Any] = None) -> Dict[str, Any]:
        """Perform authenticated request to Falcon API with error handling."""
        token = await self.authenticate()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        async with httpx.AsyncClient(timeout=25.0) as client:
            if method == "GET":
                resp = await client.get(url, params=params, headers=headers)
            elif method == "POST":
                resp = await client.post(url, params=params, json=json_body, headers=headers)
            else:
                raise ValueError(f"Unsupported method {method}")

            if resp.status_code == 403:
                raise PermissionError(f"CrowdStrike API 403 Forbidden: Missing scope for endpoint {endpoint}")
            resp.raise_for_status()
            return resp.json()

    async def test_connection(self) -> Dict[str, Any]:
        """Validate credentials, region, and basic API connectivity."""
        if not self.is_configured:
            return {
                "status": "unconfigured",
                "message": "CrowdStrike Client ID and Secret not configured.",
                "timestamp": datetime.utcnow().isoformat()
            }
        try:
            await self.authenticate()
            # Perform a light probe
            res = await self._api_call("/devices/queries/devices/v1?limit=1")
            return {
                "status": "connected",
                "message": "Successfully authenticated with CrowdStrike Falcon API.",
                "base_url": self.base_url,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"CrowdStrike connection check failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat()
            }

    async def get_hosts(self, filter_query: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve host details from Falcon Devices API."""
        if not self.is_configured:
            return []

        query_params = {"limit": min(limit, 100)}
        if filter_query:
            query_params["filter"] = filter_query

        # Step 1: Query device IDs
        query_res = await self._api_call("/devices/queries/devices/v1", params=query_params)
        device_ids = query_res.get("resources", [])
        if not device_ids:
            return []

        # Step 2: Fetch full entity details
        entities_res = await self._api_call("/devices/entities/devices/v1", method="POST", json_body={"ids": device_ids})
        return entities_res.get("resources", [])

    async def get_detections(self, filter_query: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve detections and behavioral summaries from Falcon Detects API."""
        if not self.is_configured:
            return []

        query_params = {"limit": min(limit, 100)}
        if filter_query:
            query_params["filter"] = filter_query

        # Step 1: Query detection IDs
        res = await self._api_call("/detects/queries/detects/v1", params=query_params)
        detection_ids = res.get("resources", [])
        if not detection_ids:
            return []

        # Step 2: Retrieve detection summaries
        summaries_res = await self._api_call("/detects/entities/summaries/GET/v1", method="POST", json_body={"ids": detection_ids})
        return summaries_res.get("resources", [])

    async def search_ioc(self, ioc_value: str, ioc_type: str) -> List[Dict[str, Any]]:
        """Search CrowdStrike detection telemetry for a specific IOC."""
        results = []
        clean_val = ioc_value.strip().lower()

        detections = await self.get_detections(limit=100)
        for det in detections:
            matched = False
            match_reason = ""

            # Check behaviors and file hashes
            for b in det.get("behaviors", []):
                sha256 = (b.get("sha256") or "").lower()
                md5 = (b.get("md5") or "").lower()
                cmdline = (b.get("cmdline") or "").lower()
                net_dest = (b.get("ip_address") or "").lower()

                if ioc_type in ("sha256", "md5") and (clean_val == sha256 or clean_val == md5):
                    matched = True
                    match_reason = f"File hash match: {clean_val} in process {b.get('filename')}"
                    break
                elif ioc_type == "ip" and clean_val == net_dest:
                    matched = True
                    match_reason = f"Network connection to malicious IP: {clean_val}"
                    break
                elif clean_val in cmdline:
                    matched = True
                    match_reason = f"Indicator detected in process command line"
                    break

            if matched:
                results.append({
                    "detection_id": det.get("detection_id"),
                    "device_id": det.get("device", {}).get("device_id"),
                    "hostname": det.get("device", {}).get("hostname"),
                    "severity": det.get("max_severity_displayname", "High"),
                    "status": det.get("status", "new"),
                    "match_reason": match_reason,
                    "first_behavior": det.get("first_behavior"),
                    "last_behavior": det.get("last_behavior"),
                    "raw_detection": det
                })
        return results

crowdstrike_connector = CrowdStrikeFalconConnector()
