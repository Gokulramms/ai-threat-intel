"""AlienVault OTX Connector."""

from typing import Dict, Any, List, Tuple
from openkai_engine.connectors.base import BaseTIConnector
from openkai_engine.config import settings

class AlienVaultOtxConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="alienvault_otx",
            name="AlienVault OTX",
            base_url="https://otx.alienvault.com/api/v1",
            auth_required=True,
            api_key=settings.OTX_API_KEY,
            rate_limit_delay=1.0
        )

    async def fetch_feed(self, limit: int = 50) -> Dict[str, Any]:
        if not self.api_key:
            return {"results": []}
        headers = {"X-OTX-API-KEY": self.api_key}
        resp = await self._http_get(f"{self.base_url}/pulses/subscribed?limit={limit}", headers=headers)
        return resp.json()

    def normalize(self, raw_data: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        indicators: List[Dict[str, Any]] = []
        cves: List[Dict[str, Any]] = []
        advisories: List[Dict[str, Any]] = []

        results = raw_data.get("results", []) if isinstance(raw_data, dict) else []
        for pulse in results:
            pulse_name = pulse.get("name", "Unknown Pulse")
            tags = pulse.get("tags", [])
            for ind in pulse.get("indicators", []):
                val = ind.get("indicator")
                raw_type = ind.get("type", "").lower()
                ind_type = "domain"
                if "ipv4" in raw_type or "ip" in raw_type:
                    ind_type = "ip"
                elif "sha256" in raw_type:
                    ind_type = "sha256"
                elif "md5" in raw_type:
                    ind_type = "md5"
                elif "url" in raw_type:
                    ind_type = "url"

                if val:
                    indicators.append({
                        "value": str(val).strip(),
                        "indicator_type": ind_type,
                        "source": "alienvault_otx",
                        "confidence": 75,
                        "severity": "high",
                        "malware_family": pulse_name,
                        "tags": tags,
                        "raw_data": ind
                    })

        return indicators, cves, advisories
