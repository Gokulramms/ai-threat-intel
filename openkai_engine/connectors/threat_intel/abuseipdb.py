"""AbuseIPDB Threat Intelligence Connector."""

from typing import Dict, Any, List, Tuple
from openkai_engine.connectors.base import BaseTIConnector
from openkai_engine.config import settings

class AbuseIPDBConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="abuseipdb",
            name="AbuseIPDB IP Reputation",
            base_url="https://api.abuseipdb.com/api/v2",
            auth_required=True,
            api_key=settings.ABUSEIPDB_API_KEY,
            rate_limit_delay=1.0
        )

    async def fetch_feed(self, limit: int = 100) -> Dict[str, Any]:
        if not self.api_key:
            return {"data": []}
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {"confidenceMinimum": "90", "limit": min(limit, 500)}
        resp = await self._http_get(f"{self.base_url}/blacklist", params=params, headers=headers)
        return resp.json()

    def normalize(self, raw_data: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        indicators: List[Dict[str, Any]] = []
        cves: List[Dict[str, Any]] = []
        advisories: List[Dict[str, Any]] = []

        data_list = raw_data.get("data", []) if isinstance(raw_data, dict) else []
        for item in data_list:
            ip = item.get("ipAddress")
            score = item.get("abuseConfidenceScore", 50)
            if ip:
                indicators.append({
                    "value": ip,
                    "indicator_type": "ip",
                    "source": "abuseipdb",
                    "confidence": int(score),
                    "severity": "critical" if score >= 90 else "high",
                    "tags": ["malicious_ip", "abuseipdb_blacklist"],
                    "raw_data": item
                })

        return indicators, cves, advisories
