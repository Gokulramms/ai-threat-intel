"""VirusTotal v3 API Connector."""

from typing import Dict, Any, List, Tuple
from openkai_engine.connectors.base import BaseTIConnector
from openkai_engine.config import settings

class VirusTotalConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="virustotal",
            name="VirusTotal Intelligence",
            base_url="https://www.virustotal.com/api/v3",
            auth_required=True,
            api_key=settings.VIRUSTOTAL_API_KEY,
            rate_limit_delay=15.0 if not settings.VIRUSTOTAL_API_KEY else 1.0
        )

    async def fetch_feed(self, limit: int = 20) -> Dict[str, Any]:
        if not self.api_key:
            return {"data": []}
        headers = {"x-apikey": self.api_key}
        # In free/standard tier, query intelligence search or comments
        resp = await self._http_get(f"{self.base_url}/popular_threat_categories", headers=headers)
        return resp.json()

    async def lookup_indicator(self, indicator_type: str, value: str) -> Dict[str, Any]:
        """Look up a specific IP, domain, or file hash."""
        if not self.api_key:
            return {"status": "unconfigured"}
        headers = {"x-apikey": self.api_key}
        endpoint_map = {
            "ip": f"{self.base_url}/ip_addresses/{value}",
            "domain": f"{self.base_url}/domains/{value}",
            "sha256": f"{self.base_url}/files/{value}",
            "md5": f"{self.base_url}/files/{value}"
        }
        url = endpoint_map.get(indicator_type)
        if not url:
            return {"error": "Unsupported indicator type"}
        resp = await self._http_get(url, headers=headers)
        return resp.json()

    def normalize(self, raw_data: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        indicators: List[Dict[str, Any]] = []
        cves: List[Dict[str, Any]] = []
        advisories: List[Dict[str, Any]] = []

        # If normalizing a single lookup result
        data = raw_data.get("data", {}) if isinstance(raw_data, dict) else {}
        if data:
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            val = data.get("id")
            val_type = data.get("type", "file")
            norm_type = "sha256" if val_type == "file" else val_type

            if val and malicious_count > 0:
                indicators.append({
                    "value": val,
                    "indicator_type": norm_type,
                    "source": "virustotal",
                    "confidence": min(100, malicious_count * 10),
                    "severity": "critical" if malicious_count >= 10 else "high",
                    "tags": ["virustotal_positive"],
                    "raw_data": stats
                })

        return indicators, cves, advisories
