"""CISA Known Exploited Vulnerabilities (KEV) Connector."""

from datetime import datetime
from typing import Dict, Any, List, Tuple
from openkai_engine.connectors.base import BaseTIConnector

class CisaKevConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="cisa_kev",
            name="CISA Known Exploited Vulnerabilities",
            base_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            auth_required=False,
            rate_limit_delay=0.1
        )

    async def fetch_feed(self, limit: int = 100) -> Dict[str, Any]:
        resp = await self._http_get(self.base_url)
        return resp.json()

    def normalize(self, raw_data: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        indicators: List[Dict[str, Any]] = []
        cves: List[Dict[str, Any]] = []
        advisories: List[Dict[str, Any]] = []

        vulnerabilities = raw_data.get("vulnerabilities", []) if isinstance(raw_data, dict) else []
        for item in vulnerabilities:
            cve_id = item.get("cveID")
            if not cve_id:
                continue

            cves.append({
                "id": cve_id.upper(),
                "description": item.get("shortDescription") or item.get("vulnerabilityName", ""),
                "affected_vendor": item.get("vendorProject"),
                "affected_product": item.get("product"),
                "is_kev": True,
                "has_exploit": True,
                "published_date": item.get("dateAdded"),
                "raw_data": {
                    "required_action": item.get("requiredAction"),
                    "due_date": item.get("dueDate"),
                    "notes": item.get("notes")
                }
            })

        return indicators, cves, advisories
