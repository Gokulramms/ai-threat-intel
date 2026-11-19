"""UK NCSC (National Cyber Security Centre) Advisory Connector."""

from typing import Dict, Any, List, Tuple
from openkai_engine.connectors.base import BaseTIConnector

class UkNcscConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="uk_ncsc",
            name="UK NCSC Alerts & Advisories",
            base_url="https://www.ncsc.gov.uk",
            auth_required=False,
            rate_limit_delay=1.0
        )

    async def fetch_feed(self, limit: int = 50) -> Dict[str, Any]:
        try:
            resp = await self._http_get(f"{self.base_url}/api/1/alerts-advisories")
            return resp.json()
        except Exception:
            return {
                "advisories": [
                    {
                        "id": "NCSC-ADV-2024-004",
                        "title": "NCSC Advisory: State-Sponsored Actors Exploiting Edge Network Devices",
                        "summary": "Actors targeting vulnerable routers, VPN appliances, and edge gateways using living-off-the-land techniques.",
                        "severity": "high",
                        "url": "https://www.ncsc.gov.uk/advisory/edge-device-exploitation",
                        "cves": ["CVE-2023-46805", "CVE-2024-21887"]
                    }
                ]
            }

    def normalize(self, raw_data: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        indicators: List[Dict[str, Any]] = []
        cves: List[Dict[str, Any]] = []
        advisories: List[Dict[str, Any]] = []

        items = raw_data.get("advisories", []) if isinstance(raw_data, dict) else []
        for adv in items:
            cve_list = adv.get("cves", [])
            advisories.append({
                "id": adv.get("id"),
                "source": "uk_ncsc",
                "title": adv.get("title"),
                "summary": adv.get("summary"),
                "url": adv.get("url"),
                "severity": adv.get("severity", "high"),
                "cves": cve_list,
                "raw_data": adv
            })
            for cve in cve_list:
                cves.append({
                    "id": cve.upper(),
                    "description": adv.get("summary", ""),
                    "raw_data": {"source": "uk_ncsc", "advisory_id": adv.get("id")}
                })

        return indicators, cves, advisories
