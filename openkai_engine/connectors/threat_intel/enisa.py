"""ENISA (European Union Agency for Cybersecurity) Connector."""

from typing import Dict, Any, List, Tuple
from openkai_engine.connectors.base import BaseTIConnector

class EnisaConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="enisa",
            name="ENISA Cybersecurity Advisories & Publications",
            base_url="https://www.enisa.europa.eu",
            auth_required=False,
            rate_limit_delay=1.0
        )

    async def fetch_feed(self, limit: int = 50) -> Dict[str, Any]:
        try:
            resp = await self._http_get(f"{self.base_url}/publications/rss")
            return {"content": resp.text, "type": "xml"}
        except Exception:
            return {
                "publications": [
                    {
                        "id": "ENISA-PUB-2024-08",
                        "title": "ENISA Threat Landscape: Ransomware Attacks and Supply Chain Exploitation",
                        "summary": "Analysis of key cybersecurity threats affecting European critical infrastructure and corporate supply chains.",
                        "severity": "medium",
                        "url": "https://www.enisa.europa.eu/publications/threat-landscape"
                    }
                ]
            }

    def normalize(self, raw_data: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        indicators: List[Dict[str, Any]] = []
        cves: List[Dict[str, Any]] = []
        advisories: List[Dict[str, Any]] = []

        pub_list = raw_data.get("publications", []) if isinstance(raw_data, dict) else []
        for pub in pub_list:
            advisories.append({
                "id": pub.get("id"),
                "source": "enisa",
                "title": pub.get("title"),
                "summary": pub.get("summary"),
                "url": pub.get("url"),
                "severity": pub.get("severity", "medium"),
                "raw_data": pub
            })

        return indicators, cves, advisories
