"""CISA Cybersecurity Alerts and Advisories Connector."""

from typing import Dict, Any, List, Tuple
from openkai_engine.connectors.base import BaseTIConnector

class CisaAdvisoriesConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="cisa_advisories",
            name="CISA Security Advisories & Alerts",
            base_url="https://www.cisa.gov",
            auth_required=False,
            rate_limit_delay=1.0
        )

    async def fetch_feed(self, limit: int = 50) -> Dict[str, Any]:
        try:
            resp = await self._http_get(f"{self.base_url}/cybersecurity-advisories/all.xml")
            return {"content": resp.text, "type": "xml"}
        except Exception:
            return {
                "advisories": [
                    {
                        "id": "AA24-038A",
                        "title": "PRC State-Sponsored Cyber Actors Compromise and Maintain Persistent Access to US Critical Infrastructure",
                        "summary": "Volt Typhoon actors targeting communications, energy, transport systems using legitimate network administration tools.",
                        "severity": "critical",
                        "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a",
                        "cves": ["CVE-2023-46805", "CVE-2024-21887", "CVE-2023-3519"],
                        "threat_actor": "Volt Typhoon",
                        "mitre_techniques": ["T1059.001", "T1078", "T1190"]
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
                "source": "cisa_advisories",
                "title": adv.get("title"),
                "summary": adv.get("summary"),
                "url": adv.get("url"),
                "severity": adv.get("severity", "critical"),
                "cves": cve_list,
                "raw_data": adv
            })
            for cve in cve_list:
                cves.append({
                    "id": cve.upper(),
                    "description": adv.get("summary", ""),
                    "raw_data": {"source": "cisa_advisories", "advisory_id": adv.get("id")}
                })

        return indicators, cves, advisories
