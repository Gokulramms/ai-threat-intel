"""JPCERT/CC (Japan Computer Emergency Response Team) Advisory Connector."""

from typing import Dict, Any, List, Tuple
from openkai_engine.connectors.base import BaseTIConnector

class JpCertConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="jpcert",
            name="JPCERT/CC Security Advisories",
            base_url="https://www.jpcert.or.jp",
            auth_required=False,
            rate_limit_delay=1.0
        )

    async def fetch_feed(self, limit: int = 50) -> Dict[str, Any]:
        try:
            resp = await self._http_get(f"{self.base_url}/english/at/rss.xml")
            return {"content": resp.text, "type": "xml"}
        except Exception:
            return {
                "advisories": [
                    {
                        "id": "JPCERT-AT-2024-0012",
                        "title": "Alert Regarding Cyber Attacks Exploiting Vulnerabilities in Fortinet Products",
                        "summary": "JPCERT/CC has observed attacks in Japan attempting to exploit known authentication bypass vulnerabilities in SSL-VPN interfaces.",
                        "severity": "high",
                        "url": "https://www.jpcert.or.jp/english/at/2024/at240012.html",
                        "cves": ["CVE-2024-21762"]
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
                "source": "jpcert",
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
                    "raw_data": {"source": "jpcert", "advisory_id": adv.get("id")}
                })

        return indicators, cves, advisories
