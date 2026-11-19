"""abuse.ch URLhaus & Proofpoint Emerging Threats Connector."""

from typing import Dict, Any, List, Tuple
from openkai_engine.connectors.base import BaseTIConnector
from openkai_engine.config import settings

class URLhausConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="urlhaus",
            name="abuse.ch URLhaus / ET",
            base_url="https://urlhaus-api.abuse.ch/v1",
            auth_required=False,
            rate_limit_delay=0.5
        )

    async def fetch_feed(self, limit: int = 100) -> Dict[str, Any]:
        headers = {}
        if settings.ABUSE_CH_API_KEY:
            headers["Auth-Key"] = settings.ABUSE_CH_API_KEY
            try:
                resp = await self._http_get(f"{self.base_url}/urls/recent/", headers=headers)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                pass

        # Public open feed fallback: Proofpoint Emerging Threats Compromised IPs Feed
        et_url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
        try:
            resp = await self._http_get(et_url)
            if resp.status_code == 200:
                lines = [l.strip() for l in resp.text.splitlines() if l.strip() and not l.startswith("#")]
                return {"compromised_ips": lines[:limit]}
        except Exception:
            pass
        return {"urls": []}

    def normalize(self, raw_data: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        indicators: List[Dict[str, Any]] = []
        cves: List[Dict[str, Any]] = []
        advisories: List[Dict[str, Any]] = []

        # Case 1: Emerging Threats Compromised IPs
        if isinstance(raw_data, dict) and "compromised_ips" in raw_data:
            for ip in raw_data["compromised_ips"]:
                indicators.append({
                    "value": ip,
                    "indicator_type": "ip",
                    "source": "Emerging Threats Compromised IPs",
                    "confidence": 85,
                    "severity": "high",
                    "malware_family": "Known Compromised Host",
                    "threat_actor": "Emerging Threats / Proofpoint",
                    "tags": ["compromised", "scanning", "botnet"],
                    "raw_data": {"ip": ip, "feed": "emerging_threats"}
                })
            return indicators, cves, advisories

        # Case 2: URLhaus API
        urls = raw_data.get("urls", []) if isinstance(raw_data, dict) else []
        for item in urls:
            url_val = item.get("url")
            if not url_val:
                continue

            status = item.get("url_status", "online")
            threat = item.get("threat", "malware_download")
            tags = item.get("tags") or []

            indicators.append({
                "value": url_val.strip(),
                "indicator_type": "url",
                "source": "abuse.ch URLhaus",
                "confidence": 85 if status == "online" else 60,
                "severity": "high",
                "malware_family": threat,
                "tags": tags,
                "raw_data": item
            })

        return indicators, cves, advisories
