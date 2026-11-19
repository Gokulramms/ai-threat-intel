"""abuse.ch ThreatFox IOC & Feodo Tracker Botnet Connector."""

from typing import Dict, Any, List, Tuple
from openkai_engine.connectors.base import BaseTIConnector
from openkai_engine.config import settings

class ThreatFoxConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="threatfox",
            name="abuse.ch ThreatFox / Feodo",
            base_url="https://threatfox-api.abuse.ch/api/v1",
            auth_required=False,
            rate_limit_delay=0.5
        )

    async def fetch_feed(self, limit: int = 100) -> Dict[str, Any]:
        headers = {}
        if settings.ABUSE_CH_API_KEY:
            headers["Auth-Key"] = settings.ABUSE_CH_API_KEY
            try:
                payload = {"query": "get_iocs", "days": 1}
                resp = await self._http_post(self.base_url, json_data=payload, headers=headers)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                pass

        # Public open feed fallback: abuse.ch Feodo Tracker Live Botnet C2 blocklist
        feodo_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        try:
            resp = await self._http_get(feodo_url)
            if resp.status_code == 200:
                return {"feodo_feed": resp.json()[:limit]}
        except Exception as e:
            pass
        return {"data": []}

    def normalize(self, raw_data: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        indicators: List[Dict[str, Any]] = []
        cves: List[Dict[str, Any]] = []
        advisories: List[Dict[str, Any]] = []

        # Case 1: Feodo Tracker Open Feed
        if isinstance(raw_data, dict) and "feodo_feed" in raw_data:
            for item in raw_data["feodo_feed"]:
                ip = item.get("ip_address")
                if not ip:
                    continue
                malware = item.get("malware", "Botnet C2")
                indicators.append({
                    "value": ip.strip(),
                    "indicator_type": "ip",
                    "source": "abuse.ch Feodo Tracker",
                    "confidence": 90,
                    "severity": "critical",
                    "malware_family": malware,
                    "threat_actor": f"ASN {item.get('as_number', 'Unknown')} ({item.get('country', 'XX')})",
                    "tags": ["botnet", "c2", malware.lower()],
                    "raw_data": item
                })
            return indicators, cves, advisories

        # Case 2: ThreatFox API
        data_list = raw_data.get("data", []) if isinstance(raw_data, dict) else []
        for item in data_list:
            raw_val = item.get("ioc")
            raw_type = item.get("ioc_type", "").lower()
            if not raw_val:
                continue

            ind_type = "domain"
            val = raw_val
            if "ip:port" in raw_type or "ip" in raw_type:
                ind_type = "ip"
                val = raw_val.split(":")[0]
            elif "sha256" in raw_type:
                ind_type = "sha256"
            elif "md5" in raw_type:
                ind_type = "md5"
            elif "url" in raw_type:
                ind_type = "url"

            indicators.append({
                "value": val.strip(),
                "indicator_type": ind_type,
                "source": "abuse.ch ThreatFox",
                "confidence": int(item.get("confidence_level", 75)),
                "severity": "high",
                "malware_family": item.get("malware_printable"),
                "threat_actor": item.get("threat_type"),
                "tags": item.get("tags") or [],
                "raw_data": item
            })

        return indicators, cves, advisories
