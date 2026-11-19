"""MITRE ATT&CK Connector for STIX 2.1 Enterprise Techniques."""

from typing import Dict, Any, List, Tuple
from openkai_engine.connectors.base import BaseTIConnector

class MitreAttackConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="mitre_attack",
            name="MITRE ATT&CK Enterprise Matrix",
            base_url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
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

        objects = raw_data.get("objects", []) if isinstance(raw_data, dict) else []
        for obj in objects:
            if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
                ext_refs = obj.get("external_references", [])
                tech_id = None
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id")
                        break

                if tech_id:
                    kill_chain = obj.get("kill_chain_phases", [])
                    tactics = [kc.get("phase_name") for kc in kill_chain if kc.get("kill_chain_name") == "mitre-attack"]
                    tactic_name = tactics[0] if tactics else "unknown"

                    advisories.append({
                        "id": tech_id,
                        "source": "mitre_attack",
                        "title": f"MITRE Technique {tech_id}: {obj.get('name')}",
                        "summary": obj.get("description", "")[:1000],
                        "severity": "medium",
                        "raw_data": {
                            "tactic": tactic_name,
                            "platforms": obj.get("x_mitre_platforms", []),
                            "data_sources": obj.get("x_mitre_data_sources", []),
                        }
                    })

        return indicators, cves, advisories
