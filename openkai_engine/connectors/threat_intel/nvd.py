"""NIST National Vulnerability Database (NVD) Connector."""

from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from openkai_engine.connectors.base import BaseTIConnector
from openkai_engine.config import settings

class NvdConnector(BaseTIConnector):
    def __init__(self):
        super().__init__(
            source_id="nist_nvd",
            name="NIST National Vulnerability Database",
            base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            auth_required=False,
            api_key=settings.NVD_API_KEY,
            rate_limit_delay=0.6 if settings.NVD_API_KEY else 6.0
        )

    async def fetch_feed(self, limit: int = 50, cve_id: Optional[str] = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {"resultsPerPage": min(limit, 100)}
        if cve_id:
            params["cveId"] = cve_id
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        resp = await self._http_get(self.base_url, params=params, headers=headers)
        return resp.json()

    def normalize(self, raw_data: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        indicators: List[Dict[str, Any]] = []
        cves: List[Dict[str, Any]] = []
        advisories: List[Dict[str, Any]] = []

        items = raw_data.get("vulnerabilities", []) if isinstance(raw_data, dict) else []
        for wrapper in items:
            cve_item = wrapper.get("cve", {})
            cve_id = cve_item.get("id")
            if not cve_id:
                continue

            descriptions = cve_item.get("descriptions", [])
            desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")

            # CVSS v3.1 / v3.0 metrics
            metrics = cve_item.get("metrics", {})
            cvss_data = None
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData")
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData")

            cvss_score = cvss_data.get("baseScore") if cvss_data else None
            cvss_severity = cvss_data.get("baseSeverity") if cvss_data else None

            # CWE
            weaknesses = cve_item.get("weaknesses", [])
            cwe_id = None
            if weaknesses:
                desc_list = weaknesses[0].get("description", [])
                if desc_list:
                    cwe_id = desc_list[0].get("value")

            cves.append({
                "id": cve_id.upper(),
                "description": desc,
                "cvss_v3_score": cvss_score,
                "cvss_severity": cvss_severity,
                "cwe_id": cwe_id,
                "published_date": cve_item.get("published"),
                "last_modified_date": cve_item.get("lastModified"),
                "raw_data": {
                    "references": [ref.get("url") for ref in cve_item.get("references", [])]
                }
            })

        return indicators, cves, advisories
