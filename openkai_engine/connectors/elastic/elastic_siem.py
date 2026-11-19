"""Elasticsearch and Kibana SIEM Enterprise Connector."""

import re
import httpx
from typing import Optional, Dict, Any, List
from datetime import datetime
from openkai_engine.config import settings

class ElasticSiemConnector:
    """Enterprise integration with Elasticsearch and Elastic SIEM."""

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        index_pattern: Optional[str] = None
    ):
        self.url = (url or settings.ELASTIC_URL or "").rstrip("/")
        self.api_key = api_key or settings.ELASTIC_API_KEY
        self.username = username or settings.ELASTIC_USERNAME
        self.password = password or settings.ELASTIC_PASSWORD
        self.index_pattern = index_pattern or settings.ELASTIC_INDEX
        self.is_configured = bool(self.url and (self.api_key or (self.username and self.password)))

    def _get_auth_headers(self) -> Dict[str, str]:
        """Construct secure authorization header."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        elif self.username and self.password:
            import base64
            auth_str = f"{self.username}:{self.password}"
            b64_val = base64.b64encode(auth_str.encode()).decode()
            headers["Authorization"] = f"Basic {b64_val}"
        return headers

    async def test_connection(self) -> Dict[str, Any]:
        """Verify cluster connection, health, and version."""
        if not self.is_configured:
            return {
                "status": "unconfigured",
                "message": "Elasticsearch URL and credentials not configured.",
                "timestamp": datetime.utcnow().isoformat()
            }
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(self.url, headers=self._get_auth_headers())
                resp.raise_for_status()
                data = resp.json()
                return {
                    "status": "connected",
                    "cluster_name": data.get("cluster_name"),
                    "version": data.get("version", {}).get("number"),
                    "timestamp": datetime.utcnow().isoformat()
                }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Elasticsearch connection check failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat()
            }

    async def execute_safe_search(
        self,
        query_dsl: Dict[str, Any],
        index: Optional[str] = None,
        max_size: int = 100
    ) -> Dict[str, Any]:
        """Execute validated and resource-bounded query against Elasticsearch."""
        if not self.is_configured:
            return {"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}

        target_index = index or self.index_pattern
        url = f"{self.url}/{target_index}/_search"

        # Enforce safety constraints
        bounded_dsl = query_dsl.copy()
        bounded_dsl["size"] = min(bounded_dsl.get("size", max_size), max_size)

        async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
            resp = await client.post(url, json=bounded_dsl, headers=self._get_auth_headers())
            if resp.status_code == 403:
                raise PermissionError("Elasticsearch 403: Read permission denied on requested index.")
            resp.raise_for_status()
            return resp.json()

    async def search_ioc(
        self,
        ioc_value: str,
        ioc_type: str,
        time_range: str = "now-7d",
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Search SIEM events and alerts across Elastic Common Schema (ECS) fields."""
        if not self.is_configured:
            return []

        clean_val = ioc_value.strip()

        # Build ECS-compliant must/should queries based on indicator type
        match_clauses = []
        if ioc_type == "ip":
            match_clauses = [
                {"term": {"source.ip": clean_val}},
                {"term": {"destination.ip": clean_val}},
                {"term": {"client.ip": clean_val}},
                {"term": {"server.ip": clean_val}},
                {"term": {"network.forwarded_ip": clean_val}}
            ]
        elif ioc_type in ("sha256", "md5"):
            field = "process.hash.sha256" if ioc_type == "sha256" else "process.hash.md5"
            file_field = "file.hash.sha256" if ioc_type == "sha256" else "file.hash.md5"
            match_clauses = [
                {"term": {field: clean_val.lower()}},
                {"term": {file_field: clean_val.lower()}}
            ]
        elif ioc_type == "domain":
            match_clauses = [
                {"term": {"dns.question.name": clean_val.lower()}},
                {"term": {"destination.domain": clean_val.lower()}},
                {"term": {"url.domain": clean_val.lower()}}
            ]
        elif ioc_type == "url":
            match_clauses = [
                {"match_phrase": {"url.original": clean_val}},
                {"match_phrase": {"url.full": clean_val}}
            ]
        else:
            match_clauses = [{"multi_match": {"query": clean_val, "fields": ["*"]}}]

        dsl = {
            "size": limit,
            "query": {
                "bool": {
                    "should": match_clauses,
                    "minimum_should_match": 1,
                    "filter": [
                        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}]
        }

        raw_result = await self.execute_safe_search(dsl)
        hits = raw_result.get("hits", {}).get("hits", [])
        events = []
        for h in hits:
            src = h.get("_source", {})
            events.append({
                "id": h.get("_id"),
                "index": h.get("_index"),
                "timestamp": src.get("@timestamp"),
                "host": src.get("host", {}).get("name") or src.get("host", {}).get("hostname"),
                "user": src.get("user", {}).get("name"),
                "event_category": src.get("event", {}).get("category"),
                "event_action": src.get("event", {}).get("action"),
                "source_ip": src.get("source", {}).get("ip"),
                "destination_ip": src.get("destination", {}).get("ip"),
                "process_name": src.get("process", {}).get("name"),
                "raw_event": src
            })
        return events

elastic_siem_connector = ElasticSiemConnector()
