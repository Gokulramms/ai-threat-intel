"""Base Threat Intelligence Connector Interface and Utilities."""

import asyncio
import time
import httpx
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

class BaseTIConnector(ABC):
    """Abstract Base Class for all Threat Intelligence Connectors."""

    def __init__(
        self,
        source_id: str,
        name: str,
        base_url: str,
        auth_required: bool = False,
        api_key: Optional[str] = None,
        rate_limit_delay: float = 0.5,
        max_retries: int = 3,
        timeout: float = 15.0
    ):
        self.source_id = source_id
        self.name = name
        self.base_url = base_url
        self.auth_required = auth_required
        self.api_key = api_key
        self.rate_limit_delay = rate_limit_delay
        self.max_retries = max_retries
        self.timeout = timeout
        self.last_sync_time: Optional[datetime] = None
        self.last_status: str = "initialized"
        self.last_error: Optional[str] = None

    async def _http_get(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> httpx.Response:
        """Execute HTTP GET with rate limiting and retry mechanism."""
        url = endpoint if endpoint.startswith("http") else f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        hdrs = headers or {}
        
        await asyncio.sleep(self.rate_limit_delay)

        for attempt in range(1, self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                    resp = await client.get(url, params=params, headers=hdrs)
                    if resp.status_code == 429:
                        wait_sec = float(resp.headers.get("Retry-After", 2 * attempt))
                        await asyncio.sleep(wait_sec)
                        continue
                    resp.raise_for_status()
                    return resp
            except Exception as e:
                if attempt == self.max_retries:
                    raise e
                await asyncio.sleep(1.0 * attempt)
        raise RuntimeError(f"Failed to fetch {url} after {self.max_retries} attempts.")

    async def _http_post(
        self,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> httpx.Response:
        """Execute HTTP POST with rate limiting and retry."""
        url = endpoint if endpoint.startswith("http") else f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        hdrs = headers or {}

        await asyncio.sleep(self.rate_limit_delay)

        for attempt in range(1, self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                    resp = await client.post(url, json=json_data, headers=hdrs)
                    if resp.status_code == 429:
                        wait_sec = float(resp.headers.get("Retry-After", 2 * attempt))
                        await asyncio.sleep(wait_sec)
                        continue
                    resp.raise_for_status()
                    return resp
            except Exception as e:
                if attempt == self.max_retries:
                    raise e
                await asyncio.sleep(1.0 * attempt)
        raise RuntimeError(f"Failed to POST {url} after {self.max_retries} attempts.")

    @abstractmethod
    async def fetch_feed(self, limit: int = 100) -> Dict[str, Any]:
        """Fetch raw feed data from source."""
        pass

    @abstractmethod
    def normalize(self, raw_data: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Normalize raw items into: (indicators, cves, advisories)."""
        pass

    async def test_connection(self) -> Dict[str, Any]:
        """Verify availability and credentials."""
        if self.auth_required and not self.api_key:
            return {
                "source_id": self.source_id,
                "status": "unconfigured",
                "message": f"API key required for {self.name}",
                "timestamp": datetime.utcnow().isoformat()
            }
        try:
            # Basic health probe
            raw = await self.fetch_feed(limit=5)
            self.last_status = "healthy"
            return {
                "source_id": self.source_id,
                "status": "healthy",
                "message": f"Successfully connected to {self.name}",
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            self.last_status = "error"
            self.last_error = str(e)
            return {
                "source_id": self.source_id,
                "status": "error",
                "message": f"Connection check failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat()
            }
