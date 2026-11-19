"""Pydantic Schemas for Threat Intelligence and System Entities."""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class IndicatorCreate(BaseModel):
    value: str
    indicator_type: str  # ip, domain, url, md5, sha1, sha256
    source: str
    confidence: int = Field(default=50, ge=0, le=100)
    severity: str = "medium"
    malware_family: Optional[str] = None
    threat_actor: Optional[str] = None
    tags: List[str] = []
    raw_data: Dict[str, Any] = {}

class IndicatorOut(IndicatorCreate):
    id: int
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True

class CVECreate(BaseModel):
    id: str  # CVE-YYYY-NNNNN
    description: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cwe_id: Optional[str] = None
    affected_vendor: Optional[str] = None
    affected_product: Optional[str] = None
    affected_versions: List[str] = []
    fixed_versions: List[str] = []
    is_kev: bool = False
    has_exploit: bool = False
    mitre_techniques: List[str] = []
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    raw_data: Dict[str, Any] = {}

class CVESchemaOut(CVECreate):
    class Config:
        from_attributes = True

class DeviceCreate(BaseModel):
    device_id: str
    hostname: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    device_type: str = "workstation"
    owner: Optional[str] = None
    department: Optional[str] = None
    business_unit: Optional[str] = None
    criticality: str = "medium"
    falcon_agent_id: Optional[str] = None
    falcon_status: str = "normal"
    security_status: str = "healthy"
    is_internet_facing: bool = False

class DeviceOut(DeviceCreate):
    id: int
    last_seen: datetime
    created_at: datetime

    class Config:
        from_attributes = True

class ApplicationCreate(BaseModel):
    name: str
    publisher: Optional[str] = None
    version: Optional[str] = None
    category: str = "general"
    risk_level: str = "low"
    business_criticality: str = "medium"
    owner: Optional[str] = None
    end_of_life: bool = False
    known_cves: List[str] = []

class ApplicationOut(ApplicationCreate):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True

class InvestigationCreate(BaseModel):
    trigger_type: str  # ioc, cve, advisory, alert, manual
    trigger_value: str
    title: Optional[str] = None

class InvestigationSummary(BaseModel):
    id: str
    title: str
    trigger_type: str
    trigger_value: str
    status: str
    risk_score: int
    severity: str
    confidence: int
    verdict: str
    conclusion_summary: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True
