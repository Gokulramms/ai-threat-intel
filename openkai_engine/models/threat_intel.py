"""Threat Intelligence Database Models."""

from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, Index
from openkai_engine.database import Base

class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    source_type = Column(String(50), nullable=False)  # api, rss, json, stix
    url = Column(String(500), nullable=True)
    requires_auth = Column(Boolean, default=False)
    is_enabled = Column(Boolean, default=True)
    status = Column(String(50), default="idle")  # idle, syncing, healthy, error
    records_count = Column(Integer, default=0)
    last_sync_timestamp = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String(500), nullable=False, index=True)
    indicator_type = Column(String(50), nullable=False, index=True)  # ip, domain, url, md5, sha1, sha256
    source = Column(String(100), nullable=False, index=True)
    confidence = Column(Integer, default=50)  # 0 - 100
    severity = Column(String(20), default="medium")  # critical, high, medium, low, info
    malware_family = Column(String(100), nullable=True, index=True)
    threat_actor = Column(String(100), nullable=True, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    tags = Column(JSON, default=list)
    raw_data = Column(JSON, default=dict)

    __table_args__ = (
        Index("idx_indicator_val_type", "value", "indicator_type"),
    )

class CVERecord(Base):
    __tablename__ = "cve_records"

    id = Column(String(50), primary_key=True)  # e.g. CVE-2024-38077
    description = Column(Text, nullable=True)
    cvss_v3_score = Column(Float, nullable=True)
    cvss_severity = Column(String(20), nullable=True)  # CRITICAL, HIGH, MEDIUM, LOW
    cwe_id = Column(String(50), nullable=True)
    affected_vendor = Column(String(100), nullable=True, index=True)
    affected_product = Column(String(100), nullable=True, index=True)
    affected_versions = Column(JSON, default=list)  # list of version constraints
    fixed_versions = Column(JSON, default=list)
    is_kev = Column(Boolean, default=False, index=True)
    has_exploit = Column(Boolean, default=False)
    mitre_techniques = Column(JSON, default=list)
    published_date = Column(DateTime, nullable=True)
    last_modified_date = Column(DateTime, nullable=True)
    raw_data = Column(JSON, default=dict)

class SecurityAdvisory(Base):
    __tablename__ = "security_advisories"

    id = Column(String(100), primary_key=True)  # e.g. CERTIN-2024-001
    source = Column(String(50), nullable=False, index=True)  # cert_in, enisa, uk_ncsc, jpcert, cisa
    title = Column(String(500), nullable=False)
    summary = Column(Text, nullable=True)
    url = Column(String(500), nullable=True)
    published_date = Column(DateTime, nullable=True)
    cves = Column(JSON, default=list)
    iocs = Column(JSON, default=list)
    severity = Column(String(20), default="medium")
    raw_data = Column(JSON, default=dict)

class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    technique_id = Column(String(50), primary_key=True)  # e.g. T1059.001
    name = Column(String(200), nullable=False)
    tactic = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    platforms = Column(JSON, default=list)
    data_sources = Column(JSON, default=list)
    mitigations = Column(JSON, default=list)
