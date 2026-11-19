"""Investigation, Evidence, and Reporting Database Models."""

from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index
from openkai_engine.database import Base

class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(50), primary_key=True)  # e.g. INV-2026-0001
    title = Column(String(250), nullable=False)
    trigger_type = Column(String(50), nullable=False)  # ioc, cve, advisory, alert, manual
    trigger_value = Column(String(500), nullable=False, index=True)
    status = Column(String(50), default="completed")  # pending, running, completed, failed
    risk_score = Column(Integer, default=0)  # 0 - 100
    severity = Column(String(20), default="low")  # critical, high, medium, low, info
    confidence = Column(Integer, default=50)  # 0 - 100
    verdict = Column(String(50), default="no_match_found")  # confirmed_match, potential_match, no_match_found, unable_to_verify
    conclusion_summary = Column(Text, nullable=True)
    technical_analysis = Column(Text, nullable=True)
    recommended_actions = Column(JSON, default=list)
    mitre_mappings = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, default=datetime.utcnow)

class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(50), ForeignKey("investigations.id"), nullable=False, index=True)
    source = Column(String(100), nullable=False)  # crowdstrike, elastic, threat_intel, asset_inventory
    evidence_type = Column(String(100), nullable=False)  # process, network, file_hash, auth, alert, endpoint, app
    description = Column(Text, nullable=False)
    confidence = Column(Integer, default=50)
    raw_data = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=datetime.utcnow)

class CorrelationFinding(Base):
    __tablename__ = "correlation_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(50), ForeignKey("investigations.id"), nullable=False, index=True)
    correlation_type = Column(String(50), nullable=False)  # affected_device, affected_app, edr_detection, siem_event
    entity_id = Column(String(100), nullable=False)
    entity_name = Column(String(200), nullable=False)
    match_confidence = Column(Integer, default=100)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

class GeneratedReport(Base):
    __tablename__ = "generated_reports"

    id = Column(String(50), primary_key=True)  # e.g. REP-2026-0001
    investigation_id = Column(String(50), ForeignKey("investigations.id"), nullable=True, index=True)
    title = Column(String(250), nullable=False)
    report_type = Column(String(50), default="investigation")  # executive, technical, ioc, vulnerability, siem
    format = Column(String(20), default="json")  # json, pdf, csv, xlsx
    content = Column(Text, nullable=True)
    metadata_info = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
