"""Enterprise Asset, Device, Application, and Infrastructure Inventory Models."""

from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index
from openkai_engine.database import Base

class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(100), unique=True, nullable=False, index=True)
    hostname = Column(String(200), nullable=False, index=True)
    ip_address = Column(String(50), nullable=True, index=True)
    mac_address = Column(String(50), nullable=True)
    os_name = Column(String(100), nullable=True)
    os_version = Column(String(100), nullable=True)
    device_type = Column(String(50), default="workstation")  # workstation, server, laptop, virtual, mobile
    owner = Column(String(150), nullable=True)
    department = Column(String(100), nullable=True, index=True)
    business_unit = Column(String(100), nullable=True)
    criticality = Column(String(20), default="medium")  # critical, high, medium, low
    falcon_agent_id = Column(String(100), nullable=True, index=True)
    falcon_status = Column(String(50), default="unknown")  # normal, quarantined, inactive, not_installed
    last_seen = Column(DateTime, default=datetime.utcnow)
    security_status = Column(String(50), default="healthy")  # healthy, at_risk, compromised, vulnerable
    is_internet_facing = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False, index=True)
    publisher = Column(String(200), nullable=True, index=True)
    version = Column(String(100), nullable=True)
    category = Column(String(100), default="general")
    risk_level = Column(String(20), default="low")  # critical, high, medium, low
    business_criticality = Column(String(20), default="medium")
    owner = Column(String(150), nullable=True)
    end_of_life = Column(Boolean, default=False)
    known_cves = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)

class DeviceApplicationMap(Base):
    __tablename__ = "device_application_map"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(100), nullable=False, index=True)
    application_id = Column(Integer, nullable=False, index=True)
    installed_version = Column(String(100), nullable=True)
    install_path = Column(String(500), nullable=True)
    installed_date = Column(DateTime, default=datetime.utcnow)

class InfrastructureAsset(Base):
    __tablename__ = "infrastructure_assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False, index=True)
    asset_type = Column(String(50), nullable=False)  # firewall, router, switch, cloud_account, cloud_workload, database, container
    ip_address = Column(String(50), nullable=True, index=True)
    cloud_provider = Column(String(50), nullable=True)  # aws, azure, gcp, on-prem
    region = Column(String(50), nullable=True)
    criticality = Column(String(20), default="medium")
    status = Column(String(50), default="active")
    attributes = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
