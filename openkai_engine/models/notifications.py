"""Notification Channels and Dispatch History Models."""

from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, JSON, Index
from openkai_engine.database import Base

class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    channel_type = Column(String(50), nullable=False)  # slack, teams, discord, email
    destination = Column(String(500), nullable=False)  # webhook url or email address
    is_enabled = Column(Boolean, default=True)
    min_severity = Column(String(20), default="medium")  # critical, high, medium, low
    created_at = Column(DateTime, default=datetime.utcnow)

class AlertDispatchLog(Base):
    __tablename__ = "alert_dispatch_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    investigation_id = Column(String(50), nullable=True, index=True)
    channel_type = Column(String(50), nullable=False)
    title = Column(String(250), nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(50), default="sent")  # sent, failed, suppressed
    message_payload = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    sent_at = Column(DateTime, default=datetime.utcnow)
