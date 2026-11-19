"""Unit test for Stage 2: Database and Core Models."""

import asyncio
import pytest
from openkai_engine.database import init_db, AsyncSessionLocal
from openkai_engine.models.threat_intel import ThreatIndicator, ThreatFeed
from openkai_engine.models.assets import Device, Application
from openkai_engine.core.security import hash_password, verify_password, create_access_token, decode_access_token

@pytest.mark.asyncio
async def test_database_and_security():
    # 1. Initialize tables
    await init_db()

    # 2. Test password hash & verification
    raw_pass = "TestPassword@123"
    hashed = hash_password(raw_pass)
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPassword", hashed) is False

    # 3. Test JWT token generation and decoding
    token = create_access_token({"sub": "analyst1", "role": "security_analyst"})
    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "analyst1"
    assert decoded["role"] == "security_analyst"

    # 4. Test database session insertion
    async with AsyncSessionLocal() as session:
        feed = await session.get(ThreatFeed, "cisa_kev")
        if not feed:
            feed = ThreatFeed(
                id="cisa_kev",
                name="CISA Known Exploited Vulnerabilities",
                source_type="json",
                url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                status="healthy"
            )
            session.add(feed)

        from sqlalchemy import select
        res_dev = await session.execute(select(Device).where(Device.device_id == "DEV-SRV-STAGE2"))
        device = res_dev.scalars().first()
        if not device:
            device = Device(
                device_id="DEV-SRV-STAGE2",
                hostname="corp-ad-01.internal",
                ip_address="10.0.10.5",
                criticality="critical",
                is_internet_facing=False
            )
            session.add(device)
        await session.commit()

    # 5. Verify retrieval
    async with AsyncSessionLocal() as session:
        retrieved_feed = await session.get(ThreatFeed, "cisa_kev")
        assert retrieved_feed is not None
        assert retrieved_feed.name == "CISA Known Exploited Vulnerabilities"
