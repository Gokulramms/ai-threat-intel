"""Unit Tests for Stage 3: Threat Intelligence Connectors & Normalization."""

import pytest
from openkai_engine.database import init_db
from openkai_engine.services.threat_intel_service import threat_intel_service
from openkai_engine.connectors.threat_intel.cisa_kev import CisaKevConnector
from openkai_engine.connectors.threat_intel.threatfox import ThreatFoxConnector
from openkai_engine.connectors.threat_intel.malwarebazaar import MalwareBazaarConnector

@pytest.mark.asyncio
async def test_threat_intel_connectors_and_normalization():
    await init_db()
    await threat_intel_service.initialize_feeds_table()

    # 1. Test CISA KEV Normalization
    kev_conn = CisaKevConnector()
    sample_kev_data = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-38077",
                "vendorProject": "Microsoft",
                "product": "Windows Remote Desktop Licensing Service",
                "vulnerabilityName": "Remote Code Execution Vulnerability",
                "dateAdded": "2024-07-16",
                "shortDescription": "Buffer overflow leading to unauthenticated RCE.",
                "requiredAction": "Apply vendor updates.",
                "dueDate": "2024-08-06"
            }
        ]
    }
    _, cves, _ = kev_conn.normalize(sample_kev_data)
    assert len(cves) == 1
    assert cves[0]["id"] == "CVE-2024-38077"
    assert cves[0]["is_kev"] is True
    assert cves[0]["affected_vendor"] == "Microsoft"

    # 2. Test ThreatFox Normalization
    tf_conn = ThreatFoxConnector()
    sample_tf_data = {
        "query_status": "ok",
        "data": [
            {
                "id": "12345",
                "ioc": "198.51.100.45:443",
                "threat_type": "botnet_cc",
                "ioc_type": "ip:port",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 90,
                "tags": ["cobalt_strike", "c2"]
            }
        ]
    }
    iocs, _, _ = tf_conn.normalize(sample_tf_data)
    assert len(iocs) == 1
    assert iocs[0]["value"] == "198.51.100.45"
    assert iocs[0]["indicator_type"] == "ip"
    assert iocs[0]["confidence"] == 90
    assert iocs[0]["malware_family"] == "Cobalt Strike"

    # 3. Test MalwareBazaar Normalization
    mb_conn = MalwareBazaarConnector()
    sample_mb_data = {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
                "signature": "LockBit",
                "tags": ["ransomware", "lockbit"]
            }
        ]
    }
    mb_iocs, _, _ = mb_conn.normalize(sample_mb_data)
    assert len(mb_iocs) == 2
    assert any(i["indicator_type"] == "sha256" for i in mb_iocs)
    assert any(i["indicator_type"] == "md5" for i in mb_iocs)

    # 4. Test Service Metrics
    metrics = await threat_intel_service.get_metrics()
    assert "feeds" in metrics
    assert len(metrics["feeds"]) >= 14
