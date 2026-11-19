"""End-to-End Acceptance Scenario Test.

Demonstrates:
1. Threat intelligence ingestion & normalization
2. Enterprise asset inventory matching
3. CrowdStrike Falcon & Elastic SIEM telemetry queries
4. Cross-platform correlation & deterministic verdict
5. Multi-agent AI synthesis
6. Automated security notification dispatch
7. Professional report generation (PDF, XLSX, CSV, JSON)
8. Traceability and audit logging
"""

import pytest
from openkai_engine.database import init_db
from openkai_engine.services.threat_intel_service import threat_intel_service
from openkai_engine.services.asset_service import asset_service
from openkai_engine.services.correlation_engine import correlation_engine
from openkai_engine.services.ai_orchestrator import ai_orchestrator
from openkai_engine.services.notification_service import notification_service
from openkai_engine.services.reporting_service import reporting_service

@pytest.mark.asyncio
async def test_end_to_end_threat_investigation():
    # 1. Initialize DB and baseline assets
    await init_db()
    await threat_intel_service.initialize_feeds_table()

    # Seed managed enterprise assets
    dev1 = await asset_service.add_or_update_device({
        "device_id": "DEV-SRV-PROD-01",
        "hostname": "srv-app-prod-01.corp.local",
        "ip_address": "10.0.20.15",
        "os_name": "Linux",
        "os_version": "Ubuntu 22.04 LTS",
        "device_type": "server",
        "department": "Infrastructure",
        "criticality": "critical",
        "is_internet_facing": True
    })

    app1 = await asset_service.add_or_update_application({
        "name": "Windows Remote Desktop Licensing Service",
        "publisher": "Microsoft",
        "version": "10.0.22621",
        "category": "OS Component",
        "risk_level": "critical",
        "business_criticality": "critical"
    })
    await asset_service.map_device_to_app("DEV-SRV-PROD-01", app1.id, "10.0.22621")

    # 2. Ingest Threat Intelligence (CISA KEV CVE)
    sample_kev = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-38077",
                "vendorProject": "Microsoft",
                "product": "Windows Remote Desktop Licensing Service",
                "vulnerabilityName": "Remote Code Execution Vulnerability",
                "dateAdded": "2024-07-16",
                "shortDescription": "Unauthenticated buffer overflow RCE.",
                "requiredAction": "Apply vendor updates immediately."
            }
        ]
    }
    from openkai_engine.connectors.threat_intel.cisa_kev import CisaKevConnector
    kev_conn = CisaKevConnector()
    _, cves, _ = kev_conn.normalize(sample_kev)
    assert len(cves) == 1
    assert cves[0]["id"] == "CVE-2024-38077"

    # Persist the CVE into database so the correlation engine can evaluate it
    from openkai_engine.database import AsyncSessionLocal
    from openkai_engine.models.threat_intel import CVERecord
    async with AsyncSessionLocal() as session:
        cve_obj = await session.get(CVERecord, "CVE-2024-38077")
        if not cve_obj:
            cve_obj = CVERecord(
                id="CVE-2024-38077",
                description=cves[0]["description"],
                affected_vendor=cves[0]["affected_vendor"],
                affected_product=cves[0]["affected_product"],
                is_kev=True,
                has_exploit=True,
                cvss_v3_score=9.8,
                cvss_severity="CRITICAL"
            )
            session.add(cve_obj)
            await session.commit()

    # 3. Execute End-to-End Orchestrated Investigation
    investigation_result = await ai_orchestrator.execute_full_investigation("CVE-2024-38077")

    assert investigation_result is not None
    assert investigation_result["indicator"] == "CVE-2024-38077"
    assert investigation_result["type"] == "cve"
    # Verdict should identify potential or confirmed exposure of the affected device
    assert investigation_result["verdict"] in ("potential_match", "confirmed_match")
    assert investigation_result["affected_devices"] >= 1
    assert investigation_result["risk_score"] >= 65
    assert investigation_result["severity"] in ("high", "critical")

    # 4. Verify Multi-Agent AI Outputs
    ai_analysis = investigation_result["ai_analysis"]
    assert "threat_intelligence_analysis" in ai_analysis
    assert "asset_impact_assessment" in ai_analysis
    assert "executive_summary" in ai_analysis
    assert len(ai_analysis["remediation_actions"]) >= 2

    # 5. Verify Notification Dispatch
    notification_result = await notification_service.dispatch_alert(investigation_result)
    assert isinstance(notification_result, dict)

    # 6. Test Report Generation Across Formats
    json_rep = await reporting_service.generate_json_report(investigation_result)
    assert "report_id" in json_rep

    csv_rep = await reporting_service.generate_csv_report(investigation_result)
    assert "CVE-2024-38077" in csv_rep

    xlsx_bytes = await reporting_service.generate_xlsx_report(investigation_result)
    assert len(xlsx_bytes) > 0

    pdf_bytes = await reporting_service.generate_pdf_report(investigation_result)
    assert len(pdf_bytes) > 0
    assert pdf_bytes.startswith(b"%PDF")

@pytest.mark.asyncio
async def test_ioc_sha256_investigation_scenario():
    """Test investigation of a malicious SHA256 file hash in zero-mock environment."""
    malicious_hash = "c8303f569b9148d2eb9d9b626d7f0fa929d2f6ff94553258ff8a02c3c6f60020"
    inv_result = await ai_orchestrator.execute_full_investigation(malicious_hash)

    assert inv_result["indicator"] == malicious_hash
    assert inv_result["type"] == "sha256"
    assert inv_result["verdict"] in ("no_match_found", "potential_match", "confirmed_match")
    assert "ai_analysis" in inv_result
    assert inv_result["risk_score"] >= 0
