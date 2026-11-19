"""Enterprise Cross-Platform Security Correlation Engine."""

import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import select
from openkai_engine.database import AsyncSessionLocal
from openkai_engine.models.threat_intel import ThreatIndicator, CVERecord
from openkai_engine.models.assets import Device, Application, DeviceApplicationMap
from openkai_engine.models.investigations import Investigation, EvidenceRecord, CorrelationFinding
from openkai_engine.connectors.crowdstrike import crowdstrike_connector
from openkai_engine.connectors.elastic import elastic_siem_connector
from openkai_engine.services.asset_service import asset_service

class CorrelationEngine:
    """Correlates Threat Intelligence against CrowdStrike, Elastic SIEM, and Enterprise Assets."""

    def detect_indicator_type(self, value: str) -> str:
        """Deterministically determine if value is CVE, IP, SHA256, MD5, URL, or Domain."""
        val = value.strip()
        if re.match(r"^CVE-\d{4}-\d{4,}$", val, re.IGNORECASE):
            return "cve"
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
            return "ip"
        if re.match(r"^[a-fA-F0-9]{64}$", val):
            return "sha256"
        if re.match(r"^[a-fA-F0-9]{32}$", val):
            return "md5"
        if val.startswith("http://") or val.startswith("https://"):
            return "url"
        return "domain"

    async def investigate_indicator(self, value: str, user_id: str = "system") -> Dict[str, Any]:
        """Perform full cross-platform investigation on a threat indicator or CVE."""
        clean_val = value.strip()
        ind_type = self.detect_indicator_type(clean_val)
        inv_id = f"INV-{datetime.utcnow().strftime('%Y%m%d')}-{abs(hash(clean_val)) % 10000:04d}"

        evidence_list: List[Dict[str, Any]] = []
        correlation_findings: List[Dict[str, Any]] = []

        ti_confidence = 50
        ti_severity = "medium"
        is_kev = False
        malware_family = None
        cve_details = None

        # 1. Threat Intelligence Database Query
        async with AsyncSessionLocal() as session:
            if ind_type == "cve":
                cve_res = await session.get(CVERecord, clean_val.upper())
                if cve_res:
                    is_kev = cve_res.is_kev
                    ti_severity = (cve_res.cvss_severity or "high").lower()
                    cve_details = {
                        "cve_id": cve_res.id,
                        "description": cve_res.description,
                        "cvss": cve_res.cvss_v3_score,
                        "vendor": cve_res.affected_vendor,
                        "product": cve_res.affected_product,
                        "is_kev": cve_res.is_kev
                    }
                    evidence_list.append({
                        "source": "threat_intel",
                        "evidence_type": "cve_intelligence",
                        "description": f"Identified in Threat Intel database: {cve_res.id} (CVSS: {cve_res.cvss_v3_score}, KEV: {cve_res.is_kev})",
                        "confidence": 95,
                        "raw_data": cve_details
                    })
            else:
                stmt = select(ThreatIndicator).where(ThreatIndicator.value == clean_val)
                ind_res = (await session.execute(stmt)).scalars().first()
                if ind_res:
                    ti_confidence = ind_res.confidence
                    ti_severity = ind_res.severity
                    malware_family = ind_res.malware_family
                    evidence_list.append({
                        "source": "threat_intel",
                        "evidence_type": "ioc_intelligence",
                        "description": f"Known malicious indicator: Source {ind_res.source}, Severity {ind_res.severity}, Malware: {malware_family or 'Unclassified'}",
                        "confidence": ind_res.confidence,
                        "raw_data": {"source": ind_res.source, "tags": ind_res.tags}
                    })

        # 2. CrowdStrike Falcon EDR Investigation
        cs_matches = []
        try:
            if ind_type != "cve":
                cs_matches = await crowdstrike_connector.search_ioc(clean_val, ind_type)
                for match in cs_matches:
                    evidence_list.append({
                        "source": "crowdstrike",
                        "evidence_type": "edr_detection",
                        "description": f"CrowdStrike Falcon Detection: {match.get('match_reason')} on host {match.get('hostname')}",
                        "confidence": 95,
                        "raw_data": match
                    })
                    correlation_findings.append({
                        "correlation_type": "edr_detection",
                        "entity_id": match.get("device_id") or "unknown",
                        "entity_name": match.get("hostname") or "unknown",
                        "match_confidence": 95,
                        "details": match
                    })
        except Exception as e:
            evidence_list.append({
                "source": "crowdstrike",
                "evidence_type": "api_error",
                "description": f"CrowdStrike query failed: {str(e)}",
                "confidence": 0,
                "raw_data": {"error": str(e)}
            })

        # 3. Elastic SIEM Historical Log Investigation
        siem_events = []
        try:
            if ind_type != "cve":
                siem_events = await elastic_siem_connector.search_ioc(clean_val, ind_type)
                for event in siem_events:
                    evidence_list.append({
                        "source": "elastic_siem",
                        "evidence_type": "siem_telemetry",
                        "description": f"SIEM Log Match: {event.get('event_category')} / {event.get('event_action')} on host {event.get('host')}",
                        "confidence": 90,
                        "raw_data": event
                    })
                    correlation_findings.append({
                        "correlation_type": "siem_event",
                        "entity_id": event.get("id") or "event",
                        "entity_name": event.get("host") or "unknown_host",
                        "match_confidence": 90,
                        "details": event
                    })
        except Exception as e:
            evidence_list.append({
                "source": "elastic_siem",
                "evidence_type": "api_error",
                "description": f"Elastic SIEM search failed: {str(e)}",
                "confidence": 0,
                "raw_data": {"error": str(e)}
            })

        # 4. Enterprise Asset & Application Correlation
        affected_devices = []
        affected_apps = []
        if ind_type == "cve" and cve_details:
            asset_matches = await asset_service.find_affected_assets_for_cve(
                clean_val,
                vendor=cve_details.get("vendor"),
                product=cve_details.get("product")
            )
            affected_devices = asset_matches.get("devices", [])
            affected_apps = asset_matches.get("applications", [])

            for dev in affected_devices:
                evidence_list.append({
                    "source": "asset_inventory",
                    "evidence_type": "vulnerable_device",
                    "description": f"Device {dev.get('hostname')} ({dev.get('ip_address')}) runs vulnerable software matching {clean_val}",
                    "confidence": 85,
                    "raw_data": dev
                })
                correlation_findings.append({
                    "correlation_type": "affected_device",
                    "entity_id": dev.get("device_id"),
                    "entity_name": dev.get("hostname"),
                    "match_confidence": 85,
                    "details": dev
                })
        else:
            # Check if any enterprise device matches this IP address directly
            if ind_type == "ip":
                async with AsyncSessionLocal() as session:
                    stmt = select(Device).where(Device.ip_address == clean_val)
                    dev_match = (await session.execute(stmt)).scalars().first()
                    if dev_match:
                        evidence_list.append({
                            "source": "asset_inventory",
                            "evidence_type": "endpoint_identity",
                            "description": f"IP {clean_val} matches managed enterprise device: {dev_match.hostname} ({dev_match.department})",
                            "confidence": 100,
                            "raw_data": {"device_id": dev_match.device_id, "hostname": dev_match.hostname}
                        })
                        correlation_findings.append({
                            "correlation_type": "affected_device",
                            "entity_id": dev_match.device_id,
                            "entity_name": dev_match.hostname,
                            "match_confidence": 100,
                            "details": {"criticality": dev_match.criticality}
                        })

        # 5. Deterministic Verdict Classification
        if cs_matches or (siem_events and any(e.get("host") for e in siem_events)):
            verdict = "confirmed_match"
        elif affected_devices or affected_apps:
            verdict = "potential_match"
        elif evidence_list and any(ev.get("confidence", 0) > 0 for ev in evidence_list):
            verdict = "no_match_found"
        else:
            verdict = "unable_to_verify"

        # 6. Risk Score Calculation (0 - 100)
        risk_score = 0
        if verdict == "confirmed_match":
            risk_score = 85
        elif verdict == "potential_match":
            risk_score = 65
        elif is_kev:
            risk_score = 70
        elif ti_severity == "critical":
            risk_score = 60
        elif ti_severity == "high":
            risk_score = 45
        else:
            risk_score = 25

        # Criticality additions
        for dev in affected_devices:
            if dev.get("criticality") == "critical":
                risk_score = min(100, risk_score + 15)
                break
            elif dev.get("is_internet_facing"):
                risk_score = min(100, risk_score + 10)
                break

        final_severity = "low"
        if risk_score >= 80:
            final_severity = "critical"
        elif risk_score >= 60:
            final_severity = "high"
        elif risk_score >= 40:
            final_severity = "medium"

        conclusion = (
            f"Cross-Platform Investigation of {clean_val} concluded with verdict: '{verdict.upper()}'. "
            f"Observed {len(cs_matches)} CrowdStrike EDR detections, {len(siem_events)} SIEM historical events, "
            f"and {len(affected_devices)} affected enterprise devices. Overall Risk Score: {risk_score}/100 ({final_severity.upper()})."
        )

        # 7. Persist Investigation and Evidence
        async with AsyncSessionLocal() as session:
            inv = Investigation(
                id=inv_id,
                title=f"Investigation: {clean_val} ({ind_type.upper()})",
                trigger_type=ind_type,
                trigger_value=clean_val,
                status="completed",
                risk_score=risk_score,
                severity=final_severity,
                confidence=max(ti_confidence, 80 if verdict == "confirmed_match" else 50),
                verdict=verdict,
                conclusion_summary=conclusion,
                mitre_mappings=["T1059", "T1078"] if cs_matches else [],
                created_at=datetime.utcnow(),
                completed_at=datetime.utcnow()
            )
            session.add(inv)

            for ev in evidence_list:
                ev_record = EvidenceRecord(
                    investigation_id=inv_id,
                    source=ev["source"],
                    evidence_type=ev["evidence_type"],
                    description=ev["description"],
                    confidence=ev.get("confidence", 50),
                    raw_data=ev.get("raw_data", {})
                )
                session.add(ev_record)

            for cf in correlation_findings:
                corr_record = CorrelationFinding(
                    investigation_id=inv_id,
                    correlation_type=cf["correlation_type"],
                    entity_id=cf["entity_id"],
                    entity_name=cf["entity_name"],
                    match_confidence=cf.get("match_confidence", 100),
                    details=cf.get("details", {})
                )
                session.add(corr_record)

            await session.commit()

        return {
            "investigation_id": inv_id,
            "indicator": clean_val,
            "type": ind_type,
            "verdict": verdict,
            "risk_score": risk_score,
            "severity": final_severity,
            "conclusion": conclusion,
            "evidence_count": len(evidence_list),
            "crowdstrike_matches": len(cs_matches),
            "siem_matches": len(siem_events),
            "affected_devices": len(affected_devices),
            "evidence": evidence_list,
            "findings": correlation_findings
        }

correlation_engine = CorrelationEngine()
