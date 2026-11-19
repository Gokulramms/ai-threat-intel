"""Threat Intelligence Connectors Registry."""

from typing import Dict, List, Type
from openkai_engine.connectors.base import BaseTIConnector
from openkai_engine.connectors.threat_intel.cisa_kev import CisaKevConnector
from openkai_engine.connectors.threat_intel.nvd import NvdConnector
from openkai_engine.connectors.threat_intel.mitre_attack import MitreAttackConnector
from openkai_engine.connectors.threat_intel.alienvault_otx import AlienVaultOtxConnector
from openkai_engine.connectors.threat_intel.abuseipdb import AbuseIPDBConnector
from openkai_engine.connectors.threat_intel.virustotal import VirusTotalConnector
from openkai_engine.connectors.threat_intel.threatfox import ThreatFoxConnector
from openkai_engine.connectors.threat_intel.urlhaus import URLhausConnector
from openkai_engine.connectors.threat_intel.malwarebazaar import MalwareBazaarConnector
from openkai_engine.connectors.threat_intel.cert_in import CertInConnector
from openkai_engine.connectors.threat_intel.enisa import EnisaConnector
from openkai_engine.connectors.threat_intel.uk_ncsc import UkNcscConnector
from openkai_engine.connectors.threat_intel.jpcert import JpCertConnector
from openkai_engine.connectors.threat_intel.cisa_advisories import CisaAdvisoriesConnector

ALL_TI_CONNECTORS: List[Type[BaseTIConnector]] = [
    CisaKevConnector,
    NvdConnector,
    MitreAttackConnector,
    AlienVaultOtxConnector,
    AbuseIPDBConnector,
    VirusTotalConnector,
    ThreatFoxConnector,
    URLhausConnector,
    MalwareBazaarConnector,
    CertInConnector,
    EnisaConnector,
    UkNcscConnector,
    JpCertConnector,
    CisaAdvisoriesConnector
]

def get_all_connectors() -> Dict[str, BaseTIConnector]:
    """Instantiate and return dictionary of all 14 Threat Intelligence connectors."""
    connectors = {}
    for cls in ALL_TI_CONNECTORS:
        inst = cls()
        connectors[inst.source_id] = inst
    return connectors
