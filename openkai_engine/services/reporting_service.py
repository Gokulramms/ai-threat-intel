"""Professional Report Generation Engine (PDF, XLSX, CSV, JSON)."""

import io
import csv
import json
from datetime import datetime
from typing import Dict, Any, Optional
from openpyxl import Workbook
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from openkai_engine.database import AsyncSessionLocal
from openkai_engine.models.investigations import GeneratedReport

class ReportingService:
    """Generates and exports professional SOC investigation reports."""

    async def generate_json_report(self, investigation: Dict[str, Any]) -> str:
        report_data = {
            "report_id": f"REP-JSON-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "generated_at": datetime.utcnow().isoformat(),
            "investigation": investigation
        }
        return json.dumps(report_data, indent=2)

    async def generate_csv_report(self, investigation: Dict[str, Any]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Field", "Value"])
        writer.writerow(["Investigation ID", investigation.get("investigation_id")])
        writer.writerow(["Target Indicator", investigation.get("indicator")])
        writer.writerow(["Indicator Type", investigation.get("type")])
        writer.writerow(["Verdict", investigation.get("verdict")])
        writer.writerow(["Risk Score", investigation.get("risk_score")])
        writer.writerow(["Severity", investigation.get("severity")])
        writer.writerow(["CrowdStrike Detections", investigation.get("crowdstrike_matches", 0)])
        writer.writerow(["SIEM Historical Events", investigation.get("siem_matches", 0)])
        writer.writerow(["Affected Enterprise Devices", investigation.get("affected_devices", 0)])
        writer.writerow(["Summary", investigation.get("conclusion")])
        return output.getvalue()

    async def generate_xlsx_report(self, investigation: Dict[str, Any]) -> bytes:
        wb = Workbook()
        ws = wb.active
        ws.title = "SOC Investigation Summary"

        headers = ["Investigation ID", "Indicator", "Type", "Verdict", "Risk Score", "Severity", "CS Matches", "SIEM Matches", "Devices Affected"]
        ws.append(headers)
        ws.append([
            investigation.get("investigation_id"),
            investigation.get("indicator"),
            investigation.get("type"),
            investigation.get("verdict"),
            investigation.get("risk_score"),
            investigation.get("severity"),
            investigation.get("crowdstrike_matches", 0),
            investigation.get("siem_matches", 0),
            investigation.get("affected_devices", 0)
        ])

        # Evidence tab
        ws_ev = wb.create_sheet(title="Evidence Log")
        ws_ev.append(["Source", "Type", "Description", "Confidence"])
        for ev in investigation.get("evidence", []):
            ws_ev.append([
                ev.get("source"),
                ev.get("evidence_type"),
                ev.get("description"),
                ev.get("confidence")
            ])

        out = io.BytesIO()
        wb.save(out)
        return out.getvalue()

    async def generate_pdf_report(self, investigation: Dict[str, Any]) -> bytes:
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter

        # Header banner
        p.setFont("Helvetica-Bold", 18)
        p.drawString(50, height - 50, "OpenKai Enterprise SOC Investigation Report")
        p.setStrokeColorRGB(0.1, 0.2, 0.4)
        p.line(50, height - 60, width - 50, height - 60)

        # Meta Information
        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, height - 85, f"Investigation ID: {investigation.get('investigation_id')}")
        p.setFont("Helvetica", 10)
        p.drawString(350, height - 85, f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

        p.drawString(50, height - 110, f"Target: {investigation.get('indicator')} ({investigation.get('type', '').upper()})")
        p.drawString(50, height - 130, f"Verdict: {investigation.get('verdict', '').upper()}")
        p.drawString(50, height - 150, f"Overall Risk Score: {investigation.get('risk_score')}/100 ({investigation.get('severity', '').upper()})")

        # Telemetry counts
        p.drawString(50, height - 180, f"CrowdStrike Detections: {investigation.get('crowdstrike_matches', 0)}")
        p.drawString(220, height - 180, f"SIEM Log Matches: {investigation.get('siem_matches', 0)}")
        p.drawString(380, height - 180, f"Affected Enterprise Devices: {investigation.get('affected_devices', 0)}")

        # Summary box
        p.setFont("Helvetica-Bold", 12)
        p.drawString(50, height - 215, "Executive & Technical Conclusion:")
        p.setFont("Helvetica", 9)
        text_object = p.beginText(50, height - 235)
        text_object.setFont("Helvetica", 9)
        conclusion_text = investigation.get("conclusion", "")
        # Basic word wrap
        words = conclusion_text.split()
        line = ""
        for w in words:
            if len(line) + len(w) > 85:
                text_object.textLine(line)
                line = w + " "
            else:
                line += w + " "
        if line:
            text_object.textLine(line)
        p.drawText(text_object)

        # Footer
        p.setFont("Helvetica-Oblique", 8)
        p.drawString(50, 40, "Confidential - OpenKai AI Security Operations - Not for public dissemination")
        p.showPage()
        p.save()

        buffer.seek(0)
        return buffer.getvalue()

reporting_service = ReportingService()
