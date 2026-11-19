"""Report Generation and Export API Routes."""

from fastapi import APIRouter, Response, HTTPException
from openkai_engine.services.reporting_service import reporting_service
from openkai_engine.services.correlation_engine import correlation_engine

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.get("/export/{inv_id}")
async def export_report(inv_id: str, format: str = "json"):
    """Export investigation report in JSON, CSV, XLSX, or PDF."""
    from openkai_engine.api.routes_investigations import get_investigation_details
    data = await get_investigation_details(inv_id)

    actual_id = data["investigation"]["id"]
    inv_summary = {
        "investigation_id": actual_id,
        "indicator": data["investigation"]["trigger_value"],
        "type": data["investigation"]["trigger_type"],
        "verdict": data["investigation"]["verdict"],
        "risk_score": data["investigation"]["risk_score"],
        "severity": data["investigation"]["severity"],
        "conclusion": data["investigation"]["conclusion"],
        "evidence": data["evidence"],
        "findings": data["findings"]
    }

    fmt = format.lower()
    if fmt == "json":
        json_str = await reporting_service.generate_json_report(inv_summary)
        return Response(content=json_str, media_type="application/json")
    elif fmt == "csv":
        csv_str = await reporting_service.generate_csv_report(inv_summary)
        return Response(
            content=csv_str,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={actual_id}.csv"}
        )
    elif fmt == "xlsx":
        xlsx_bytes = await reporting_service.generate_xlsx_report(inv_summary)
        return Response(
            content=xlsx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={actual_id}.xlsx"}
        )
    elif fmt == "pdf":
        pdf_bytes = await reporting_service.generate_pdf_report(inv_summary)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={actual_id}.pdf"}
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Supported: json, csv, xlsx, pdf")
