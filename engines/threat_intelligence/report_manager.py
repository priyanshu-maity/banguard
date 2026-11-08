from core.schema import ThreatReport
from .database import save_report_version
from .hashing import serialize_report, generate_report_hash


def submit_report(report: ThreatReport) -> dict:
    report_json = serialize_report(report)
    content_hash = generate_report_hash(report)

    version = save_report_version(report.report_id, report.investigation_id, report.created_at, report_json, content_hash)

    return {
        "report_id": report.report_id,
        "version": version,
        "content_hash": content_hash,
    }
