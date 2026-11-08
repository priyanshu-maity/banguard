import hashlib

from .database import get_report_version


def verify_report(report_id: str, version: int | None = None) -> dict:
    stored_report = get_report_version(report_id, version)
    if stored_report is None:
        return {"verified": False, "reason": "Report not found."}

    calculated_hash = hashlib.sha256(stored_report["report_json"].encode("utf-8")).hexdigest()
    verified = calculated_hash == stored_report["content_hash"]

    return {
        "report_id": report_id,
        "version": stored_report["version"],
        "verified": verified,
        "reason": "Report integrity verified." if verified else "Report content has been modified."
    }
