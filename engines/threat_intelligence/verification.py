import hashlib

from .database import get_report_version
from .blockchain import get_registered_report


def verify_report(report_id: str, version: int | None = None) -> dict:
    stored_report = get_report_version(report_id, version)

    if stored_report is None:
        return {"report_id": report_id, "verified": False, "reason": "Report not found locally."}

    calculated_hash = hashlib.sha256(stored_report["report_json"].encode("utf-8")).hexdigest()

    try:
        blockchain_record = get_registered_report(report_id, stored_report["version"])
    except Exception:
        return {"report_id": report_id, "version": stored_report["version"], "verified": False, "reason": "Report not found on blockchain."}

    registered_hash = blockchain_record["content_hash"].removeprefix("0x").lower()
    verified = calculated_hash == registered_hash

    return {
        "report_id": report_id,
        "version": stored_report["version"],
        "verified": verified,
        "reason": "Report integrity verified against blockchain." if verified else "Report content does not match blockchain record.",
        "content_hash": calculated_hash,
        "blockchain_hash": registered_hash,
        "registered_at": blockchain_record["registered_at"],
        "submitter": blockchain_record["submitter"]
    }
