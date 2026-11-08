from core.schema import ThreatReport
from .database import save_report_version, get_report_version, update_blockchain_tx_hash
from .hashing import serialize_report, generate_report_hash
from .blockchain import register_report_on_chain, get_latest_version, get_registered_report


def submit_report(report: ThreatReport) -> dict:
    report_json = serialize_report(report)
    content_hash = generate_report_hash(report)
    version = save_report_version(report.report_id, report.investigation_id, report.created_at, report_json, content_hash)
    stored_version = get_report_version(report.report_id, version)

    if stored_version["blockchain_tx_hash"]:
        return {"report_id": report.report_id, "version": version, "content_hash": content_hash, "blockchain_tx_hash": stored_version["blockchain_tx_hash"]}

    latest_version = get_latest_version(report.report_id)

    if latest_version >= version:
        blockchain_record = get_registered_report(report.report_id, version)
        registered_hash = blockchain_record["content_hash"].removeprefix("0x").lower()

        if registered_hash != content_hash:
            raise RuntimeError("Local report does not match the existing blockchain record.")

        return {"report_id": report.report_id, "version": version, "content_hash": content_hash, "blockchain_tx_hash": None}

    transaction_hash = register_report_on_chain(report.report_id, version, content_hash)
    update_blockchain_tx_hash(report.report_id, version, transaction_hash)

    return {"report_id": report.report_id, "version": version, "content_hash": content_hash, "blockchain_tx_hash": transaction_hash}