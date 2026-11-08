from core.schema import ThreatReport
from .database import save_report_version, update_blockchain_tx_hash
from .hashing import serialize_report, generate_report_hash
from .blockchain import register_report_on_chain


def submit_report(report: ThreatReport) -> dict:
    report_json = serialize_report(report)
    content_hash = generate_report_hash(report)

    version = save_report_version(report.report_id, report.investigation_id, report.created_at, report_json, content_hash)
    transaction_hash = register_report_on_chain(report.report_id, version, content_hash)
    update_blockchain_tx_hash(report.report_id, version, transaction_hash)

    return {"report_id": report.report_id, "version": version, "content_hash": content_hash, "blockchain_tx_hash": transaction_hash}
