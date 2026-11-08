import hashlib
import json
from dataclasses import asdict
from enum import Enum

from core.schema import ThreatReport


def _serialize_value(value):
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"Unsupported type: {type(value).__name__}")

def serialize_report(report: ThreatReport) -> str:
    report_data = asdict(report)
    return json.dumps(report_data, default=_serialize_value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

