from dataclasses import dataclass, field
from enum import Enum


class IndicatorType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    PHONE_NUMBER = "phone_number"
    UPI_ID = "upi_id"

@dataclass
class IndicatorSource:
    investigation_id: str
    module: str

@dataclass
class SharedIndicator:
    indicator_type: IndicatorType
    value: str
    sources: list[IndicatorSource] = field(default_factory=list)

@dataclass
class InvestigationRelationship:
    investigation_ids: tuple[str, str]
    shared_indicators: list[SharedIndicator] = field(default_factory=list)

@dataclass
class ThreatCorrelationResult:
    relationships: list[InvestigationRelationship] = field(default_factory=list)