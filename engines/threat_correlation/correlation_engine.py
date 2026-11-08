from core.schema import AnalysisResult, AnalysisStatus
from .database import find_matching_investigations, save_investigation
from .indicator_extractor import extract_indicators
from .schema import IndicatorType, IndicatorSource, SharedIndicator, InvestigationRelationship, ThreatCorrelationResult


def correlate_investigation(investigation_id: str, original_url: str, m1_result=None, m2_result=None, m3_result=None, m5_result=None) -> AnalysisResult[ThreatCorrelationResult]:

    try:
        indicators = extract_indicators(investigation_id, original_url, m1_result, m2_result, m3_result, m5_result)
        matches = find_matching_investigations(indicators, investigation_id)
        grouped_matches = {}
        current_indicators = {(indicator.indicator_type, indicator.value): indicator for indicator in indicators}

        for match in matches:
            previous_id = match["investigation_id"]
            indicator_type = IndicatorType(match["indicator_type"])
            value = match["value"]
            key = (indicator_type, value)

            current_indicator = current_indicators.get(key)

            if current_indicator is None:
                continue

            if previous_id not in grouped_matches:
                grouped_matches[previous_id] = {}

            if key not in grouped_matches[previous_id]:
                grouped_matches[previous_id][key] = SharedIndicator(indicator_type=indicator_type, value=value)

            shared_indicator = grouped_matches[previous_id][key]
            sources = [IndicatorSource(previous_id, match["source_module"]), *current_indicator.sources]

            for source in sources:
                if source not in shared_indicator.sources:
                    shared_indicator.sources.append(source)

        relationships = [
            InvestigationRelationship(investigation_ids=(previous_id, investigation_id), shared_indicators=list(shared_indicators.values()))
            for previous_id, shared_indicators in grouped_matches.items()
        ]
        save_investigation(investigation_id, original_url, indicators)

        return AnalysisResult(investigation_id=investigation_id, module="M4", status=AnalysisStatus.COMPLETED, data=ThreatCorrelationResult(relationships=relationships))

    except Exception as error:
        return AnalysisResult(investigation_id=investigation_id, module="M4", status=AnalysisStatus.FAILED, error=str(error))
