import os
import base64
import requests
from dotenv import load_dotenv

from .analysis_result import URLAnalysisResult

load_dotenv()


class ThreatIntelligenceAnalyzer:
    VIRUSTOTAL_ENDPOINT = 'https://www.virustotal.com/api/v3/urls'
    TIMEOUT = 10

    def __init__(self, url: str, result: URLAnalysisResult):
        self.url = url
        self.result = result

        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')

    def analyze(self):
        if not self.virustotal_api_key:
            self.result.threat_intelligence_provider_status['virustotal'] = 'not_configured'
            return

        try:
            self._check_virustotal()

        except requests.HTTPError:
            self.result.threat_intelligence_provider_status['virustotal'] = 'error'

        except requests.RequestException:
            self.result.threat_intelligence_provider_status['virustotal'] = 'error'

    def _check_virustotal(self):
        url_id = base64.urlsafe_b64encode(
            self.url.encode('utf-8')
        ).decode('utf-8').rstrip('=')

        headers = {
            'x-apikey': self.virustotal_api_key,
            'accept': 'application/json'
        }

        response = requests.get(
            f'{self.VIRUSTOTAL_ENDPOINT}/{url_id}',
            headers=headers,
            timeout=self.TIMEOUT
        )

        if response.status_code == 404:
            self.result.threat_intelligence_provider_status['virustotal'] = 'no_report'
            return

        response.raise_for_status()

        data = response.json().get('data', {})
        attributes = data.get('attributes', {})

        stats = attributes.get('last_analysis_stats', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)

        self.result.virustotal_malicious = (
            malicious > 0,
            malicious
        )

        self.result.virustotal_suspicious = (
            suspicious > 0,
            suspicious
        )

        self.result.virustotal_harmless_count = harmless
        self.result.virustotal_undetected_count = undetected

        self.result.virustotal_reputation = (
            attributes.get('reputation')
        )

        self.result.virustotal_categories = (
            attributes.get('categories', {})
        )

        self.result.threat_intelligence_provider_status['virustotal'] = 'success'
