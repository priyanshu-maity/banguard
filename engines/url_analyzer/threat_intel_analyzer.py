import os
import time
import base64
import logging

import requests
from dotenv import load_dotenv

from .analysis_result import URLAnalysisResult

load_dotenv()

logger = logging.getLogger(__name__)


class ThreatIntelligenceAnalyzer:
    VIRUSTOTAL_BASE = 'https://www.virustotal.com/api/v3'
    VIRUSTOTAL_URLS = f'{VIRUSTOTAL_BASE}/urls'
    VIRUSTOTAL_ANALYSES = f'{VIRUSTOTAL_BASE}/analyses'

    TIMEOUT = 10
    POLL_ATTEMPTS = 6        # total wait is roughly POLL_ATTEMPTS * POLL_INTERVAL seconds
    POLL_INTERVAL = 3

    def __init__(self, url: str, result: URLAnalysisResult):
        self.url = url
        self.result = result

        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')

    def analyze(self):
        if not self.virustotal_api_key:
            self._set_status('not_configured')
            return

        try:
            self._check_virustotal()

        except requests.RequestException as error:
            logger.warning('VirusTotal request failed for %s: %r', self.url, error)
            self._set_status('error')

        except (KeyError, ValueError, TypeError) as error:
            logger.warning('VirusTotal returned an unexpected response for %s: %r', self.url, error)
            self._set_status('error')

    def _set_status(self, status: str):
        self.result.threat_intelligence_provider_status['virustotal'] = status

    @property
    def _headers(self) -> dict[str, str]:
        return {
            'x-apikey': self.virustotal_api_key,
            'accept': 'application/json'
        }

    def _url_id(self) -> str:
        return base64.urlsafe_b64encode(
            self.url.encode('utf-8')
        ).decode('utf-8').rstrip('=')

    def _get_report(self) -> requests.Response:
        return requests.get(
            f'{self.VIRUSTOTAL_URLS}/{self._url_id()}',
            headers=self._headers,
            timeout=self.TIMEOUT
        )

    def _check_virustotal(self):
        response = self._get_report()

        # 404 means VirusTotal has never seen this URL, so submit it for scanning
        if response.status_code == 404:
            if not self._submit_and_wait():
                self._set_status('no_report')
                return

            response = self._get_report()

            if response.status_code == 404:
                self._set_status('no_report')
                return

        if not response.ok:
            logger.warning(
                'VirusTotal returned HTTP %s for %s: %s',
                response.status_code,
                self.url,
                response.text[:300]
            )
            self._set_status('error')
            return

        self._parse_report(response.json())

    def _submit_and_wait(self) -> bool:
        submit = requests.post(
            self.VIRUSTOTAL_URLS,
            headers=self._headers,
            data={'url': self.url},
            timeout=self.TIMEOUT
        )

        if not submit.ok:
            logger.warning(
                'VirusTotal URL submission returned HTTP %s: %s',
                submit.status_code,
                submit.text[:300]
            )
            raise requests.HTTPError(
                f'VirusTotal submission failed with HTTP {submit.status_code}',
                response=submit
            )

        analysis_id = submit.json()['data']['id']

        for _ in range(self.POLL_ATTEMPTS):
            time.sleep(self.POLL_INTERVAL)

            analysis = requests.get(
                f'{self.VIRUSTOTAL_ANALYSES}/{analysis_id}',
                headers=self._headers,
                timeout=self.TIMEOUT
            )

            if not analysis.ok:
                logger.warning(
                    'VirusTotal analysis poll returned HTTP %s: %s',
                    analysis.status_code,
                    analysis.text[:300]
                )
                raise requests.HTTPError(
                    f'VirusTotal analysis poll failed with HTTP {analysis.status_code}',
                    response=analysis
                )

            status = analysis.json()['data']['attributes']['status']

            if status == 'completed':
                return True

        logger.info('VirusTotal analysis did not complete in time for %s', self.url)
        return False

    def _parse_report(self, payload: dict):
        data = payload.get('data', {})
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

        self.result.virustotal_reputation = attributes.get('reputation')
        self.result.virustotal_categories = attributes.get('categories', {})

        self._set_status('success')