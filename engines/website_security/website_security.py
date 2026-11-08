import logging

from core.fetch_redirect_chain import FetchError
from core.network_safety import NonPublicAddressError, ResolutionError
from core.schema import AnalysisResult, AnalysisStatus
from header_inspector import HeaderInspector
from page_fetcher import PageFetcher
from target_resolver import InvalidTargetError, TargetResolver
from website_security_result import WebsiteSecurityResult

logger = logging.getLogger(__name__)


class WebsiteSecurityAnalyzer:
    def __init__(self, url: str, investigation_id: str):
        self.url = url
        self.investigation_id = investigation_id
        self.result = WebsiteSecurityResult()
        self.target = None
        self.page = None

    def analyze(self) -> AnalysisResult[WebsiteSecurityResult]:
        try:
            self._resolve_target()
            self._fetch_page()
            self._inspect_headers()
            return self._response(AnalysisStatus.COMPLETED)

        except InvalidTargetError as error:  # message is written for users
            return self._fail(AnalysisStatus.FAILED, str(error))

        except NonPublicAddressError as error:
            logger.warning("M5 %s: non-public target: %s", self.investigation_id, error)
            self.result.publicly_resolvable = (False, [])
            return self._fail(AnalysisStatus.FAILED,
                              "The address resolves to a non-public network and was not analysed.")

        except ResolutionError as error:
            logger.info("M5 %s: DNS failure: %s", self.investigation_id, error)
            return self._fail(AnalysisStatus.FAILED, "DNS resolution failed.")

        except FetchError as error:
            logger.info("M5 %s: fetch failed: %s", self.investigation_id, error.message)
            if error.hops:
                self.result.page_fetched = (False, None)  # a failed fetch has no "final URL"
            return self._fail(AnalysisStatus.PARTIAL, error.message)

        except (ValueError, TypeError) as error:
            logger.warning("M5 %s: invalid input: %s", self.investigation_id, error)
            return self._fail(AnalysisStatus.FAILED, "The URL could not be analysed.")

        except Exception:  # never let an unexpected error escape to the caller with internals attached
            logger.exception("M5 %s: unexpected error", self.investigation_id)
            return self._fail(AnalysisStatus.FAILED, "An unexpected error occurred during analysis.")

    def _resolve_target(self):
        self.target = TargetResolver(self.url, self.result).resolve()

    def _fetch_page(self):
        self.page = PageFetcher(self.target, self.result).fetch()

    def _inspect_headers(self):
        HeaderInspector(
            headers=self.page.headers,
            final_url=self.page.final_url,
            status_code=self.page.status_code,
            result=self.result,
        ).inspect()

    def _fail(self, status: AnalysisStatus, message: str):
        return self._response(status, message)

    def _response(self, status: AnalysisStatus, error: str | None = None):
        if error is None:
            return AnalysisResult(investigation_id=self.investigation_id, module="M5",
                                  status=status, data=self.result)
        return AnalysisResult(investigation_id=self.investigation_id, module="M5",
                              status=status, data=self.result, error=error)


def analyze_website_security(url: str, investigation_id: str) -> AnalysisResult[WebsiteSecurityResult]:
    return WebsiteSecurityAnalyzer(url, investigation_id).analyze()