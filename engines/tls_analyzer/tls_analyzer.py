from .analysis_result import TLSAnalysisResult
from .certificate_retriever import CertificateRetriever
from .issuer_checker import IssuerChecker
from .validity_checker import ValidityChecker


class TLSAnalyzer:
    def __init__(self, host: str, port: int = 443):
        self.host = host
        self.port = port
        self.result = TLSAnalysisResult()
        self._certificate = None

    def analyze(self) -> TLSAnalysisResult:
        self._retrieve_certificate()
        if self._certificate is None:
            return self.result
        self._check_validity()
        self._check_issuer()
        return self.result

    def _retrieve_certificate(self):
        self._certificate = CertificateRetriever(self.host, self.port, self.result).retrieve()

    def _check_validity(self):
        ValidityChecker(self._certificate, self.host, self.result).check()

    def _check_issuer(self):
        IssuerChecker(self._certificate, self.result).check()
