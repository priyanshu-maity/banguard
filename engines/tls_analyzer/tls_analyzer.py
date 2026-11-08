from analysis_result import TLSAnalysisResult


class TLSAnalyzer:
    def __init__(self, url: str):
        self.url = url
        self.result = TLSAnalysisResult()

    def analyze(self):
        self._retrieve_certificate()
        self._check_validity()
        self._check_issuer()

        return self.result

    def _retrieve_certificate(self):
        ...

    def _check_validity(self):
        ...

    def _check_issuer(self):
        ...
