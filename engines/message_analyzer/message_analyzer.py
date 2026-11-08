from .analysis_result import MessageAnalysisResult
from .input_sanitizer import InputSanitizer
from .indicator_extractor import IndicatorExtractor
from .language_analyzer import LanguageAnalyzer


class MessageAnalyzer:
    def __init__(self, message: str):
        self.message = message
        self.result = MessageAnalysisResult()

        self.sanitized_message = None


    def analyze(self) -> MessageAnalysisResult:
        self._sanitize_input()
        self._extract_indicators()
        self._analyze_language()

        return self.result

    def _sanitize_input(self):
        self.sanitized_message = InputSanitizer.sanitize(self.message)

    def _extract_indicators(self):
        extractor = IndicatorExtractor(self.sanitized_message).extract()

        self.result.urls = extractor.urls
        self.result.email_addresses = extractor.email_addresses
        self.result.phone_numbers = extractor.phone_numbers

    def _analyze_language(self):
        analyzer = LanguageAnalyzer(
            self.sanitized_message,
            self.result
        )

        self.result = analyzer.analyze()
