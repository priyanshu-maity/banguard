import re
import phonenumbers


class IndicatorExtractor:
    URL_PATTERN = re.compile(
        r'(?i)\b(?:https?://|www\.)[^\s<>"\']+'
    )

    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    )

    DEFAULT_REGION = 'IN'

    def __init__(self, message: str):
        self.message = message

        self.urls = []
        self.email_addresses = []
        self.phone_numbers = []

    def extract(self):
        self._extract_urls()
        self._extract_emails()
        self._extract_phone_numbers()

        return self

    def _extract_urls(self):
        matches = self.URL_PATTERN.findall(self.message)

        for url in matches:
            url = url.rstrip('.,!?;:)]}')

            if url.lower().startswith('www.'):
                url = 'https://' + url

            if url not in self.urls:
                self.urls.append(url)

    def _extract_emails(self):
        matches = self.EMAIL_PATTERN.findall(self.message)

        self.email_addresses = list(dict.fromkeys(
            email.lower() for email in matches
        ))

    def _extract_phone_numbers(self):
        for match in phonenumbers.PhoneNumberMatcher(
            self.message,
            self.DEFAULT_REGION
        ):

            number = match.number

            if phonenumbers.is_valid_number(number):

                formatted = phonenumbers.format_number(
                    number,
                    phonenumbers.PhoneNumberFormat.E164
                )

                if formatted not in self.phone_numbers:
                    self.phone_numbers.append(formatted)
