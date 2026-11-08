import unicodedata

import idna
import tldextract
from rapidfuzz import fuzz

from analysis_result import URLAnalysisResult
from constants.known_brands import KNOWN_BRANDS
from constants.suspicious_keywords import SUSPICIOUS_KEYWORDS
from constants.known_scripts import KNOWN_SCRIPTS


class DomainInspector:
    TLD_EXTRACTOR = tldextract.TLDExtract()

    def __init__(self, domain: str, result: URLAnalysisResult, path: str = '/'):
        self.domain = domain
        self.result = result
        self.path = path

        self.subdomain = None
        self.registered_domain = None
        self.public_suffix = None

    def inspect(self):
        self._extract_domain_metadata()
        self._check_typosquatting()
        self._check_punycode()
        self._check_mixed_scripts()
        self._check_brand_in_subdomain()
        self._check_suspicious_keywords()
        self._check_domain_structure()

    def _extract_domain_metadata(self):
        extracted = self.TLD_EXTRACTOR(self.domain)

        self.subdomain = extracted.subdomain or None
        self.registered_domain = extracted.top_domain_under_public_suffix or None
        self.public_suffix = extracted.suffix or None

    def _check_typosquatting(self):
        domain_label = self.registered_domain.split('.')[0]

        detected_brands = []

        for brand in KNOWN_BRANDS:
            similarity = fuzz.ratio(domain_label, brand)
            threshold = 90 if len(brand) < 5 else 80

            if similarity >= threshold and domain_label != brand:
                detected_brands.append(brand)

        self.result.typosquatting_detected = (
            bool(detected_brands),
            detected_brands
        )

    def _check_punycode(self):
        punycode_labels = [
            label
            for label in self.domain.split('.')
            if label.startswith('xn--')
        ]

        self.result.uses_punycode = (
            bool(punycode_labels),
            punycode_labels
        )

    def _check_mixed_scripts(self):
        unicode_domain = idna.decode(self.domain)
        mixed_labels = []

        for label in unicode_domain.split('.'):
            detected_scripts = set()

            for char in label:
                if not char.isalpha():
                    continue

                unicode_name = unicodedata.name(char, '')

                for script in KNOWN_SCRIPTS:
                    if script in unicode_name:
                        detected_scripts.add(script)
                        break

            if len(detected_scripts) > 1:
                mixed_labels.append(
                    f'{label}: {", ".join(sorted(detected_scripts))}'
                )

        self.result.mixed_unicode_scripts = (
            bool(mixed_labels),
            mixed_labels
        )

    def _check_brand_in_subdomain(self):
        if not self.subdomain:
            self.result.brand_in_subdomain = (False, [])
            return

        subdomain_tokens = {
            token
            for label in self.subdomain.split('.')
            for token in label.split('-')
        }

        registered_label = self.registered_domain.split('.')[0]
        registered_tokens = set(registered_label.split('-'))

        detected_brands = [
            brand
            for brand in KNOWN_BRANDS
            if brand in subdomain_tokens
            and brand not in registered_tokens
        ]

        self.result.brand_in_subdomain = (
            bool(detected_brands),
            detected_brands
        )

    def _check_suspicious_keywords(self):
        searchable_text = f'{self.domain} {self.path}'.lower()

        detected_keywords = [
            keyword
            for keyword in SUSPICIOUS_KEYWORDS
            if keyword in searchable_text
        ]

        self.result.suspicious_keywords = (
            bool(detected_keywords),
            detected_keywords
        )

    def _check_domain_structure(self):
        hyphen_count = self.domain.count('-')

        subdomain_count = (
            len(self.subdomain.split('.'))
            if self.subdomain
            else 0
        )

        self.result.excessive_hyphens = (
            hyphen_count >= 3,
            hyphen_count
        )

        self.result.excessive_subdomains = (
            subdomain_count > 3,
            subdomain_count
        )
