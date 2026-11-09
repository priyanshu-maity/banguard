import re
from urllib.parse import urlsplit

from .website_security_result import WebsiteSecurityResult

MAX_DETAIL_CHARS = 200

_HSTS_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)", re.IGNORECASE)
_CSP_FRAME_ANCESTORS = re.compile(r"(?:^|;)\s*frame-ancestors\s+\S+", re.IGNORECASE)


class HeaderInspector:
    """
    Evaluates the security headers of the final response.

    Header names are lower-cased here, so the result does not depend on how the fetcher
    stores them. A header counts as present only if its value is effective, not merely non-empty.
    """

    def __init__(self, headers: dict[str, str], final_url: str, status_code: int | None,
                 result: WebsiteSecurityResult):
        self.headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        self.final_url = final_url
        self.status_code = status_code
        self.result = result

    def inspect(self) -> bool:
        """Returns False when the headers were deliberately not evaluated."""
        if self.status_code is None or self.status_code >= 400:
            # Error, block and challenge pages carry different headers from the real site.
            return False

        self._check_hsts()
        self._check_csp()
        self._check_content_type_options()
        self._check_framing_protection()
        self._check_referrer_policy()
        self._check_permissions_policy()
        return True

    def _value(self, name: str) -> str | None:
        value = self.headers.get(name, "").strip()
        return value or None

    @staticmethod
    def _detail(value: str | None) -> str | None:
        return value[:MAX_DETAIL_CHARS] if value else None

    def _check_hsts(self) -> None:
        if urlsplit(self.final_url).scheme.lower() != "https":
            return  # not applicable on HTTP; the plain-HTTP finding covers it
        value = self._value("strict-transport-security")
        match = _HSTS_MAX_AGE.search(value) if value else None
        effective = bool(match) and int(match.group(1)) > 0  # max-age=0 switches HSTS off
        self.result.missing_hsts = (not effective, self._detail(value))

    def _check_csp(self) -> None:
        value = self._value("content-security-policy")
        self.result.missing_csp = (value is None, self._detail(value))

    def _check_content_type_options(self) -> None:
        value = self._value("x-content-type-options")
        tokens = {t.strip().lower() for t in value.split(",")} if value else set()
        self.result.missing_content_type_options = ("nosniff" not in tokens, self._detail(value))

    def _check_framing_protection(self) -> None:
        xfo = self._value("x-frame-options")
        xfo_valid = bool(xfo) and xfo.split(",")[0].strip().upper() in ("DENY", "SAMEORIGIN")
        csp = self._value("content-security-policy")
        csp_valid = bool(csp and _CSP_FRAME_ANCESTORS.search(csp))  # modern replacement for X-Frame-Options
        self.result.missing_framing_protection = (not (xfo_valid or csp_valid), self._detail(xfo))

    def _check_referrer_policy(self) -> None:
        value = self._value("referrer-policy")
        self.result.missing_referrer_policy = (value is None or value.lower() == "unsafe-url", self._detail(value))

    def _check_permissions_policy(self) -> None:
        value = self._value("permissions-policy")
        self.result.missing_permissions_policy = (value is None, self._detail(value))