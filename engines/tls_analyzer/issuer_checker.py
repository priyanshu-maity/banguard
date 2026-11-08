import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ObjectIdentifier

from .analysis_result import TLSAnalysisResult
from constants.distrusted_cas import DISTRUST_LIST


class IssuerChecker:
    def __init__(self, certificate: x509.Certificate, result: TLSAnalysisResult):
        self.certificate = certificate
        self.result = result
        self.issuer_cn = self._attribute(certificate.issuer, NameOID.COMMON_NAME)
        self.issuer_org = self._attribute(certificate.issuer, NameOID.ORGANIZATION_NAME)

    def check(self) -> None:
        self._check_self_signed()
        self._check_unknown_issuer()
        self._check_distrust_list()

    @property
    def issuer_label(self) -> str:
        return self.issuer_cn or self.issuer_org or self.certificate.issuer.rfc4514_string()

    def _check_self_signed(self) -> None:
        self.result.self_signed = (self.certificate.issuer == self.certificate.subject, self.issuer_label)

    def _check_unknown_issuer(self) -> None:
        failed, reason = self.result.verification_failed
        if failed is False:
            self.result.unknown_issuer = (False, self.issuer_label)
        elif failed and reason == "unknown_issuer":
            self.result.unknown_issuer = (True, self.issuer_label)
        else:
            self.result.unknown_issuer = (None, self.issuer_label)

    def _check_distrust_list(self) -> None:
        try:
            entries = DISTRUST_LIST
        except (OSError, ValueError, KeyError):
            self.result.distrusted_ca_match = (None, [])
            return

        fingerprint = self.certificate.fingerprint(hashes.SHA256()).hex()
        cn = (self.issuer_cn or "").casefold()
        org = (self.issuer_org or "").casefold()

        matches = []
        for entry in entries:
            by_name = (
                (cn and cn in {n.casefold() for n in entry.get("issuer_common_names", [])})
                or (org and org in {n.casefold() for n in entry.get("issuer_organizations", [])})
            )
            by_fingerprint = fingerprint in {f.replace(":", "").lower() for f in entry.get("sha256_fingerprints", [])}
            if by_name or by_fingerprint:
                matched_on = "fingerprint" if by_fingerprint else "issuer name"
                matches.append(
                    f"Issued by a CA listed as distrusted: {entry['name']} "
                    f"(matched on {matched_on}; source: {entry['source']}; listed {entry['date']})"
                )
        self.result.distrusted_ca_match = (bool(matches), matches)

    @staticmethod
    def _attribute(name: x509.Name, oid: ObjectIdentifier) -> str | None:
        values = name.get_attributes_for_oid(oid)
        if not values:
            return None
        value = values[0].value
        return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value