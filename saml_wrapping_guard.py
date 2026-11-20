class SamlWrapError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_ALLOWED_TRANSFORMS = ("enveloped-signature", "exclusive-c14n")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class AssertionWrappingGuard:
    def __init__(self, audience, acs_url, issuers, max_skew=120):
        self.audience = audience
        self.acs_url = acs_url
        self.issuers = set(issuers)
        self.max_skew = max_skew

    def verify(self, envelope, now):
        if not isinstance(envelope, dict):
            raise SamlWrapError("invalid_envelope")

        response_id = envelope.get("response_id")
        request_id = envelope.get("request_id")
        assertions = envelope.get("assertions")
        if not isinstance(assertions, list):
            raise SamlWrapError("invalid_envelope")

        ids = [response_id]
        for item in assertions:
            ids.append(item.get("id") if isinstance(item, dict) else None)
        for element_id in ids:
            if not isinstance(element_id, str) or not element_id.strip():
                raise SamlWrapError("empty_id")
        if len(set(ids)) != len(ids):
            raise SamlWrapError("id_collision")

        if len(assertions) != 1:
            raise SamlWrapError("assertion_count")
        assertion = assertions[0]
        if not isinstance(assertion, dict):
            raise SamlWrapError("assertion_count")

        assertion_id = assertion.get("id")

        signature = assertion.get("signature")
        if not isinstance(signature, dict):
            raise SamlWrapError("unsigned_assertion")
        if signature.get("parent") != "Assertion":
            raise SamlWrapError("bad_signature_parent")
        if signature.get("reference_id") != assertion_id:
            raise SamlWrapError("reference_mismatch")
        transforms = signature.get("transforms")
        if not isinstance(transforms, (list, tuple)) or tuple(transforms) != _ALLOWED_TRANSFORMS:
            raise SamlWrapError("bad_transforms")
        digest = signature.get("digest")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in _HEX_DIGITS for ch in digest)
        ):
            raise SamlWrapError("bad_digest")

        if assertion.get("issuer") not in self.issuers:
            raise SamlWrapError("unknown_issuer")
        if assertion.get("audience") != self.audience:
            raise SamlWrapError("audience_mismatch")
        if assertion.get("recipient") != self.acs_url:
            raise SamlWrapError("recipient_mismatch")

        not_on_or_after = assertion.get("not_on_or_after")
        if not isinstance(not_on_or_after, (int, float)) or isinstance(not_on_or_after, bool):
            raise SamlWrapError("assertion_expired")
        if now > not_on_or_after + self.max_skew:
            raise SamlWrapError("assertion_expired")

        issue_instant = assertion.get("issue_instant")
        if isinstance(issue_instant, (int, float)) and not isinstance(issue_instant, bool):
            if issue_instant > now + self.max_skew:
                raise SamlWrapError("assertion_not_yet_valid")

        if assertion.get("in_response_to") != request_id:
            raise SamlWrapError("request_mismatch")

        subject = assertion.get("subject")
        if not isinstance(subject, str) or not subject.strip():
            raise SamlWrapError("empty_subject")

        return {"subject": subject, "assertion_id": assertion_id}
