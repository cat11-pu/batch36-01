import pytest

import saml_wrapping_guard as sw

AUDIENCE = "https://sp.example.com/metadata"
ACS = "https://sp.example.com/acs"
ISSUER = "https://idp.example.com"


def guard(max_skew=120):
    return sw.AssertionWrappingGuard(AUDIENCE, ACS, {ISSUER}, max_skew=max_skew)


def assertion(**over):
    a = {
        "id": "a-1",
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "recipient": ACS,
        "not_on_or_after": 500,
        "issue_instant": 100,
        "subject": "alice",
        "in_response_to": "req-1",
        "signature": {
            "reference_id": "a-1",
            "parent": "Assertion",
            "transforms": ["enveloped-signature", "exclusive-c14n"],
            "digest": "ab" * 32,
        },
    }
    a.update(over)
    return a


def envelope(*assertions, **over):
    e = {"response_id": "r-1", "request_id": "req-1", "assertions": list(assertions) or [assertion()]}
    e.update(over)
    return e


def test_signed_assertion_is_accepted():
    res = guard().verify(envelope(), now=200)
    assert res["subject"] == "alice"
    assert res["assertion_id"] == "a-1"


def test_assertion_without_signature_is_rejected():
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(signature=None)), now=200)
    assert exc.value.code == "unsigned_assertion"


def test_signature_on_response_level_is_rejected():
    sig = {"reference_id": "r-1", "parent": "Response", "transforms": ["enveloped-signature", "exclusive-c14n"], "digest": "ab" * 32}
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(signature=sig)), now=200)
    assert exc.value.code == "bad_signature_parent"


def test_reference_must_point_back_to_the_assertion():
    sig = {"reference_id": "a-9", "parent": "Assertion", "transforms": ["enveloped-signature", "exclusive-c14n"], "digest": "ab" * 32}
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(signature=sig)), now=200)
    assert exc.value.code == "reference_mismatch"


def test_duplicate_element_ids_are_rejected():
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(), assertion()), now=200)
    assert exc.value.code == "id_collision"


def test_untrusted_issuer_is_rejected():
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(issuer="https://idp.other.example")), now=200)
    assert exc.value.code == "unknown_issuer"


def test_extra_transform_is_rejected():
    sig = {"reference_id": "a-1", "parent": "Assertion", "transforms": ["enveloped-signature", "with-comments", "exclusive-c14n"], "digest": "ab" * 32}
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(signature=sig)), now=200)
    assert exc.value.code == "bad_transforms"


def test_digest_must_be_sixty_four_hex_chars():
    sig = {"reference_id": "a-1", "parent": "Assertion", "transforms": ["enveloped-signature", "exclusive-c14n"], "digest": "zz" * 32}
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(signature=sig)), now=200)
    assert exc.value.code == "bad_digest"


def test_audience_must_match_exactly():
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(audience="https://sp.other.example/metadata")), now=200)
    assert exc.value.code == "audience_mismatch"


def test_recipient_must_match_acs_url():
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(recipient="https://sp.example.com/acs2")), now=200)
    assert exc.value.code == "recipient_mismatch"


def test_expired_assertion_beyond_skew_is_rejected():
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(not_on_or_after=100)), now=400)
    assert exc.value.code == "assertion_expired"


def test_expired_assertion_within_skew_is_accepted():
    res = guard().verify(envelope(assertion(not_on_or_after=450)), now=500)
    assert res["subject"] == "alice"


def test_far_future_issue_instant_is_rejected():
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(issue_instant=900)), now=200)
    assert exc.value.code == "assertion_not_yet_valid"


def test_request_binding_must_match():
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(in_response_to="req-9")), now=200)
    assert exc.value.code == "request_mismatch"


def test_empty_subject_is_rejected():
    with pytest.raises(sw.SamlWrapError) as exc:
        guard().verify(envelope(assertion(subject="")), now=200)
    assert exc.value.code == "empty_subject"
