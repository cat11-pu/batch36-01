import pytest

import saml_metadata as sm

ENTITY = "https://sp.example.org/metadata"


def store(max_validity=1000):
    anchors = [
        {"key_id": "old", "fingerprint": "fp-old", "not_before": 0, "not_after": 100, "usage": "signing"},
        {"key_id": "new", "fingerprint": "fp-new", "not_before": 50, "not_after": 300, "usage": "signing"},
        {"key_id": "enc", "fingerprint": "fp-enc", "not_before": 0, "not_after": 300, "usage": "encryption"},
    ]
    return sm.MetadataTrustStore(ENTITY, anchors, max_validity=max_validity)


def document(**over):
    d = {
        "entity_id": ENTITY,
        "valid_until": 200,
        "cache_duration": 3600,
        "sso_url": "https://idp.example.org/sso",
        "signing_cert": "fp-old",
    }
    d.update(over)
    return d


def signature(**over):
    s = {"key_id": "old", "reference": "EntityDescriptor", "digest": "ab" * 32}
    s.update(over)
    return s


def test_valid_metadata_returns_snapshot():
    res = store().validate(document(), signature(), now=60)
    assert res["entity_id"] == ENTITY
    assert res["key_id"] == "old"
    assert res["fingerprint"] == "fp-old"
    assert res["expires_at"] == 200


def test_entity_id_mismatch_is_rejected():
    with pytest.raises(ValueError):
        store().validate(document(entity_id="https://other.example.org/metadata"), signature(), now=60)


def test_missing_entity_id_is_rejected():
    doc = document()
    del doc["entity_id"]
    with pytest.raises(ValueError):
        store().validate(doc, signature(), now=60)


def test_missing_signature_is_rejected():
    with pytest.raises(ValueError):
        store().validate(document(), None, now=60)


def test_signature_reference_must_cover_entity_descriptor():
    with pytest.raises(ValueError):
        store().validate(document(), signature(reference="Response"), now=60)


def test_digest_must_be_sixty_four_hex_chars():
    with pytest.raises(ValueError):
        store().validate(document(), signature(digest="zz" * 32), now=60)


def test_unknown_signing_key_is_rejected():
    with pytest.raises(ValueError):
        store().validate(document(), signature(key_id="ghost"), now=60)


def test_certificate_fingerprint_must_match_anchor():
    with pytest.raises(ValueError):
        store().validate(document(signing_cert="fp-other"), signature(), now=60)


def test_encryption_key_cannot_sign_metadata():
    with pytest.raises(ValueError):
        store().validate(document(signing_cert="fp-enc"), signature(key_id="enc"), now=60)


def test_expired_anchor_is_rejected():
    with pytest.raises(ValueError):
        store().validate(document(valid_until=300), signature(), now=150)


def test_not_yet_valid_anchor_is_rejected():
    with pytest.raises(ValueError):
        store().validate(document(signing_cert="fp-new"), signature(key_id="new"), now=10)


def test_metadata_valid_until_in_past_is_rejected():
    with pytest.raises(ValueError):
        store().validate(document(valid_until=50), signature(), now=60)


def test_metadata_validity_beyond_cache_cap_is_rejected():
    with pytest.raises(ValueError):
        store().validate(document(valid_until=2000), signature(), now=60)


def test_rollover_overlap_accepts_both_anchors():
    g = store()
    assert g.validate(document(), signature(), now=60)["key_id"] == "old"
    fresh = g.validate(document(signing_cert="fp-new"), signature(key_id="new"), now=60)
    assert fresh["key_id"] == "new"
    assert set(g.trusted_keys(60)) == {"old", "new"}


def test_retired_anchor_is_rejected_after_overlap():
    g = store()
    with pytest.raises(ValueError):
        g.validate(document(valid_until=300), signature(), now=120)
    res = g.validate(document(valid_until=300, signing_cert="fp-new"), signature(key_id="new"), now=120)
    assert res["key_id"] == "new"
    assert g.trusted_keys(120) == ["new"]
