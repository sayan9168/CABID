import json

import pytest

from cabid.signature import (SEAL_FORMAT, SealError, canonical_bytes, payload_of, seal_report,
                             sign_file, verify_file, verify_report)


def report():
    return {"status": "SUSPICIOUS", "anomaly_score": 0.6, "components": {"temporal": 0.5}}


def test_seal_verifies_and_records_digest():
    sealed = seal_report(report())
    assert sealed["seal"]["format"] == SEAL_FORMAT
    assert len(sealed["seal"]["digest_sha256"]) == 64
    result = verify_report(sealed)
    assert result["verified"] is True
    assert result["digest_ok"] is True
    assert result["hmac_present"] is False
    assert "only against accidental edits" in result["reason"]


def test_canonical_form_ignores_key_order_and_whitespace():
    a = {"b": 1, "a": [1, 2, {"y": 2, "x": 1}]}
    b = {"a": [1, 2, {"x": 1, "y": 2}], "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)
    assert seal_report(a)["seal"]["digest_sha256"] == seal_report(b)["seal"]["digest_sha256"]


def test_resealing_drops_the_previous_seal():
    once = seal_report(report())
    twice = seal_report(once)
    assert "seal" in twice
    assert payload_of(twice) == payload_of(once)
    assert verify_report(twice)["verified"] is True


def test_tampering_is_detected():
    sealed = seal_report(report())
    sealed["status"] = "NO_ANOMALY_DETECTED"
    result = verify_report(sealed)
    assert result["verified"] is False
    assert result["digest_ok"] is False
    assert "modified after sealing" in result["reason"]


def test_nested_edit_is_detected():
    sealed = seal_report(report())
    sealed["components"]["temporal"] = 0.1
    assert verify_report(sealed)["verified"] is False


def test_hmac_round_trip_with_correct_key():
    sealed = seal_report(report(), "shared-secret")
    assert verify_report(sealed, "shared-secret")["verified"] is True
    assert "both match" in verify_report(sealed, "shared-secret")["reason"]
    assert verify_report(sealed)["verified"] is True          # digest still fine
    assert verify_report(sealed)["hmac_ok"] is None            # key not checked


def test_hmac_mismatch_is_reported_not_silent():
    sealed = seal_report(report(), "shared-secret")
    result = verify_report(sealed, "wrong-key")
    assert result["verified"] is False
    assert result["hmac_ok"] is False
    assert "re-sealed without the original key" in result["reason"]


def test_empty_key_rejected():
    with pytest.raises(SealError):
        seal_report(report(), "")


def test_document_without_seal_is_an_error():
    with pytest.raises(SealError, match="no seal"):
        verify_report(report())


def test_unknown_seal_format_is_an_error():
    sealed = seal_report(report())
    sealed["seal"]["format"] = "cabid-seal/99"
    with pytest.raises(SealError, match="unsupported seal format"):
        verify_report(sealed)


def test_file_round_trip(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report()), encoding="utf-8")
    seal = sign_file(path, "k")
    assert seal["hmac_sha256"]
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["seal"]["digest_sha256"] == seal["digest_sha256"]
    assert verify_file(path, "k")["verified"] is True


def test_sign_to_separate_output(tmp_path):
    source = tmp_path / "in.json"
    source.write_text(json.dumps(report()), encoding="utf-8")
    out = tmp_path / "signed" / "out.json"
    sign_file(source, None, out)
    assert "seal" not in json.loads(source.read_text(encoding="utf-8"))
    assert verify_file(out)["verified"] is True


def test_non_json_file_reports_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    with pytest.raises(SealError, match="invalid JSON"):
        verify_file(bad)


def test_non_object_report_rejected():
    with pytest.raises(SealError):
        seal_report(["not", "an", "object"])
