"""Report integrity sealing: canonical hashing plus optional HMAC signing.

A CABID report is evidence in the loose sense that someone may later ask "is this
the report that was produced, or was it edited?". This module makes that
answerable without shipping a crypto dependency:

* ``sha256`` of a canonical JSON serialisation — detects accidental corruption
  and any edit, as long as nothing recomputes the digest.
* Optional ``hmac-sha256`` with an operator key — detects edits by anyone who
  does not hold the key.

This is deliberately **not** a digital signature. HMAC proves knowledge of a shared
secret, so whoever can verify can also forge. For non-repudiation use
``openssl dgst -sha256 -sign`` over the canonical form, or sign the digest with a
key-based tool. The docstring and the report field say so, because calling HMAC a
signature would overstate what this provides.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

SEAL_FORMAT = "cabid-seal/1"
SEAL_FIELDS = ("$schema", "format", "digest_sha256", "hmac_sha256", "canonical", "note")
_NOTE = ("digest_sha256 detects accidental or naive edits; hmac_sha256 (when present) "
         "proves the sealer held the shared key. Neither is a non-repudiable signature.")


class SealError(ValueError):
    """Raised when a seal cannot be verified or is malformed."""


def canonical_bytes(document: dict) -> bytes:
    """Stable serialisation: sorted keys, UTF-8, no insignificant whitespace."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def payload_of(document: dict) -> dict:
    """Return the report body with any existing seal removed."""
    if not isinstance(document, dict):
        raise SealError("report must be a JSON object")
    return {key: value for key, value in document.items() if key != "seal"}


def seal_report(document: dict, key: str | bytes | None = None) -> dict:
    """Return a copy of ``document`` with an added ``seal`` block."""
    if key is not None and not isinstance(key, (str, bytes)):
        raise SealError("key must be a string, bytes, or None")
    body = payload_of(document)
    digest = hashlib.sha256(canonical_bytes(body)).hexdigest()
    seal = {
        "$schema": "https://github.com/sayan9168/CABID/blob/main/docs/report-integrity.md",
        "format": SEAL_FORMAT,
        "digest_sha256": digest,
        "canonical": "json.dumps(payload, sort_keys=True, separators=(',', ':')) minus this seal block",
        "note": _NOTE,
    }
    if key is not None:
        secret = key.encode("utf-8") if isinstance(key, str) else key
        if not secret:
            raise SealError("key must not be empty")
        seal["hmac_sha256"] = hmac.new(secret, canonical_bytes(body), hashlib.sha256).hexdigest()
    sealed = dict(body)
    sealed["seal"] = seal
    return sealed


def verify_report(document: dict, key: str | bytes | None = None) -> dict:
    """Verify a seal. Returns a result dict; raises SealError when unusable."""
    if not isinstance(document, dict):
        raise SealError("report must be a JSON object")
    seal = document.get("seal")
    if not isinstance(seal, dict):
        raise SealError("report has no seal block")
    if seal.get("format") != SEAL_FORMAT:
        raise SealError(f"unsupported seal format: {seal.get('format')}")
    body = payload_of(document)
    expected = hashlib.sha256(canonical_bytes(body)).hexdigest()
    digest_ok = hmac.compare_digest(str(seal.get("digest_sha256", "")), expected)
    hmac_present = "hmac_sha256" in seal
    hmac_ok = None
    if hmac_present:
        if key is None:
            hmac_ok = None
        else:
            secret = key.encode("utf-8") if isinstance(key, str) else key
            computed = hmac.new(secret, canonical_bytes(body), hashlib.sha256).hexdigest()
            hmac_ok = hmac.compare_digest(str(seal.get("hmac_sha256", "")), computed)
    verified = digest_ok and (hmac_ok is not False)
    return {
        "verified": verified,
        "digest_ok": digest_ok,
        "hmac_present": hmac_present,
        "hmac_ok": hmac_ok,
        "expected_digest": expected,
        "recorded_digest": seal.get("digest_sha256"),
        "reason": _reason(digest_ok, hmac_present, hmac_ok, key is not None),
    }


def _reason(digest_ok: bool, hmac_present: bool, hmac_ok: bool | None, key_given: bool) -> str:
    if not digest_ok:
        return "content differs from the sealed digest: the report was modified after sealing"
    if not hmac_present:
        return "digest matches; no HMAC present, so integrity is only against accidental edits"
    if not key_given:
        return "digest matches; HMAC present but no key supplied, so the key cannot be checked"
    if hmac_ok:
        return "digest and HMAC both match"
    return "digest matches but HMAC does not: the report was re-sealed without the original key"


def sign_file(path: str | Path, key: str | bytes | None = None,
              output: str | Path | None = None) -> dict:
    """Seal a JSON report on disk and write it back (or to ``output``)."""
    source = Path(path)
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SealError(f"{source}: invalid JSON: {exc}") from exc
    sealed = seal_report(document, key)
    destination = Path(output) if output else source
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(sealed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return sealed["seal"]


def verify_file(path: str | Path, key: str | bytes | None = None) -> dict:
    source = Path(path)
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SealError(f"{source}: invalid JSON: {exc}") from exc
    return verify_report(document, key)
