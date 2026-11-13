# Report integrity

A CABID report may be cited later, so someone may eventually ask *"is this the
report that was produced, or was it edited?"*. Sealing makes that answerable
without adding a dependency.

## What sealing provides

| Layer | Detects | Does not detect |
| --- | --- | --- |
| `digest_sha256` | accidental corruption, careless edits, and any edit that does not recompute the seal | deliberate re-sealing by someone who has the report |
| `hmac_sha256` (opt-in) | edits by anyone who does **not** hold the shared key | edits by anyone who *does* hold the key |

**This is not a digital signature.** HMAC proves knowledge of a shared secret, so
whoever can verify can also forge. For non-repudiation, sign the canonical bytes
with a private key instead:

```bash
# extract the canonical body, then sign with your own key
cabid seal report.json --verify > verify.json
openssl dgst -sha256 -sign key.pem -out report.sig report.json
```

The seal block says this in its `note` field, so a reader of the JSON does not
have to find this page to learn the limitation.

## Seal a report

```bash
cabid analyze events.jsonl -o report.json --sign
CABID_KEY=... cabid analyze events.jsonl -o report.json --sign --seal-key-env CABID_KEY
cabid seal report.json                      # seal an existing report in place
cabid seal report.json -o signed.json       # seal to a new file
```

The key is read from an environment variable, never from a command-line argument —
arguments are visible in process listings and shell history.

## Verify

```bash
cabid seal report.json --verify
CABID_KEY=... cabid seal report.json --verify --key-env CABID_KEY
```

Exit code `0` when verified, `1` when the digest or HMAC does not match. Output:

```json
{
  "verified": true,
  "digest_ok": true,
  "hmac_present": true,
  "hmac_ok": true,
  "expected_digest": "…",
  "recorded_digest": "…",
  "reason": "digest and HMAC both match"
}
```

`hmac_ok` is `null` (not `false`) when no key was supplied, so "not checked" is
never reported as "failed".

## Canonical form

The digest covers `json.dumps(payload, sort_keys=True, separators=(',', ':'),
ensure_ascii=False)` of the report **without** its `seal` block. Key order and
whitespace therefore do not matter, and a report can be pretty-printed or
re-minified without invalidating the seal.

Sealing an already-sealed report drops the previous seal first, so re-sealing is
idempotent and cannot silently preserve a stale digest.

## What this does not cover

- The **inputs**. The seal proves the report was not edited after sealing; it says
  nothing about whether the events were authentic.
- The **time** of sealing, unless you record it yourself. There is no trusted
  timestamp.
- Anything after sealing. A sealed report is a snapshot; a later analysis is a
  different report with a different digest.
