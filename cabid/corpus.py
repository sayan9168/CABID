"""Reproducible public-corpus acquisition with pinned checksums.

Nothing in this module is bundled with the package. Corpora are fetched on
demand into a local cache directory, verified against a pinned SHA-256, and
reused offline afterwards. If a download is impossible (air-gapped host, no
network, mirror moved) the caller gets a clear error naming the manual steps
rather than a silent empty result.

Every entry in :data:`CORPORA` records where the bytes came from, the exact
commit they were taken at, and the digest of the archive that was verified
during authoring. A changed digest is a hard failure: a corpus that silently
drifts makes published benchmark numbers unreproducible.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

CORPUS_FORMAT = "cabid-corpus/1"

#: Where downloads are cached when the caller does not choose a directory.
DEFAULT_CACHE = Path(
    os.environ.get("CABID_CACHE")
    or (Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "cabid")
)

MAX_ARCHIVE_BYTES = 512 * 1024 * 1024


class CorpusError(RuntimeError):
    """Raised when a corpus cannot be fetched, verified, or extracted."""


CORPORA: dict[str, dict] = {
    "adfa-ld": {
        "title": "ADFA-LD intrusion detection dataset (mirrored as plain files)",
        "kind": "syscall-traces",
        "url": (
            "https://codeload.github.com/roopansh/Data-Mining-Project-CS244"
            "/zip/79c6db0011ba4da0adeffdb5ce9b9f615547e1a1"
        ),
        "archive_sha256": "e6e73c16b294d14ed6ddfd50bfb7e52a0e3a6fcf40cc1981c2d40e7faed77eb2",
        "archive_bytes": 4215574,
        "archive_root": "roopansh-Data-Mining-Project-CS244-79c6db0",
        "member_prefix": "ADFA-LD/",
        "source_commit": "79c6db0011ba4da0adeffdb5ce9b9f615547e1a1",
        "license": "Research use; cite Creech & Hu (2013)",
        "provenance": (
            "Original data: Creech & Hu, 'Generation of a new IDS test dataset: "
            "time to move on', UNSW@ADFA, 2013. This mirror republishes the "
            "ADFA-LD tree as ordinary files; the upstream labelled release is "
            "distributed via Git LFS and could not be fetched by API."
        ),
        "files": 5951,
        "caveats": [
            "Traces are 2013-era 32-bit userspace syscall sequences, not modern host logs.",
            "Each trace carries no timestamps, pids, or paths; timing and process context "
            "are synthesised by the adapter and are therefore approximate.",
            "Attack classes are small (75-338 traces per class) and well known to the "
            "literature, so a high score here does not demonstrate real-world detection.",
        ],
    },
}


def cache_dir(base: str | Path | None = None) -> Path:
    """Resolve the cache directory, honouring ``CABID_CACHE`` when set."""
    return Path(base) if base is not None else DEFAULT_CACHE


def catalogue() -> list[dict]:
    """Describe the known corpora and their pinned digests."""
    entries = []
    for name, spec in sorted(CORPORA.items()):
        entries.append({
            "name": name,
            "title": spec["title"],
            "kind": spec["kind"],
            "url": spec["url"],
            "archive_sha256": spec["archive_sha256"],
            "archive_bytes": spec["archive_bytes"],
            "files": spec["files"],
            "license": spec["license"],
            "source_commit": spec["source_commit"],
            "caveats": list(spec["caveats"]),
        })
    return entries


def _spec(name: str) -> dict:
    try:
        return CORPORA[name]
    except KeyError as exc:
        known = ", ".join(sorted(CORPORA))
        raise CorpusError(f"unknown corpus {name!r}; known corpora: {known}") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, destination: Path, timeout: float) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "cabid-corpus-fetch"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > MAX_ARCHIVE_BYTES:
                raise CorpusError(
                    f"remote archive declares {int(declared)} bytes, above the "
                    f"{MAX_ARCHIVE_BYTES}-byte safety limit"
                )
            written = 0
            with destination.open("wb") as handle:
                for chunk in iter(lambda: response.read(1 << 20), b""):
                    written += len(chunk)
                    if written > MAX_ARCHIVE_BYTES:
                        raise CorpusError(
                            f"download exceeded the {MAX_ARCHIVE_BYTES}-byte safety limit"
                        )
                    handle.write(chunk)
    except urllib.error.URLError as exc:
        raise CorpusError(
            f"download failed for {url}: {exc}. Fetch the archive manually, place it at "
            f"{destination}, and re-run with --offline."
        ) from exc
    except OSError as exc:
        raise CorpusError(f"could not write {destination}: {exc}") from exc


def _split_member(member: str, prefix: str) -> str | None:
    """Return the path below ``prefix``, or ``None`` if the member is elsewhere.

    The corpus directory may sit at any depth inside the archive wrapper, so the
    prefix is matched as a whole path component rather than as a string prefix.
    """
    parts = member.split("/")
    try:
        index = parts.index(prefix.rstrip("/"))
    except ValueError:
        return None
    remainder = "/".join(parts[index + 1:])
    return remainder or None


def _extract(archive: Path, spec: dict, destination: Path) -> None:
    """Extract only the corpus subtree, refusing absolute or parent paths."""
    try:
        with zipfile.ZipFile(archive) as bundle:
            # GitHub archives wrap everything in "<repo>-<sha>/", but the exact
            # prefix differs between the zipball API and codeload, so locate the
            # corpus directory by its own name instead of trusting the wrapper.
            members = [
                info for info in bundle.infolist()
                if not info.is_dir() and _split_member(info.filename, spec["member_prefix"])
            ]
            if not members:
                raise CorpusError(
                    f"{archive} contains no members under */{spec['member_prefix']}"
                )
            staging = Path(tempfile.mkdtemp(prefix="cabid-extract-", dir=destination.parent))
            try:
                for info in members:
                    relative = _split_member(info.filename, spec["member_prefix"])
                    if relative is None:  # pragma: no cover - filtered above
                        continue
                    target = (staging / relative).resolve()
                    if staging.resolve() not in target.parents and target != staging.resolve():
                        raise CorpusError(f"refusing unsafe archive member: {info.filename}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(info) as source, target.open("wb") as sink:
                        shutil.copyfileobj(source, sink)
                if destination.exists():
                    shutil.rmtree(destination)
                staging.rename(destination)
            except BaseException:
                shutil.rmtree(staging, ignore_errors=True)
                raise
    except zipfile.BadZipFile as exc:
        raise CorpusError(f"{archive} is not a readable zip archive") from exc


def fetch(name: str, base: str | Path | None = None, *, refresh: bool = False,
          offline: bool = False, timeout: float = 120.0) -> dict:
    """Ensure a corpus is present and verified in the cache; return its manifest.

    A verified corpus is never re-downloaded unless ``refresh`` is set, so the
    common path makes no network call at all.
    """
    spec = _spec(name)
    root = cache_dir(base) / name
    archive = root / "archive.zip"
    data = root / "data"
    record = root / "manifest.json"

    if not refresh and record.exists() and data.is_dir():
        try:
            saved = json.loads(record.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            saved = None
        if isinstance(saved, dict) and saved.get("archive_sha256") == spec["archive_sha256"]:
            saved["cache_hit"] = True
            return saved

    if offline:
        raise CorpusError(
            f"corpus {name!r} is not cached at {root} and --offline was requested. "
            f"Download manually from {spec['url']}, save it as {archive}, then re-run "
            "without --offline so the checksum can be verified."
        )

    root.mkdir(parents=True, exist_ok=True)
    if refresh or not archive.exists() or _sha256(archive) != spec["archive_sha256"]:
        _download(spec["url"], archive, timeout)
    actual = _sha256(archive)
    if actual != spec["archive_sha256"]:
        archive.unlink(missing_ok=True)
        raise CorpusError(
            f"checksum mismatch for {name!r}: expected {spec['archive_sha256']}, got {actual}. "
            "The remote archive changed; refusing to use unverifiable data."
        )

    _extract(archive, spec, data)
    files = sorted(path.relative_to(data).as_posix() for path in data.rglob("*.txt"))
    manifest = {
        "format": CORPUS_FORMAT,
        "name": name,
        "title": spec["title"],
        "archive_sha256": actual,
        "archive_bytes": archive.stat().st_size,
        "source_url": spec["url"],
        "source_commit": spec["source_commit"],
        "license": spec["license"],
        "provenance": spec["provenance"],
        "caveats": list(spec["caveats"]),
        "extracted_files": len(files),
        "expected_files": spec["files"],
        "path": str(data),
        "cache_hit": False,
    }
    if len(files) != spec["files"]:
        raise CorpusError(
            f"corpus {name!r} extracted {len(files)} files but {spec['files']} were expected"
        )
    record.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def verify(name: str, base: str | Path | None = None) -> dict:
    """Re-verify a cached corpus against its pinned digest without network access."""
    spec = _spec(name)
    root = cache_dir(base) / name
    archive = root / "archive.zip"
    if not archive.exists():
        raise CorpusError(f"no cached archive at {archive}; run the fetch step first")
    actual = _sha256(archive)
    ok = actual == spec["archive_sha256"]
    return {
        "name": name,
        "path": str(archive),
        "verified": ok,
        "expected_sha256": spec["archive_sha256"],
        "actual_sha256": actual,
    }


def load_manifest(name: str, base: str | Path | None = None) -> dict:
    """Read a previously written manifest without touching the network."""
    record = cache_dir(base) / name / "manifest.json"
    if not record.exists():
        raise CorpusError(f"corpus {name!r} has not been fetched into {record.parent}")
    try:
        data = json.loads(record.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CorpusError(f"{record}: invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise CorpusError(f"{record}: manifest must be a JSON object")
    return data
