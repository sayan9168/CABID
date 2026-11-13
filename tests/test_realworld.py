"""Tests for corpus acquisition, the ADFA-LD adapter, and the real benchmark.

No test touches the network. A miniature ADFA-LD tree is written to ``tmp_path``
in the real layout, and the fetch path is exercised against a locally built zip
whose digest is injected into the registry.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from cabid import corpus
from cabid.adfa import (
    NgramNovelty,
    TraceError,
    corpus_sessions,
    ngrams,
    read_trace,
    technique_of,
    trace_to_events,
)
from cabid.realworld import (
    LIMITATIONS,
    default_config,
    metrics,
    roc_auc,
    run_adfa_benchmark,
    threshold_curve,
    wilson_interval,
)

TRAINING = [
    "3 4 6 3 4 6 3 4 6",          # read/write/close: file_write only
    "3 5 4 6 3 5 4 6 3 5",        # open + write
    "4 6 3 4 6 3 4 6 3 4",        # write/close
    "5 4 4 6 3 5 4 6 3 4",        # open/write
    "3 4 5 6 3 4 5 6 3 4",        # open/write/close
    "4 5 3 6 4 5 3 6 4 5",        # open/write/close
    "3 4 6 3 4 6 5 5 4 6",        # open/write
    "4 4 6 3 3 5 4 6 3 4",        # open/write
]
VALIDATION = [
    "3 4 6 3 4 6 3 4 6 4",
    "5 4 6 3 5 4 6 3 5 4",
    "4 6 3 4 6 3 4 6 3 4",
    "3 5 4 6 3 5 4 6 3 5",
]
ATTACK = {
    "Adduser_1": ["120 102 102 102 102 206 102 102 102 102"],
    "Hydra_SSH_1": ["102 102 102 102 102 102 102 102 102 102"],
    "Web_Shell_1": ["120 11 102 4 5 102 4 5 102 4"],
}


def _write_tree(root: Path) -> Path:
    base = root / "ADFA-LD"
    for directory, contents in (
        ("Training_Data_Master", TRAINING),
        ("Validation_Data_Master", VALIDATION),
    ):
        folder = base / directory
        folder.mkdir(parents=True)
        prefix = "UTD" if directory.startswith("Training") else "UVD"
        for index, body in enumerate(contents, start=1):
            (folder / f"{prefix}-{index:04d}.txt").write_text(body + "\n", encoding="utf-8")
    attack_root = base / "Attack_Data_Master"
    for technique, traces in ATTACK.items():
        folder = attack_root / technique
        folder.mkdir(parents=True)
        for index, body in enumerate(traces, start=1):
            (folder / f"UAD-{technique}-{index}.txt").write_text(body + "\n", encoding="utf-8")
    return base


# --------------------------------------------------------------- adapter ----

def test_read_trace_preserves_order_and_rejects_junk(tmp_path):
    trace = tmp_path / "UAD-x-1.txt"
    trace.write_text("11 4 5 102\n", encoding="utf-8")
    assert read_trace(trace) == [11, 4, 5, 102]
    bad = tmp_path / "bad.txt"
    bad.write_text("11 four\n", encoding="utf-8")
    with pytest.raises(TraceError):
        read_trace(bad)


def test_read_trace_rejects_empty_and_missing(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("   \n", encoding="utf-8")
    with pytest.raises(TraceError):
        read_trace(empty)
    with pytest.raises(TraceError):
        read_trace(tmp_path / "absent.txt")


def test_trace_to_events_maps_only_known_syscalls(tmp_path):
    trace = tmp_path / "UAD-Adduser-1-1371.txt"
    trace.write_text("11 102 4 3 240 206\n", encoding="utf-8")
    events = trace_to_events(trace)
    kinds = [event["event_type"] for event in events]
    # Synthetic root start, then only the syscalls with a defensible mapping:
    # execve, socketcall, write, (read and futex dropped), setgroups32.
    assert kinds == ["process_start", "process_exec", "network_connect", "file_write",
                     "privilege_change"]
    # clone() is a process_start, distinct from the synthetic root event.
    clone = trace_to_events(_write(trace.parent / "clone.txt", "120 4\n"))
    assert [event["event_type"] for event in clone] == ["process_start", "process_start",
                                                        "file_write"]
    assert "read" not in [event["target"] for event in events]
    assert "futex" not in [event["target"] for event in events]


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_trace_to_events_is_deterministic(tmp_path):
    trace = tmp_path / "UAD-x-9.txt"
    trace.write_text("120 102 4 206\n", encoding="utf-8")
    assert trace_to_events(trace) == trace_to_events(trace)


def test_trace_to_events_timestamps_stay_inside_window(tmp_path):
    trace = tmp_path / "UAD-x-2.txt"
    trace.write_text("120 " + "4 " * 40, encoding="utf-8")
    events = trace_to_events(trace, window_seconds=20.0)
    stamps = [event["timestamp"] for event in events]
    assert max(stamps) - min(stamps) <= 20.0
    assert stamps == sorted(stamps)


def test_trace_with_no_mapped_syscalls_yields_no_events(tmp_path):
    trace = tmp_path / "UVD-0001.txt"
    trace.write_text("3 6 240 45 91 240 3 6\n", encoding="utf-8")
    assert trace_to_events(trace) == []


def test_trace_to_events_rejects_non_positive_window(tmp_path):
    trace = tmp_path / "t.txt"
    trace.write_text("4\n", encoding="utf-8")
    with pytest.raises(TraceError):
        trace_to_events(trace, window_seconds=0)


def test_corpus_sessions_labels_the_three_splits(tmp_path):
    groups = corpus_sessions(_write_tree(tmp_path))
    assert len(groups["training"]) == len(TRAINING)
    assert len(groups["validation"]) == len(VALIDATION)
    assert len(groups["attack"]) == 3
    assert {label for _, _, label in groups["training"]} == {0}
    assert {label for _, _, label in groups["attack"]} == {1}


def test_corpus_sessions_rejects_missing_directory(tmp_path):
    (tmp_path / "ADFA-LD").mkdir()
    with pytest.raises(TraceError):
        corpus_sessions(tmp_path / "ADFA-LD")


def test_technique_of_strips_scenario_index():
    assert technique_of("attack/Adduser_1/UAD-Adduser-1-1371") == "Adduser"
    assert technique_of("attack/Hydra_SSH_1/t") == "Hydra_SSH"
    assert technique_of("validation/UVD-0001") == "benign"


# ------------------------------------------------------- n-gram reference ----

def test_ngrams_counts_contiguous_windows():
    assert ngrams([1, 2, 3, 4], 3) == {(1, 2, 3), (2, 3, 4)}
    assert ngrams([1, 2], 3) == set()
    with pytest.raises(ValueError):
        ngrams([1, 2], 0)


def test_ngram_novelty_scores_seen_sequences_as_zero():
    model = NgramNovelty(3).fit([[1, 2, 3, 4, 5]])
    assert model.score([1, 2, 3, 4]) == 0.0
    assert model.score([9, 9, 9]) == 1.0
    assert model.learned_ngrams == 3


def test_ngram_novelty_handles_trace_shorter_than_window():
    model = NgramNovelty(3).fit([[1, 2, 3]])
    assert model.score([7]) == 0.0


# ---------------------------------------------------------------- metrics ----

def test_metrics_confusion_matrix_and_intervals():
    result = metrics([1, 1, 0, 0], [1, 0, 1, 0])
    assert (result["tp"], result["fn"], result["fp"], result["tn"]) == (1, 1, 1, 1)
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["false_positive_rate"] == 0.5
    low, high = result["precision_ci95"]
    assert low < 0.5 < high


def test_metrics_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        metrics([1], [1, 0])


def test_wilson_interval_is_bounded_and_narrows_with_more_data():
    assert wilson_interval(0, 0) == (0.0, 0.0)
    wide = wilson_interval(5, 10)
    narrow = wilson_interval(50, 100)
    assert wide[0] >= 0.0 and wide[1] <= 1.0
    assert (narrow[1] - narrow[0]) < (wide[1] - wide[0])
    low, high = wilson_interval(0, 100)
    assert low == 0.0 and 0.0 < high < 0.06
    with pytest.raises(ValueError):
        wilson_interval(5, 3)


def test_roc_auc_is_threshold_free():
    assert roc_auc([0, 1], [0.1, 0.9]) == 1.0
    assert roc_auc([0, 1], [0.9, 0.1]) == 0.0
    assert roc_auc([0, 1, 0, 1], [0.5, 0.5, 0.5, 0.5]) == 0.5
    with pytest.raises(ValueError):
        roc_auc([1], [0.1, 0.2])
    assert roc_auc([0, 0], [0.1, 0.2]) == 0.0


# --------------------------------------------------------------- benchmark ----

def test_benchmark_runs_on_a_miniature_corpus(tmp_path):
    report = run_adfa_benchmark(_write_tree(tmp_path))
    assert report["format"] == "cabid-realworld-benchmark/1"
    assert set(report["models"]) >= {"cabid_core", "cabid_with_baseline",
                                     "syscall_ngram_3gram", "cabid_gate_disabled"}
    assert report["corpus"]["trace_counts"]["attack"] == 3
    assert report["limitations"] == LIMITATIONS
    assert 0.0 <= report["score_separation"]["cabid_anomaly_score_auc"] <= 1.0


def test_benchmark_report_never_claims_real_world_effectiveness(tmp_path):
    report = run_adfa_benchmark(_write_tree(tmp_path))
    blob = json.dumps(report).lower()
    assert "not evidence of real-world" in blob
    for banned in ("verdict", "confirmed intrusion", "proves"):
        assert banned not in blob


def test_benchmark_calibration_derives_a_floor_from_benign_traces(tmp_path):
    report = run_adfa_benchmark(_write_tree(tmp_path), calibration_percentile=0.5)
    calibration = report["calibration"]
    assert 0.0 <= calibration["completeness_minimum_ratio"] <= 1.0
    assert calibration["calibration_traces"] == 2
    assert calibration["method"].startswith("percentile")


def test_benchmark_declares_classes_the_corpus_can_emit(tmp_path):
    report = run_adfa_benchmark(_write_tree(tmp_path))
    classes = set(report["completeness_classes_used"])
    assert "heartbeat" not in classes
    assert "process_exit" not in classes
    assert default_config()["completeness"]["minimum_ratio"] == 1.0


def test_benchmark_is_reproducible(tmp_path):
    root = _write_tree(tmp_path)
    first = run_adfa_benchmark(root, seed=3)
    second = run_adfa_benchmark(root, seed=3)
    assert first["models"] == second["models"]
    assert first["calibration"] == second["calibration"]


def test_benchmark_rejects_bad_parameters(tmp_path):
    root = _write_tree(tmp_path)
    with pytest.raises(ValueError):
        run_adfa_benchmark(root, calibration_fraction=0.0)
    with pytest.raises(ValueError):
        run_adfa_benchmark(root, calibration_percentile=1.0)


def test_benchmark_separates_unmappable_traces(tmp_path):
    base = _write_tree(tmp_path)
    (base / "Validation_Data_Master" / "UVD-9000.txt").write_text("3 6 240 45\n",
                                                                  encoding="utf-8")
    report = run_adfa_benchmark(base)
    coverage = report["coverage"]
    assert coverage["unmappable_benign_traces"] == 1
    assert "models_mappable_only" in report
    assert (report["models_mappable_only"]["cabid_core"]["sample_count"]
            < report["models"]["cabid_core"]["sample_count"])


def test_threshold_curve_returns_monotone_cutoffs(tmp_path):
    curve = threshold_curve(_write_tree(tmp_path))
    rows = curve["curve"]
    assert rows
    assert [row["threshold"] for row in rows] == sorted(row["threshold"] for row in rows)


# ----------------------------------------------------------------- corpus ----

def _build_archive(tmp_path: Path, body: str = "4 5 6\n") -> tuple[Path, str]:
    archiveroot = tmp_path / "repo-abc123"
    tree = archiveroot / "ADFA-LD"
    (tree / "Training_Data_Master").mkdir(parents=True)
    (tree / "Training_Data_Master" / "UTD-0001.txt").write_text(body, encoding="utf-8")
    (tree / "Validation_Data_Master").mkdir()
    (tree / "Validation_Data_Master" / "UVD-0001.txt").write_text(body, encoding="utf-8")
    (tree / "Attack_Data_Master" / "Adduser_1").mkdir(parents=True)
    (tree / "Attack_Data_Master" / "Adduser_1" / "UAD-1.txt").write_text(body, encoding="utf-8")
    archive = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for path in sorted(archiveroot.rglob("*.txt")):
            bundle.write(path, path.relative_to(tmp_path).as_posix())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return archive, digest


@pytest.fixture
def local_corpus(tmp_path, monkeypatch):
    archive, digest = _build_archive(tmp_path)
    spec = dict(corpus.CORPORA["adfa-ld"])
    spec.update({
        "url": archive.as_uri(),
        "archive_sha256": digest,
        "files": 3,
        "member_prefix": "ADFA-LD/",
    })
    monkeypatch.setitem(corpus.CORPORA, "adfa-ld", spec)
    return tmp_path / "cache"


def test_catalogue_publishes_pinned_digests():
    entries = corpus.catalogue()
    assert entries and all(len(entry["archive_sha256"]) == 64 for entry in entries)
    assert all(entry["caveats"] for entry in entries)


def test_fetch_extracts_verifies_and_caches(local_corpus):
    manifest = corpus.fetch("adfa-ld", local_corpus)
    assert manifest["extracted_files"] == 3
    assert manifest["cache_hit"] is False
    second = corpus.fetch("adfa-ld", local_corpus)
    assert second["cache_hit"] is True
    assert corpus.verify("adfa-ld", local_corpus)["verified"] is True


def test_fetch_rejects_a_tampered_archive(local_corpus, tmp_path, monkeypatch):
    malformed, digest = _build_archive(tmp_path / "other", body="4\n")
    spec = dict(corpus.CORPORA["adfa-ld"])
    spec.update({"url": malformed.as_uri(), "archive_sha256": "0" * 64, "files": 3})
    monkeypatch.setitem(corpus.CORPORA, "adfa-ld", spec)
    with pytest.raises(corpus.CorpusError, match="checksum mismatch"):
        corpus.fetch("adfa-ld", local_corpus)
    assert not (local_corpus / "adfa-ld" / "archive.zip").exists()


def test_fetch_offline_without_cache_gives_actionable_error(local_corpus):
    with pytest.raises(corpus.CorpusError) as excinfo:
        corpus.fetch("adfa-ld", local_corpus, offline=True)
    assert "offline" in str(excinfo.value)


def test_unknown_corpus_is_rejected():
    with pytest.raises(corpus.CorpusError, match="unknown corpus"):
        corpus.fetch("no-such-corpus", "/tmp/cabid-none")


def test_verify_and_load_manifest_require_a_prior_fetch(tmp_path):
    with pytest.raises(corpus.CorpusError):
        corpus.verify("adfa-ld", tmp_path)
    with pytest.raises(corpus.CorpusError):
        corpus.load_manifest("adfa-ld", tmp_path)


def test_manifest_survives_json_round_trip(local_corpus):
    corpus.fetch("adfa-ld", local_corpus)
    reloaded = corpus.load_manifest("adfa-ld", local_corpus)
    assert reloaded["format"] == "cabid-corpus/1"
    assert reloaded["expected_files"] == 3


def test_extract_refuses_path_traversal(tmp_path, monkeypatch):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("repo-abc/ADFA-LD/../../escape.txt", "4\n")
    spec = dict(corpus.CORPORA["adfa-ld"])
    spec.update({"archive_sha256": "x", "files": 1})
    with pytest.raises(corpus.CorpusError, match="unsafe"):
        corpus._extract(archive, spec, tmp_path / "out")


def test_extract_reports_archive_without_the_corpus(tmp_path):
    archive = tmp_path / "empty.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("repo-abc/README.md", "hi")
    spec = dict(corpus.CORPORA["adfa-ld"])
    with pytest.raises(corpus.CorpusError, match="no members"):
        corpus._extract(archive, spec, tmp_path / "out")


def test_corrupt_cached_archive_is_replaced(local_corpus):
    root = local_corpus / "adfa-ld"
    root.mkdir(parents=True)
    (root / "archive.zip").write_bytes(b"not a zip")
    manifest = corpus.fetch("adfa-ld", local_corpus)
    assert manifest["extracted_files"] == 3
