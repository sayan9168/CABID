from cabid.ingest import normalize_many
from cabid.skew import MAX_PLAUSIBLE_SKEW, MIN_PAIRS, estimate_skew


def two_sources(shift: float, repeats: int = 12):
    rows = []
    stamp = 1000.0
    for index in range(repeats):
        name = ["sshd", "cron", "nginx"][index % 3]
        rows.append({"timestamp": stamp, "event_type": "process_start",
                     "process_id": 100 + index, "parent_process_id": 1,
                     "process_name": name, "source": "hostA"})
        rows.append({"timestamp": stamp + shift, "event_type": "process_start",
                     "process_id": 200 + index, "parent_process_id": 1,
                     "process_name": name, "source": "hostB"})
        stamp += 30
    return normalize_many(rows)


def test_single_source_cannot_estimate_skew():
    report = estimate_skew(normalize_many([
        {"timestamp": 1, "event_type": "heartbeat", "process_id": 1,
         "parent_process_id": 0, "process_name": "a"}]))
    assert report["sources_compared"] == 1
    assert report["skew_detected"] is False
    assert report["offsets"] == {}
    assert "cannot be estimated" in report["notes"][0]


def test_consistent_offset_is_detected_but_not_applied():
    report = estimate_skew(two_sources(40.0))
    assert report["skew_detected"] is True
    assert report["confident_offsets"] == {"hostB": 40.0}
    assert report["applied"] is False
    assert "No correction is applied automatically" in report["notes"][1]


def test_aligned_sources_report_no_skew():
    report = estimate_skew(two_sources(0.0))
    assert report["skew_detected"] is False
    assert report["confident_offsets"] == {}


def test_too_few_matched_pairs_produces_no_estimate():
    report = estimate_skew(two_sources(40.0, repeats=2))
    entry = report["offsets"]["hostB"]
    assert entry["estimated_offset_seconds"] is None
    assert entry["confident"] is False
    assert str(MIN_PAIRS) in entry["reason"]
    assert report["skew_detected"] is False


def test_reference_source_is_the_largest():
    rows = []
    for index in range(4):
        rows.append({"timestamp": float(index), "event_type": "heartbeat",
                     "process_id": index + 1, "parent_process_id": 0,
                     "process_name": "big", "source": "big"})
    rows.append({"timestamp": 1.0, "event_type": "heartbeat", "process_id": 99,
                 "parent_process_id": 0, "process_name": "big", "source": "small"})
    report = estimate_skew(normalize_many(rows))
    assert report["reference_source"] == "big"


def test_sign_convention_is_documented():
    report = estimate_skew(two_sources(40.0))
    assert any("positive means the source clock is ahead" in note for note in report["notes"])


def test_implausible_gap_is_not_used_as_a_pair():
    rows = []
    for index in range(8):
        rows.append({"timestamp": float(index * 10), "event_type": "heartbeat",
                     "process_id": index + 1, "parent_process_id": 0, "process_name": "x",
                     "source": "a"})
        rows.append({"timestamp": float(index * 10) + MAX_PLAUSIBLE_SKEW * 10,
                     "event_type": "heartbeat", "process_id": 50 + index,
                     "parent_process_id": 0, "process_name": "x", "source": "b"})
    report = estimate_skew(normalize_many(rows))
    assert report["offsets"]["b"]["matched_pairs"] == 0
    assert report["skew_detected"] is False


def test_aggregate_notes_surface_a_detected_offset(tmp_path):
    import json

    from cabid.aggregate import ingest_sources

    for label, shift in (("hostA", 0.0), ("hostB", 40.0)):
        rows = []
        stamp = 1000.0
        for index in range(12):
            rows.append({"timestamp": stamp + shift, "event_type": "process_start",
                         "process_id": 100 + index, "parent_process_id": 1,
                         "process_name": ["sshd", "cron", "nginx"][index % 3]})
            stamp += 30
        (tmp_path / f"{label}.jsonl").write_text(
            "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    merged = ingest_sources([tmp_path / "hostA.jsonl", tmp_path / "hostB.jsonl"])
    assert merged["clock_skew"]["skew_detected"] is True
    assert any("clock offset" in note for note in merged["notes"])
    assert any("not applied" in note for note in merged["notes"])
