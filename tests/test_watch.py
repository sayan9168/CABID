import json

from cabid.watch import WatchState, watch_file


def write(path, rows):
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")


def test_watch_state_scores_only_new_data(tmp_path):
    path = tmp_path / "stream.jsonl"
    write(path, [{"timestamp": 100 + i, "event_type": "heartbeat", "process_id": 1} for i in range(3)])
    state = WatchState(window_seconds=60)
    assert len(state.read_new(path)) == 3
    assert state.read_new(path) == []
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"timestamp": 110, "event_type": "process_start", "process_id": 5}) + "\n")
    assert len(state.read_new(path)) == 1
    report = state.score()
    assert report["event_count"] == 4
    assert report["watch"]["buffered_events"] == 4
    assert report["watch"]["window_seconds"] == 60


def test_partial_trailing_line_is_buffered(tmp_path):
    path = tmp_path / "stream.jsonl"
    path.write_text('{"timestamp":1,"event_type":"heartbeat","process_id":1}\n{"timestamp":2,"ev',
                    encoding="utf-8")
    state = WatchState()
    assert len(state.read_new(path)) == 1
    with path.open("a", encoding="utf-8") as handle:
        handle.write('ent_type":"process_start","process_id":2}\n')
    assert len(state.read_new(path)) == 1
    assert state.window()[-1]["event_type"] == "process_start"


def test_invalid_lines_are_counted_not_fatal(tmp_path):
    path = tmp_path / "stream.jsonl"
    path.write_text('not json\n{"timestamp":1,"event_type":"bogus","process_id":1}\n'
                    '{"timestamp":2,"event_type":"heartbeat","process_id":1}\n', encoding="utf-8")
    state = WatchState()
    state.read_new(path)
    assert state.invalid_lines == 2
    assert state.score()["watch"]["invalid_lines"] == 2


def test_window_drops_stale_events(tmp_path):
    path = tmp_path / "stream.jsonl"
    write(path, [{"timestamp": 0, "event_type": "heartbeat", "process_id": 1},
                 {"timestamp": 500, "event_type": "heartbeat", "process_id": 1}])
    state = WatchState(window_seconds=100)
    state.read_new(path)
    assert [event["timestamp"] for event in state.window()] == [500.0]


def test_watch_file_reports_per_poll(tmp_path):
    path = tmp_path / "stream.jsonl"
    write(path, [{"timestamp": 1, "event_type": "heartbeat", "process_id": 1}])
    seen = []
    reports = watch_file(path, window_seconds=60, interval=0.01, iterations=2,
                         on_report=seen.append, sleep=lambda _: None)
    assert len(reports) == 2 and len(seen) == 2
    assert reports[-1]["watch"]["batch"] == 2


def test_max_events_bounds_the_window(tmp_path):
    path = tmp_path / "stream.jsonl"
    write(path, [{"timestamp": i, "event_type": "heartbeat", "process_id": 1} for i in range(10)])
    state = WatchState(window_seconds=1000, max_events=4)
    state.read_new(path)
    assert len(state.window()) == 4
    assert state.window()[-1]["timestamp"] == 9.0
