"""locklens core tests — run with `python tests/test_core.py` or `pytest`."""

import json
import os
import tempfile
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from locklens.core import (
    build_plan,
    parse_pid_from_jsonl,
    parse_pid_from_lockfile,
    pid_alive,
    scan,
)


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def test_pid_alive_self():
    assert pid_alive(os.getpid()) is True


def test_pid_alive_dead():
    # A PID far above any real process id is reliably gone on every OS.
    assert pid_alive(2_147_483_647) is False
    assert pid_alive(None) is None


def test_parse_lockfile_plain_int():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x.lock")
        _write(p, "1234")
        assert parse_pid_from_lockfile(p) == 1234


def test_parse_lockfile_json():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x.lock.json")
        _write(p, json.dumps({"owner_pid": 5678}))
        assert parse_pid_from_lockfile(p) == 5678


def test_parse_lockfile_loose():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x.lock")
        _write(p, 'some text pid: 42 and more')
        assert parse_pid_from_lockfile(p) == 42


def test_parse_jsonl():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "sess.jsonl")
        _write(p, json.dumps({"event": "lock", "pid": 9001}) + "\n" +
                   json.dumps({"event": "msg", "text": "hi"}))
        assert parse_pid_from_jsonl(p) == 9001


def test_scan_finds_orphan_and_alive():
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "alive.lock"), str(os.getpid()))
        _write(os.path.join(d, "dead.lock"), "2147483647")
        findings = scan(d)
        by_name = {os.path.basename(f.path): f for f in findings}
        assert "alive.lock" in by_name
        assert by_name["alive.lock"].alive is True
        assert "dead.lock" in by_name
        assert by_name["dead.lock"].orphan is True


def test_build_plan_safe_for_orphan():
    with tempfile.TemporaryDirectory() as d:
        _write(os.path.join(d, "dead.lock"), "2147483647")
        findings = scan(d)
        plan = build_plan(findings, {})
        assert any(a.severity == "safe" and a.target.endswith("dead.lock") for a in plan)


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except Exception as e:  # noqa
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
