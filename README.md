# locklens

> Read-only health inspector for local agent runtimes — find orphaned session
> locks, duplicate processes, and port conflicts **before** they break your agents.

`locklens` is a tiny, dependency-free Python tool born from real pain: a portable
OpenClaw/Hermes deployment that kept hitting `orphan-self-pid`,
`non-openclaw-owner`, and `EADDRINUSE` lock/port conflicts. Every repair tool in
that world follows one iron rule — **it must never depend on the system being
repaired**. `locklens` does exactly that: it only *reads* files, processes, and
ports, then reports and suggests. It never deletes a lock or kills a process.

## Why

Local multi-agent runtimes (OpenClaw, Hermes, and friends) use per-session
`.jsonl` files and lock files with an owner PID. When a process crashes, its
lock is left behind; the next instance sees a "live" owner that isn't there and
refuses to start, or two instances fight over the same port. `locklens` finds
these before they bite.

## Features

- **Zero dependencies** — pure Python standard library, runs on Python ≥ 3.9.
- **Cross-platform PID liveness** via `os.kill(pid, 0)` (Windows / Linux / macOS).
- **Lock scanning** — `*.lock`, `*.lock.json`, `*.pid`, and session `*.jsonl`
  with owner PIDs parsed from plain int, JSON, or loose `pid: N` text.
- **Port conflict detection** — parses `netstat -ano` (Windows) / `ss -tlnp`
  (Linux) to spot duplicate binders.
- **Safe repair plan** — orphan locks flagged `safe` to clear; live locks left
  alone; unknown liveness flagged `warn`. Nothing is ever applied automatically.

## Install

```bash
pip install locklens        # (after publish)
# or, zero-install, portable:
python -m locklens.cli scan /path/to/runtime
```

## Usage

```bash
# Scan a runtime directory for lock/session owner PIDs
python -m locklens.cli scan E:\openclaw\.openclaw

# Full report including listening ports
python -m locklens.cli report E:\openclaw\.openclaw --ports

# Produce a safe, read-only repair plan
python -m locklens.cli plan E:\openclaw\.openclaw --ports

# Machine-readable output
python -m locklens.cli report E:\openclaw\.openclaw --json
```

### Example

```
=== repair plan (read-only, nothing applied) ===
  [safe ] E:\openclaw\.openclaw\agents\main\session.jsonl
           -> remove orphan lock file
           (owner PID 12345 is not running (orphan-self-pid / non-openclaw-owner risk))
  [warn ] port 18786
           -> investigate duplicate binders
           (multiple PIDs bound: [9001, 9002] (duplicate-instance / EADDRINUSE risk))

Summary: 2 action(s), 1 safe to auto-apply.
```

## Tests

```bash
python tests/test_core.py     # standalone, no install
pytest                        # if pytest is available
```

## License

MIT
