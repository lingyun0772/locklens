"""Core detection logic for locklens.

Design principles (mirrors the operator's "repair tool must never depend on the
system being repaired" rule):

* Read-only by default. We never delete a lock file or kill a process.
* Pure standard library. Runs on any Python >= 3.9 with zero install.
* Cross-platform PID liveness via ``os.kill(pid, 0)`` (works on Win/linux/mac).
"""

from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Iterable, Optional

# ---- data model -----------------------------------------------------------


@dataclass
class LockFinding:
    path: str
    pid: Optional[int]
    alive: Optional[bool]  # None == could not determine
    kind: str              # "lockfile" | "session_jsonl"
    detail: str = ""

    @property
    def orphan(self) -> bool:
        """Owner process is confirmed dead (safe to clear)."""
        return self.pid is not None and self.alive is False


@dataclass
class PortFinding:
    port: int
    pids: list[int]
    proto: str = "tcp"

    @property
    def conflict(self) -> bool:
        return len(self.pids) > 1


@dataclass
class RepairAction:
    severity: str          # "safe" | "warn" | "info"
    target: str
    action: str
    reason: str


# ---- PID liveness ---------------------------------------------------------


def pid_alive(pid: Optional[int]) -> Optional[bool]:
    """Return True if the process exists, False if gone, None if unknown.

    Uses ``os.kill(pid, 0)`` which, on every supported platform, only checks
    for existence without delivering a signal.
    """
    if pid is None:
        return None
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        # Process exists but we lack signal permission -> it is alive.
        # (PermissionError subclasses OSError, so must be checked first.)
        return True
    except (ProcessLookupError, OSError, ValueError):
        # On Unix a missing PID raises ProcessLookupError; on Windows an
        # invalid/nonexistent PID raises OSError (WinError 87). Both mean
        # "does not exist".
        return False
    except NotImplementedError:
        return None
    except Exception:
        return None


# ---- PID parsers ----------------------------------------------------------


def parse_pid_from_lockfile(path: str) -> Optional[int]:
    """Best-effort PID extraction from a lock file.

    Handles: plain integer, JSON object with pid/owner_pid, and loose
    ``pid: 123`` / ``"pid": 123`` text.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            txt = fh.read().strip()
    except OSError:
        return None
    if not txt:
        return None
    if txt.isdigit():
        return int(txt)
    try:
        data = json.loads(txt)
        if isinstance(data, dict):
            for key in ("pid", "owner_pid", "ownerPid", "pid_"):
                if key in data:
                    try:
                        return int(data[key])
                    except (TypeError, ValueError):
                        pass
    except (ValueError, json.JSONDecodeError):
        pass
    m = re.search(r'"?pid"?\s*[:=]\s*(\d+)', txt, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


def parse_pid_from_jsonl(path: str, scan_lines: int = 8) -> Optional[int]:
    """Extract an owner PID from a session ``.jsonl`` (or any JSON-lines) file.

    Scans only the first few lines — lock metadata is normally at the top.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= scan_lines:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except (ValueError, json.JSONDecodeError):
                    data = None
                if isinstance(data, dict):
                    for key in ("pid", "owner_pid", "ownerPid"):
                        if key in data:
                            try:
                                return int(data[key])
                            except (TypeError, ValueError):
                                pass
                m = re.search(r'"?pid"?\s*[:=]\s*(\d+)', line, re.IGNORECASE)
                if m:
                    return int(m.group(1))
    except OSError:
        return None
    return None


# ---- scanning -------------------------------------------------------------


def _iter_files(root: str, patterns: Iterable[str]) -> Iterable[str]:
    root = os.path.expanduser(root)
    for pat in patterns:
        yield from glob.glob(os.path.join(root, "**", pat), recursive=True)


def scan(
    root: str,
    *,
    lock_patterns: Iterable[str] = ("*.lock", "*.lock.json", "*.pid"),
    session_patterns: Iterable[str] = ("*.jsonl",),
    skip_dirs: Iterable[str] = (".git", "node_modules", "__pycache__"),
    max_files: int = 20000,
) -> list[LockFinding]:
    """Scan a directory tree for lock files and session jsonl with owner PIDs.

    Only files whose parsed PID is non-None are returned as findings.
    """
    findings: list[LockFinding] = []
    seen_dirs = set()

    def _skipped(path: str) -> bool:
        parent = os.path.dirname(path)
        parts = set(os.path.normpath(parent).split(os.sep))
        return bool(parts & set(skip_dirs))

    count = 0
    for pat, kind, parser in (
        (tuple(lock_patterns), "lockfile", parse_pid_from_lockfile),
        (tuple(session_patterns), "session_jsonl", parse_pid_from_jsonl),
    ):
        for path in _iter_files(root, pat):
            count += 1
            if count > max_files:
                break
            if _skipped(path):
                continue
            pid = parser(path)
            if pid is None:
                continue
            findings.append(
                LockFinding(
                    path=path,
                    pid=pid,
                    alive=pid_alive(pid),
                    kind=kind,
                )
            )
        if count > max_files:
            break
    return findings


# ---- port conflicts -------------------------------------------------------


def list_listening_ports() -> dict[int, PortFinding]:
    """Parse listening sockets from ``netstat -ano`` (Windows) or fall back.

    Returns a mapping ``port -> PortFinding`` aggregating all PIDs bound to it.
    """
    cmd = ["netstat", "-ano"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = proc.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        try:
            out = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, timeout=20
            ).stdout.decode("utf-8", "replace")
        except (OSError, subprocess.SubprocessError):
            return {}

    ports: dict[int, PortFinding] = {}
    # Windows:  TCP    0.0.0.0:18786   0.0.0.0:0   LISTENING   1234
    # linux ss:  LISTEN 0 128 0.0.0.0:18786 0.0.0.0:*  users:(("node",pid=1234))
    win_re = re.compile(r"^\s*(TCP|UDP)\s+\S+:(\d+)\s+\S+\s+(?:LISTENING|CLOSE_WAIT)?\s*(\d*)", re.IGNORECASE)
    ss_re = re.compile(r":(\d+)\s")
    for line in out.splitlines():
        m = win_re.match(line)
        if m:
            proto = m.group(1).lower()
            port = int(m.group(2))
            pid_str = m.group(3).strip()
            pid = int(pid_str) if pid_str.isdigit() else None
        else:
            # ss style: find port + pid
            sm = ss_re.search(line)
            if not sm or "LISTEN" not in line.upper() and "tcp" not in line.lower():
                continue
            port = int(sm.group(1))
            pm = re.search(r"pid=(\d+)", line)
            pid = int(pm.group(1)) if pm else None
            proto = "tcp"
        if pid is None:
            continue
        if port not in ports:
            ports[port] = PortFinding(port=port, pids=[pid], proto=proto)
        elif pid not in ports[port].pids:
            ports[port].pids.append(pid)
    return ports


# ---- repair plan ----------------------------------------------------------


def build_plan(findings: list[LockFinding], ports: dict[int, PortFinding]) -> list[RepairAction]:
    """Produce safe, read-only repair suggestions. Never auto-applies."""
    actions: list[RepairAction] = []
    for f in findings:
        if f.orphan:
            actions.append(
                RepairAction(
                    severity="safe",
                    target=f.path,
                    action="remove orphan lock file",
                    reason=f"owner PID {f.pid} is not running (orphan-self-pid / non-openclaw-owner risk)",
                )
            )
        elif f.alive is True:
            actions.append(
                RepairAction(
                    severity="info",
                    target=f.path,
                    action="leave as-is",
                    reason=f"owner PID {f.pid} is alive; lock is legitimate",
                )
            )
        else:
            actions.append(
                RepairAction(
                    severity="warn",
                    target=f.path,
                    action="inspect manually",
                    reason=f"owner PID {f.pid} liveness unknown; do not clear blindly",
                )
            )
    for pf in ports.values():
        if pf.conflict:
            actions.append(
                RepairAction(
                    severity="warn",
                    target=f"port {pf.port}",
                    action="investigate duplicate binders",
                    reason=f"multiple PIDs bound: {pf.pids} (duplicate-instance / EADDRINUSE risk)",
                )
            )
    return actions
