"""locklens — read-only health inspector for local agent runtimes."""

__version__ = "0.1.0"

from .core import (
    LockFinding,
    PortFinding,
    pid_alive,
    parse_pid_from_lockfile,
    parse_pid_from_jsonl,
    scan,
    list_listening_ports,
    build_plan,
)

__all__ = [
    "LockFinding",
    "PortFinding",
    "pid_alive",
    "parse_pid_from_lockfile",
    "parse_pid_from_jsonl",
    "scan",
    "list_listening_ports",
    "build_plan",
]
