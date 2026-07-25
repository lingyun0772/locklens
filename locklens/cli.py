"""locklens command-line interface.

Usage:
    locklens scan  <root> [--json]
    locklens report <root> [--json]
    locklens plan  <root> [--json] [--ports]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from .core import (
    LockFinding,
    PortFinding,
    RepairAction,
    build_plan,
    list_listening_ports,
    scan,
)


def _print_findings(findings: list[LockFinding]) -> None:
    if not findings:
        print("  (no locks with resolvable owner PID found)")
        return
    for f in findings:
        if f.orphan:
            tag = "ORPHAN"
        elif f.alive is True:
            tag = "alive"
        else:
            tag = "unknown"
        print(f"  [{tag:6}] pid={f.pid!s:>7}  {f.kind:12}  {f.path}")


def _print_ports(ports: dict[int, PortFinding]) -> None:
    if not ports:
        print("  (no listening ports parsed)")
        return
    for port in sorted(ports):
        pf = ports[port]
        flag = "  <-- CONFLICT" if pf.conflict else ""
        print(f"  port {port:>6} proto={pf.proto:4} pids={pf.pids}{flag}")


def _print_plan(actions: list[RepairAction]) -> None:
    if not actions:
        print("  (nothing to do — all clean)")
        return
    for a in actions:
        print(f"  [{a.severity:5}] {a.target}\n           -> {a.action}\n           ({a.reason})")


def cmd_scan(args: argparse.Namespace) -> int:
    findings = scan(args.root)
    if args.json:
        payload = [
            {
                "path": f.path,
                "pid": f.pid,
                "alive": f.alive,
                "kind": f.kind,
                "orphan": f.orphan,
            }
            for f in findings
        ]
        print(json.dumps({"root": args.root, "findings": payload}, ensure_ascii=False, indent=2))
    else:
        print(f"Scanning {args.root} ...")
        print(f"Lock findings: {len(findings)}")
        _print_findings(findings)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    findings = scan(args.root)
    ports = list_listening_ports() if args.ports else {}
    if args.json:
        print(
            json.dumps(
                {
                    "root": args.root,
                    "locks": [
                        {
                            "path": f.path,
                            "pid": f.pid,
                            "alive": f.alive,
                            "kind": f.kind,
                            "orphan": f.orphan,
                        }
                        for f in findings
                    ],
                    "ports": [
                        {"port": p, "pids": pf.pids, "conflict": pf.conflict}
                        for p, pf in sorted(ports.items())
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(f"=== locklens report: {args.root} ===")
        print(f"\nLock findings ({len(findings)}):")
        _print_findings(findings)
        if args.ports:
            print(f"\nListening ports ({len(ports)}):")
            _print_ports(ports)
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    findings = scan(args.root)
    ports = list_listening_ports() if args.ports else {}
    actions = build_plan(findings, ports)
    if args.json:
        print(
            json.dumps(
                {
                    "root": args.root,
                    "actions": [vars(a) for a in actions],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(f"=== repair plan (read-only, nothing applied) ===")
        _print_plan(actions)
        safe = sum(1 for a in actions if a.severity == "safe")
        print(f"\nSummary: {len(actions)} action(s), {safe} safe to auto-apply.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="locklens",
        description="Read-only health inspector for local agent runtimes.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="scan for lock/session owner PIDs")
    sp.add_argument("root", help="directory to scan (recursively)")
    sp.add_argument("--json", action="store_true", help="emit JSON")
    sp.set_defaults(func=cmd_scan)

    rp = sub.add_parser("report", help="full health report (locks + ports)")
    rp.add_argument("root", help="directory to scan")
    rp.add_argument("--json", action="store_true", help="emit JSON")
    rp.add_argument("--ports", action="store_true", help="include listening-port check")
    rp.set_defaults(func=cmd_report)

    pp = sub.add_parser("plan", help="produce a safe repair plan")
    pp.add_argument("root", help="directory to scan")
    pp.add_argument("--json", action="store_true", help="emit JSON")
    pp.add_argument("--ports", action="store_true", help="include listening-port check")
    pp.set_defaults(func=cmd_plan)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
