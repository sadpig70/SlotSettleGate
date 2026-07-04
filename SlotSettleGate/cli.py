"""CLI entry point: sample / evaluate / report."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from .engine import AuditLogger, evaluate_packet
from .report import render_markdown_report


def sample_packet(verdict_kind="authorized"):
    base = {
        "run_id": "RUN-AUTHORIZED-001",
        "slot": {
            "slot_id": "SLOT-001",
            "slot_start_unix": 1_700_000_000,
            "slot_end_unix": 1_700_000_300,
            "execution_unix": 1_700_000_120,
            "duration_limit_sec": 300,
            "reauth_required": False,
            "reauth_granted": True,
            "authorization_hash": "a" * 64,
        },
        "settlement": {
            "amount_usd": 1500.0,
            "rules_passed": 4,
            "rules_total": 4,
            "compliance_score": 0.98,
            "jurisdiction": "US",
        },
        "veto_escrow": {
            "risk_score": 0.25,
            "escrow_active": True,
            "veto_threshold": 0.8,
            "interrupt_requested": False,
        },
    }

    if verdict_kind == "review":
        base["run_id"] = "RUN-REVIEW-001"
        base["settlement"]["compliance_score"] = 0.92
        base["veto_escrow"]["risk_score"] = 0.62
    elif verdict_kind == "vetoed":
        base["run_id"] = "RUN-VETOED-001"
        base["slot"]["execution_unix"] = 1_700_000_400
        base["settlement"]["rules_passed"] = 2
        base["veto_escrow"]["interrupt_requested"] = True

    return base


def write_samples(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    mapping = {
        "authorized.json": sample_packet("authorized"),
        "review.json": sample_packet("review"),
        "vetoed.json": sample_packet("vetoed"),
    }
    for name, packet in mapping.items():
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(packet, handle, indent=2, sort_keys=True)
    return mapping


def main(args_list=None):
    parser = argparse.ArgumentParser(
        description="SlotSettleGate: time-boxed settlement authorization gate"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sample_parser = sub.add_parser("sample", help="write example packets")
    sample_parser.add_argument("--out", default="examples", help="output directory")

    eval_parser = sub.add_parser("evaluate", help="evaluate a packet JSON file")
    eval_parser.add_argument("--input", default="examples/authorized.json")
    eval_parser.add_argument("--output", default="output.json")
    eval_parser.add_argument("--audit-log", default="audit_log.json")

    report_parser = sub.add_parser("report", help="render markdown report")
    report_parser.add_argument("--input", default="output.json")
    report_parser.add_argument("--out", default="output.report.md")

    args = parser.parse_args(args_list if args_list is not None else sys.argv[1:])

    if args.command == "sample":
        mapping = write_samples(args.out)
        print(f"[SlotSettleGate] wrote {len(mapping)} sample packets to {args.out}/")
        return 0

    if args.command == "evaluate":
        if not os.path.exists(args.input):
            print(f"[Error] input not found: {args.input}", file=sys.stderr)
            return 1
        with open(args.input, encoding="utf-8") as handle:
            packet = json.load(handle)
        result = evaluate_packet(packet)
        logger = AuditLogger(args.audit_log)
        audit_entry = logger.append(
            packet, result, datetime.now(timezone.utc).isoformat()
        )
        if not logger.verify_chain():
            print("[Warning] audit chain verification failed", file=sys.stderr)
        output = {"packet": packet, "result": result, "audit_entry": audit_entry}
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2, sort_keys=True)
        print(f"[SlotSettleGate] verdict={result['verdict']} -> {args.output}")
        return 0

    if args.command == "report":
        if not os.path.exists(args.input):
            print(f"[Error] input not found: {args.input}", file=sys.stderr)
            return 1
        with open(args.input, encoding="utf-8") as handle:
            payload = json.load(handle)
        report = render_markdown_report(
            payload.get("packet", {}),
            payload.get("result", {}),
            payload.get("audit_entry", {}),
        )
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(report)
        print(f"[SlotSettleGate] report -> {args.out}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())