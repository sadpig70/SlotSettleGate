"""Markdown report renderer for SlotSettleGate verdicts."""

import json


def render_markdown_report(packet, result, audit_entry):
    verdict = result["verdict"]
    status = {
        "authorized": "AUTHORIZED",
        "review": "REVIEW",
        "vetoed": "VETOED",
    }

    lines = [
        "# SlotSettleGate Audit Report",
        "",
        f"## Final Verdict: {status.get(verdict, verdict)}",
        "",
        "### Check Results",
    ]
    for check in result.get("checks", []):
        lines.append(f"- **{check['name']}** ({check['verdict']}): {check['reason']}")
    lines.append("")
    lines.append("### Reasons")
    for reason in result.get("reasons", []):
        lines.append(f"- {reason}")
    lines.append("")
    lines.append("### Input Packet")
    lines.append("```json")
    lines.append(json.dumps(packet, indent=2, sort_keys=True))
    lines.append("```")
    lines.append("")
    lines.append("### Audit Entry")
    lines.append(f"- timestamp: `{audit_entry.get('timestamp', '')}`")
    lines.append(f"- run_id: `{audit_entry.get('run_id', '')}`")
    lines.append(f"- input_hash: `{audit_entry.get('input_hash', '')}`")
    lines.append(f"- previous_hash: `{audit_entry.get('previous_hash', '')}`")
    lines.append(f"- entry_hash: `{audit_entry.get('entry_hash', '')}`")
    lines.append("")
    return "\n".join(lines)