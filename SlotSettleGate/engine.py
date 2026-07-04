"""Deterministic time-boxed settlement authorization engine (stdlib only)."""

import hashlib
import json
import os
import re

SEVERITY = {"authorized": 0, "review": 1, "vetoed": 2}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _verdict(name, verdict, reason):
    return {"name": name, "verdict": verdict, "reason": reason}


def _missing(required, obj):
    if not isinstance(obj, dict):
        return list(required)
    return [k for k in required if k not in obj or obj[k] in ("", None)]


def _max_verdict(current, new):
    if SEVERITY[new] > SEVERITY[current]:
        return new
    return current


def check_slot(slot):
    required = [
        "slot_id",
        "slot_start_unix",
        "slot_end_unix",
        "execution_unix",
        "duration_limit_sec",
        "reauth_required",
        "reauth_granted",
        "authorization_hash",
    ]
    miss = _missing(required, slot)
    if miss:
        return _verdict("slot", "vetoed", f"missing fields: {', '.join(miss)}")

    auth_hash = str(slot.get("authorization_hash", ""))
    if not SHA256_RE.fullmatch(auth_hash):
        return _verdict("slot", "vetoed", "invalid authorization_hash sha256 hex")

    start = int(slot["slot_start_unix"])
    end = int(slot["slot_end_unix"])
    execution = int(slot["execution_unix"])
    duration = int(slot["duration_limit_sec"])

    if end <= start:
        return _verdict("slot", "vetoed", "slot_end_unix must be after slot_start_unix")
    if duration <= 0:
        return _verdict("slot", "vetoed", "duration_limit_sec must be positive")
    if (end - start) > duration:
        return _verdict("slot", "vetoed", "slot window exceeds duration_limit_sec")

    if execution < start or execution > end:
        return _verdict("slot", "vetoed", "execution_unix outside slot window")

    if slot.get("reauth_required") is True and slot.get("reauth_granted") is not True:
        return _verdict("slot", "vetoed", "re-authorization required but not granted")

    span = end - start
    elapsed = execution - start
    if span > 0 and elapsed / span >= 0.9 and slot.get("reauth_required") is True:
        return _verdict("slot", "review", "execution near slot end with reauth policy active")

    return _verdict("slot", "authorized", "slot authorization valid")


def check_settlement(settlement):
    required = [
        "amount_usd",
        "rules_passed",
        "rules_total",
        "compliance_score",
        "jurisdiction",
    ]
    miss = _missing(required, settlement)
    if miss:
        return _verdict("settlement", "vetoed", f"missing fields: {', '.join(miss)}")

    rules_passed = int(settlement["rules_passed"])
    rules_total = int(settlement["rules_total"])
    compliance = float(settlement["compliance_score"])
    amount = float(settlement["amount_usd"])

    if rules_total <= 0:
        return _verdict("settlement", "vetoed", "rules_total must be positive")
    if rules_passed < 0 or rules_passed > rules_total:
        return _verdict("settlement", "vetoed", "rules_passed out of range")
    if amount < 0:
        return _verdict("settlement", "vetoed", "amount_usd must be non-negative")
    if compliance < 0.0 or compliance > 1.0:
        return _verdict("settlement", "vetoed", "compliance_score must be between 0 and 1")

    if rules_passed < rules_total:
        if rules_passed < (rules_total * 0.75):
            return _verdict(
                "settlement",
                "vetoed",
                f"only {rules_passed}/{rules_total} settlement rules passed",
            )
        return _verdict(
            "settlement",
            "review",
            f"partial compliance: {rules_passed}/{rules_total} rules passed",
        )

    if compliance < 0.85:
        return _verdict("settlement", "vetoed", f"compliance_score {compliance} below floor 0.85")
    if compliance < 0.95:
        return _verdict("settlement", "review", f"compliance_score {compliance} below target 0.95")

    return _verdict("settlement", "authorized", "settlement compliance satisfied")


def check_veto_escrow(veto):
    required = [
        "risk_score",
        "escrow_active",
        "veto_threshold",
        "interrupt_requested",
    ]
    miss = _missing(required, veto)
    if miss:
        return _verdict("veto_escrow", "vetoed", f"missing fields: {', '.join(miss)}")

    risk = float(veto["risk_score"])
    threshold = float(veto["veto_threshold"])

    if risk < 0.0 or risk > 1.0:
        return _verdict("veto_escrow", "vetoed", "risk_score must be between 0 and 1")
    if threshold <= 0.0 or threshold > 1.0:
        return _verdict("veto_escrow", "vetoed", "veto_threshold must be between 0 and 1")
    if veto.get("escrow_active") is not True:
        return _verdict("veto_escrow", "vetoed", "veto escrow not active")
    if veto.get("interrupt_requested") is True:
        return _verdict("veto_escrow", "vetoed", "interrupt requested on veto escrow")

    if risk >= threshold:
        return _verdict("veto_escrow", "vetoed", f"risk_score {risk} at or above veto_threshold {threshold}")
    if risk >= threshold * 0.75:
        return _verdict("veto_escrow", "review", f"risk_score {risk} approaching veto_threshold {threshold}")

    return _verdict("veto_escrow", "authorized", "veto escrow bounds satisfied")


def evaluate_packet(packet):
    """Evaluate a settlement authorization packet and return a k-way verdict."""
    if not isinstance(packet, dict):
        return {
            "verdict": "vetoed",
            "checks": [_verdict("packet", "vetoed", "packet must be a JSON object")],
            "reasons": ["packet must be a JSON object"],
        }

    checks = []
    reasons = []
    final = "authorized"

    for name, section, checker in (
        ("slot", packet.get("slot", {}), check_slot),
        ("settlement", packet.get("settlement", {}), check_settlement),
        ("veto_escrow", packet.get("veto_escrow", {}), check_veto_escrow),
    ):
        result = checker(section)
        checks.append(result)
        final = _max_verdict(final, result["verdict"])
        if result["verdict"] != "authorized":
            reasons.append(f"{name}: {result['reason']}")

    if final == "authorized":
        reasons.append("slot, settlement, and veto-escrow checks all satisfied")

    return {"verdict": final, "checks": checks, "reasons": reasons}


class AuditLogger:
    """Append-only SHA-256 hash-chained audit ledger."""

    def __init__(self, log_path="audit_log.json"):
        self.log_path = log_path

    def _hash_entry(self, entry):
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def load_log(self):
        if not os.path.exists(self.log_path):
            return []
        try:
            with open(self.log_path, encoding="utf-8") as handle:
                content = handle.read().strip()
                if not content:
                    return []
                return json.loads(content)
        except (OSError, json.JSONDecodeError):
            return []

    def append(self, packet, result, timestamp):
        entries = self.load_log()
        previous_hash = "0" * 64
        if entries:
            previous_hash = entries[-1].get("entry_hash", "0" * 64)

        input_hash = hashlib.sha256(
            json.dumps(packet, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        entry = {
            "timestamp": timestamp,
            "run_id": packet.get("run_id", ""),
            "input_hash": input_hash,
            "verdict": result["verdict"],
            "previous_hash": previous_hash,
        }
        entry["entry_hash"] = self._hash_entry(entry)
        entries.append(entry)

        with open(self.log_path, "w", encoding="utf-8") as handle:
            json.dump(entries, handle, indent=2, sort_keys=True)

        return entry

    def verify_chain(self):
        entries = self.load_log()
        if not entries:
            return True

        expected_prev = "0" * 64
        for entry in entries:
            if entry.get("previous_hash") != expected_prev:
                return False
            temp = entry.copy()
            actual = temp.pop("entry_hash", None)
            if self._hash_entry(temp) != actual:
                return False
            expected_prev = actual
        return True