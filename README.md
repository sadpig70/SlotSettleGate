# SlotSettleGate

> Does a time-boxed autonomous settlement run have valid slot authorization, pass settlement compliance rules, and remain within veto-escrow interrupt bounds?

`SlotSettleGate` combines three corpus mechanisms:

- **SlotGate** — fixed execution slots with re-authorization gates
- **SettleMesh** — pre-settlement compliance rule checks
- **VetoEscrow** — interruptible clearing gate for high-risk decisions

## What it is not

- Not a live payment processor or blockchain node.
- Not a slot scheduler or cron orchestrator.
- Not a regulatory rule authoring engine.

It verifies static audit packets and issues deterministic verdicts.

## Install / Run

Requires Python 3.10+ and no external packages.

```bash
python -m pip install -e .
python -m SlotSettleGate sample --out examples
python -m SlotSettleGate evaluate --input examples/authorized.json
python -m SlotSettleGate report --input output.json --out output.report.md
```

## Verdict scheme

| Verdict | Meaning |
|---|---|
| `authorized` | Slot, settlement, and veto-escrow checks satisfied |
| `review` | Partial compliance or elevated risk — human review required |
| `vetoed` | Hard gate failure — settlement must not proceed |

## Audit ledger

`evaluate --audit-log PATH` appends a SHA-256 hash-chained record per evaluation.

## Provenance

- recreate run: `005-slotsettlegate`
- sources: `SettleMesh` + `SlotGate` + `VetoEscrow`
- stdlib-only, deterministic, MIT

## License

MIT (c) Jung Wook Yang, 2026