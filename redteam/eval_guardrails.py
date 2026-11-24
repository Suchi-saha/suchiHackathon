"""Evaluate the guardrail functions on the holdout and benign sets. Writes an append-only report.

Usage:  .venv/bin/python redteam/eval_guardrails.py <run-label>
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.plugins.guardrails import injection_detected, normalize_unicode, redact_pii  # noqa: E402
from redteam.holdout import BENIGN, HOLDOUT_INJECTION, HOLDOUT_PII  # noqa: E402


def main(label: str) -> None:
    out_dir = ROOT / "reports" / "guardrails" / label
    if out_dir.exists():
        raise SystemExit(f"{out_dir} exists; evidence is append-only")
    out_dir.mkdir(parents=True)

    blocked = [t for t in HOLDOUT_INJECTION if injection_detected(normalize_unicode(t))]
    missed = [t for t in HOLDOUT_INJECTION if t not in blocked]
    inj_rate = len(blocked) / len(HOLDOUT_INJECTION) * 100

    pii_ok, pii_leak = [], []
    for text, markers in HOLDOUT_PII:
        redacted, _ = redact_pii(normalize_unicode(text))
        leaked = [m for m in markers if m.lower() in redacted.lower()]
        (pii_leak if leaked else pii_ok).append((text, leaked))
    pii_rate = len(pii_ok) / len(HOLDOUT_PII) * 100

    false_pos = [t for t in BENIGN if injection_detected(normalize_unicode(t))]
    fp_rate = len(false_pos) / len(BENIGN) * 100

    lines = [
        f"# Guardrail evaluation {label}",
        "",
        f"Date (UTC): {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"Holdout injection: {len(blocked)}/{len(HOLDOUT_INJECTION)} blocked ({inj_rate:.1f}%)",
        f"Holdout PII: {len(pii_ok)}/{len(HOLDOUT_PII)} redacted ({pii_rate:.1f}%)",
        f"Benign control: {len(false_pos)}/{len(BENIGN)} wrongly blocked ({fp_rate:.1f}% false refusal)",
        "",
        "## Missed holdout injections",
        *[f"- {t}" for t in missed],
        "",
        "## PII leaks after redaction",
        *[f"- {t!r} leaked {leaked}" for t, leaked in pii_leak],
        "",
        "## Benign queries wrongly blocked",
        *[f"- {t}" for t in false_pos],
    ]
    (out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:6]))


if __name__ == "__main__":
    main(sys.argv[1])
