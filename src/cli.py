from __future__ import annotations

import argparse
from pathlib import Path

from .engine import assess
from .loader import load_events
from .reporting import render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess synthetic lateral-movement telemetry defensively.")
    parser.add_argument("--events", default="data/synthetic_events.json")
    parser.add_argument("--output", default="reports/generated-assessment.md")
    args = parser.parse_args()

    findings = assess(load_events(args.events))
    report = render_markdown(findings)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"wrote {len(findings)} findings to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
