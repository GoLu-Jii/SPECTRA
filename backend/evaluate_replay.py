"""Command-line entry point for passive Zeek replay evaluation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from backend.evaluation import evaluate_zeek_directory


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--zeek-dir",
        required=True,
        type=Path,
        help="Directory containing Zeek .log files",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for the JSON evaluation summary",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = evaluate_zeek_directory(args.zeek_dir)
    rendered = json.dumps(summary, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
