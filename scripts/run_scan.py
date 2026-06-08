from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from sangraph_logging import setup_logging
from scanner.scan import DEFAULT_SAVE_PATH, main as run_scan


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan a repository for sanitizer candidates.")
    parser.add_argument("--project-path", required=True, help="Path to the repository to scan")
    parser.add_argument("--save-path", default=str(DEFAULT_SAVE_PATH), help="Path to the JSON output file")
    parser.add_argument("--debug-save-path", help="Optional JSONL file for all scan decisions, including rejected snippets")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging()
    run_scan(args.project_path, args.save_path, args.debug_save_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
