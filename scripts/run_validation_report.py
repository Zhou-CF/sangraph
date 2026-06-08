from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from sangraph_logging import setup_logging
from validation_opencode.agent import run_validation_with_audit


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a vulnerability report against a repository.")
    parser.add_argument("--report-path", required=True, help="Path to the report file to validate")
    parser.add_argument("--repo-path", required=True, help="Path to the target repository")
    parser.add_argument("--audit-dir", help="Optional directory for validation artifacts")
    return parser.parse_args(argv)


async def _run(args: argparse.Namespace) -> dict:
    result = await run_validation_with_audit(
        report_path=args.report_path,
        repo_path=args.repo_path,
        audit_dir=args.audit_dir,
    )
    return {
        "report_path": result["report_path"],
        "repo_path": result["repo_path"],
        "audit_dir": result["audit_dir"],
        "workspace_dir": result["workspace_dir"],
        "result": result["result"].model_dump(mode="json"),
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging()
    payload = asyncio.run(_run(args))
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
