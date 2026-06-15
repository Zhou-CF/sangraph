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

from base_opencode import run_analysis_with_audit
from sangraph_logging import setup_logging


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze a patch or sanitizer code.")
    parser.add_argument(
        "--repo-path",
        help="Optional path to the target repository for deeper context analysis",
    )
    parser.add_argument("--patch-path", help="Path to the patch file to analyze")

    sanitizer_group = parser.add_mutually_exclusive_group()
    sanitizer_group.add_argument("--sanitizer-code", help="Direct sanitizer code content to analyze")
    sanitizer_group.add_argument("--sanitizer-code-file", help="Path to a file containing sanitizer code")

    parser.add_argument("--audit-dir", help="Optional directory for analysis artifacts")
    parser.add_argument(
        "--analysis-profile",
        choices=["standard", "enhanced_search"],
        default="standard",
        help="Analysis profile to use",
    )

    args = parser.parse_args(argv)

    input_modes = [
        bool((args.patch_path or "").strip()),
        bool((args.sanitizer_code or "").strip()),
        bool((args.sanitizer_code_file or "").strip()),
    ]
    if sum(input_modes) != 1:
        parser.error("Exactly one of --patch-path, --sanitizer-code, or --sanitizer-code-file must be provided.")

    return args


def _load_sanitizer_code(args: argparse.Namespace) -> str | None:
    if args.sanitizer_code is not None:
        return args.sanitizer_code
    if args.sanitizer_code_file is not None:
        return Path(args.sanitizer_code_file).read_text(encoding="utf-8")
    return None


async def _run(args: argparse.Namespace) -> dict:
    sanitizer_code = _load_sanitizer_code(args)
    result = await run_analysis_with_audit(
        repo_path=args.repo_path,
        patch_path=args.patch_path,
        sanitizer_code=sanitizer_code,
        audit_dir=args.audit_dir,
        analysis_profile=args.analysis_profile,
    )
    return {
        "repo_path": result.get("repo_path", ""),
        "patch_path": result.get("patch_path", ""),
        "input_mode": result.get("input_mode"),
        "input_source": result.get("input_source"),
        "audit_dir": str(result.get("audit_dir", args.audit_dir or "")),
        "final_verdict_source": result.get("final_verdict_source", ""),
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
