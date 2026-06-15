from __future__ import annotations

import argparse
from pathlib import Path
import sys

import uvicorn

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from sangraph_logging import setup_logging


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the SanGraph web API server.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8010, help="Bind port")
    parser.add_argument("--reload", action="store_true", help="Enable autoreload")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging()
    run_kwargs = {
        "host": args.host,
        "port": args.port,
        "reload": args.reload,
        "log_config": None,
    }
    if args.reload:
        # Restrict autoreload to source code so generated validation artifacts do not restart the API.
        run_kwargs["reload_dirs"] = [str(SRC_DIR)]
    uvicorn.run("webapp.app:app", **run_kwargs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
