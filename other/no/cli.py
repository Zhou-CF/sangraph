from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .builder import build_index, default_db_path
from .models import SearchFilters
from .search import search_cases


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Non-vector sanitizer RAG index builder and search CLI.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser("build", help="Build a SQLite FTS5 index from sanitizer case data.")
    build_parser.add_argument("--input", default="unsafe_sanitzer_enriched_incomplete_only.with_patches.json")
    build_parser.add_argument("--labels", default="unsafe_sanitzer_source_labels.jsonl")
    build_parser.add_argument("--output", default=str(default_db_path()))
    build_parser.add_argument("--force", action="store_true")

    search_parser = subparsers.add_parser("search", help="Search the SQLite FTS5 sanitizer case index.")
    search_parser.add_argument("--db", default=str(default_db_path()))
    search_parser.add_argument("--query", required=True)
    search_parser.add_argument("--top-k", type=int, default=10)
    search_parser.add_argument("--language", default="")
    search_parser.add_argument("--source-type", default="")
    search_parser.add_argument("--sanitizer", default="")
    search_parser.add_argument("--cwe", default="")
    search_parser.add_argument("--project", default="")
    search_parser.add_argument("--vendor", default="")
    search_parser.add_argument("--json", action="store_true")
    search_parser.add_argument("--show-reasons", action="store_true")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "build":
        summary = build_index(args.input, args.labels, args.output, force=args.force)
        print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
        return 0

    filters = SearchFilters(
        languages=tuple(split_csv(args.language)),
        source_types=tuple(split_csv(args.source_type)),
        sanitizer_names=tuple(split_csv(args.sanitizer)),
        cwe_ids=tuple(split_csv(args.cwe)),
        projects=tuple(split_csv(args.project)),
        vendors=tuple(split_csv(args.vendor)),
    )
    response = search_cases(args.query, top_k=args.top_k, filters=filters, db_path=Path(args.db))
    if args.json:
        print(json.dumps(response.to_dict(), ensure_ascii=False, indent=2))
        return 0

    for index, item in enumerate(response.results, start=1):
        print(f"[{index}] {item.cve_id} score={item.score:.3f} :: {item.title}")
        print(f"    summary: {item.summary}")
        print(f"    matched: {json.dumps(item.matched_fields, ensure_ascii=False)}")
        if args.show_reasons:
            print(f"    reason: {item.reason}")
    return 0


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]
