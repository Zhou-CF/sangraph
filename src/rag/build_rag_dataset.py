from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from json_repair import repair_json
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import PydanticOutputParser
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from tqdm import tqdm

load_dotenv(override=True)

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parents[1]
DATA_DIR = REPO_ROOT / "other" / "data"
PROMPT_DIR = PACKAGE_DIR / "prompt"
DEFAULT_INPUT_PATH = DATA_DIR / "verified_sanitizer_dataset.jsonl"
DEFAULT_OUTPUT_PATH = DATA_DIR / "verified_sanitizer_dataset.to_rag.jsonl"
DEFAULT_ERROR_PATH = DATA_DIR / "verified_sanitizer_dataset.to_rag.errors.jsonl"
DEFAULT_PROMPT_PATH = PROMPT_DIR / "to_rag.txt"
DEFAULT_FEWSHOT_PATH = PROMPT_DIR / "to_rag_fewshot.txt"
DEFAULT_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
CWE_PATTERN = re.compile(r"^CWE-\d+$")


def _resolve_repo_path(path: str | Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute() or candidate.exists():
        return candidate
    if candidate.parts:
        if candidate.parts[0] in {"artifacts", "data", "plan"}:
            return REPO_ROOT / "other" / candidate
        if candidate.parts[0] == "prompt":
            return PROMPT_DIR / Path(*candidate.parts[1:])
    repo_relative = REPO_ROOT / candidate
    if repo_relative.exists():
        return repo_relative
    return candidate


class RagGenerationOutput(BaseModel):
    actions: list[str] = Field(default_factory=list)
    details: list[str] = Field(default_factory=list)
    sanitizer_logic_with_nlp: str = Field(default="")
    validation_api_list: list[str] = Field(default_factory=list)
    unsafe_sanitizer_info: dict[str, Any] = Field(default_factory=dict)
    programming_language: str = Field(default="")
    cwe_id: list[str] = Field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a RAG-ready intermediate JSONL with DeepSeek."
    )
    parser.add_argument("--input-path", default=str(DEFAULT_INPUT_PATH))
    parser.add_argument("--output-path", default=str(DEFAULT_OUTPUT_PATH))
    parser.add_argument("--error-path", default=str(DEFAULT_ERROR_PATH))
    parser.add_argument("--prompt-path", default=str(DEFAULT_PROMPT_PATH))
    parser.add_argument("--fewshot-path", default=str(DEFAULT_FEWSHOT_PATH))
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--sleep-seconds", type=float, default=0.0)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--resume", action="store_true", default=True)
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at line {line_no}: {exc}") from exc
    return records


def existing_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    ids: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            record_id = str(data.get("id", "")).strip()
            if record_id:
                ids.add(record_id)
    return ids


def build_stable_id(record: dict[str, Any]) -> str:
    seed = "##".join(
        [
            str(record.get("cve_id", "")),
            str(record.get("sanitizer_file", "")),
            str(record.get("sanitizer_start_line", "")),
            str(record.get("sanitizer_symbol", "")),
        ]
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def read_patch_content(record: dict[str, Any]) -> str:
    patch_path = str(record.get("patch_path", "")).strip()
    if not patch_path:
        return ""
    path = _resolve_repo_path(patch_path)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def normalize_list(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for value in values:
        item = str(value).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    return normalized


def filter_cwe_ids(values: list[Any]) -> list[str]:
    return [value for value in normalize_list(values) if CWE_PATTERN.match(value)]


def build_logic_text(output: RagGenerationOutput) -> str:
    parts = [output.sanitizer_logic_with_nlp.strip()]
    if output.actions:
        parts.append(", ".join(normalize_list(output.actions)))
    if output.details:
        parts.append(", ".join(normalize_list(output.details)))
    return "; ".join([part for part in parts if part])


def make_parser() -> PydanticOutputParser:
    return PydanticOutputParser(pydantic_object=RagGenerationOutput)


def load_prompt_template(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_optional_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8").strip()


def build_user_prompt(
    record: dict[str, Any],
    prompt_template: str,
    fewshot_text: str,
    parser: PydanticOutputParser,
) -> str:
    source_prompt = prompt_template.format(
        format_instructions=parser.get_format_instructions(),
        defense_code_content=record.get("sanitizer_code", ""),
    )
    context = {
        "cve_id": record.get("cve_id", ""),
        "sanitizer_file": record.get("sanitizer_file", ""),
        "sanitizer_symbol": record.get("sanitizer_symbol", ""),
        "sanitizer_reason": record.get("sanitizer_reason", ""),
        "bypass_input": record.get("bypass_input", ""),
        "why_bypass_works": record.get("why_bypass_works", ""),
    }
    extra_requirements = """

你还需要补全这些面向 RAG 入库的字段，并且一并放进同一个 JSON 输出中：
- validation_api_list: 代码中真实出现或高度可确定的函数/API 名列表
- unsafe_sanitizer_info: 一个 JSON 对象，至少包含“缺陷原因”“绕过原理”“关键过滤点”“涉及函数”
- programming_language: 仅输出一种语言；无法确定则输出 "Unknown"
- cwe_id: 仅输出形如 CWE-79 的数组；无法确定则输出空数组

约束：
- actions 和 details 继续保持英文
- sanitizer_logic_with_nlp 继续保持英文
- unsafe_sanitizer_info 的值可以使用中文
- 不要输出 Markdown 代码块
- 只输出 JSON 对象
"""
    return (
        f"{source_prompt}\n\n"
        f"{fewshot_text}\n\n"
        f"额外上下文如下：\n{json.dumps(context, ensure_ascii=False, indent=2)}\n"
        f"{extra_requirements}"
    )


def create_llm(model: str) -> ChatOpenAI:
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise ValueError("DEEPSEEK_API_KEY is required.")
    return ChatOpenAI(
        model=model,
        base_url=DEEPSEEK_BASE_URL,
        api_key=api_key,
        temperature=0,
        timeout=120,
        model_kwargs={"response_format": {"type": "json_object"}},
    )


def parse_llm_output(content: str, parser: PydanticOutputParser) -> RagGenerationOutput:
    try:
        return parser.parse(content)
    except Exception:
        repaired = repair_json(content)
        return RagGenerationOutput.model_validate_json(repaired)


def invoke_with_retry(
    llm: ChatOpenAI,
    parser: PydanticOutputParser,
    prompt: str,
    max_retries: int,
    sleep_seconds: float,
) -> RagGenerationOutput:
    last_error: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            response = llm.invoke(
                [
                    SystemMessage(
                        content="You are a strict JSON generator for security RAG data preparation."
                    ),
                    HumanMessage(content=prompt),
                ]
            )
            content = response.content if isinstance(response.content, str) else str(response.content)
            return parse_llm_output(content, parser)
        except Exception as exc:
            last_error = exc
            if attempt < max_retries:
                time.sleep(max(sleep_seconds, 1.0))
    assert last_error is not None
    raise last_error


def build_output_record(record: dict[str, Any], llm_output: RagGenerationOutput) -> dict[str, Any]:
    logic_text = build_logic_text(llm_output)
    if not logic_text.strip():
        raise ValueError("unsafe_sanitizer_logic is empty after LLM generation")

    info = dict(llm_output.unsafe_sanitizer_info or {})
    info.update(
        {
            "owner": record.get("owner", ""),
            "repo": record.get("repo", ""),
            "sanitizer_file": record.get("sanitizer_file", ""),
            "sanitizer_symbol": record.get("sanitizer_symbol", ""),
            "sanitizer_start_line": record.get("sanitizer_start_line"),
            "sanitizer_end_line": record.get("sanitizer_end_line"),
            "sanitizer_reason": record.get("sanitizer_reason", ""),
            "why_bypass_works": record.get("why_bypass_works", ""),
            "patch_path": record.get("patch_path", ""),
            "actions": normalize_list(llm_output.actions),
            "details": normalize_list(llm_output.details),
        }
    )

    return {
        "id": build_stable_id(record),
        "CVE_ID": record.get("cve_id", ""),
        "patch_content": read_patch_content(record),
        "cwe_id": filter_cwe_ids(llm_output.cwe_id),
        "programming_language": (llm_output.programming_language or "Unknown").strip() or "Unknown",
        "unsafe_sanitizer_info": info,
        "vulnerable_code_snippet": record.get("sanitizer_code", ""),
        "unsafe_sanitizer_logic": logic_text,
        "validation_api_list": normalize_list(llm_output.validation_api_list),
        "bypass_poc": str(record.get("bypass_input", "")),
    }


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def process_records(args: argparse.Namespace) -> int:
    input_path = _resolve_repo_path(args.input_path)
    output_path = _resolve_repo_path(args.output_path)
    error_path = _resolve_repo_path(args.error_path)
    prompt_path = _resolve_repo_path(args.prompt_path)
    fewshot_path = _resolve_repo_path(args.fewshot_path)

    if args.overwrite:
        for path in (output_path, error_path):
            if path.exists():
                path.unlink()

    records = load_jsonl(input_path)
    if args.limit > 0:
        records = records[: args.limit]

    processed_ids = existing_ids(output_path) if args.resume and not args.overwrite else set()
    parser = make_parser()
    prompt_template = load_prompt_template(prompt_path)
    fewshot_text = load_optional_text(fewshot_path)
    llm = create_llm(args.model)

    success = 0
    skipped = 0
    failed = 0

    progress = tqdm(records, desc="Building RAG dataset", unit="record")
    for record in progress:
        record_id = build_stable_id(record)
        if record_id in processed_ids:
            skipped += 1
            progress.set_postfix(
                success=success,
                skipped=skipped,
                failed=failed,
            )
            continue

        try:
            prompt = build_user_prompt(record, prompt_template, fewshot_text, parser)
            llm_output = invoke_with_retry(
                llm=llm,
                parser=parser,
                prompt=prompt,
                max_retries=args.max_retries,
                sleep_seconds=args.sleep_seconds,
            )
            output_record = build_output_record(record, llm_output)
            append_jsonl(output_path, output_record)
            success += 1
        except Exception as exc:
            failed += 1
            append_jsonl(
                error_path,
                {
                    "id": record_id,
                    "cve_id": record.get("cve_id", ""),
                    "sanitizer_file": record.get("sanitizer_file", ""),
                    "sanitizer_symbol": record.get("sanitizer_symbol", ""),
                    "error": str(exc),
                    "raw_record": record,
                },
            )
        progress.set_postfix(
            success=success,
            skipped=skipped,
            failed=failed,
        )

        if args.sleep_seconds > 0:
            time.sleep(args.sleep_seconds)

    print(
        json.dumps(
            {
                "input_path": str(input_path),
                "output_path": str(output_path),
                "error_path": str(error_path),
                "model": args.model,
                "success": success,
                "skipped": skipped,
                "failed": failed,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if failed == 0 else 1


def main() -> int:
    args = parse_args()
    return process_records(args)


if __name__ == "__main__":
    sys.exit(main())
