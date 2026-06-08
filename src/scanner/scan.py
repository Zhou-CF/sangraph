from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice
from pathlib import Path
from typing import Any

from langchain.messages import HumanMessage, SystemMessage
from llm_factory.llm_factory import llm_factory
from sangraph_logging import get_logger
from tqdm import tqdm

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAVE_PATH = REPO_ROOT / "other" / "data" / "test.json"
DEFAULT_LLM_MODEL = "qwen3-8b-2ae89b5c4e9f"
DEBUG_FILE_SUFFIX = ".debug.jsonl"

# 1. Basic concurrency settings
MAX_WORKERS = 10

# 2. Language and file filters
VALID_EXTENSIONS = {
    ".py",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".php",
}

IGNORED_DIRS = {
    ".venv",
    "venv",
    "env",
    "node_modules",
    "vendor",
    "__pycache__",
    ".git",
    ".svn",
    ".idea",
    ".vscode",
    "dist",
    "build",
    "target",
    "bin",
    "pkg",
    "docs",
    "doc",
    "assets",
    "static",
    "images",
    "test",
    "tests",
    "__tests__",
    "testdata",
    "fixtures",
}

# 3. Circuit breakers for generated or minified files
MAX_FILE_SIZE = 500 * 1024
MAX_LINE_LENGTH = 3000

SYSTEM_PROMPT = """
你是一个专业的静态代码安全审计专家。你的任务是严格识别代码片段中是否包含**具有安全防御意图**的 Sanitizer（清洗/过滤）或 Validator（验证）逻辑。

请严格遵循以下判断逻辑（优先级从高到低）：

1.  **普通数据转换 (Transformation) -> FALSE**:
    * 任何仅改变数据格式、解码、解析或提取部分内容的操作，只要不涉及移除恶意字符，均为 False。
    * 典型特征：urldecode, base64_decode, parse_url, json_decode, date_format, pathinfo, trim (仅去空)。

2.  **不可见的封装调用 (Hidden Wrapper) -> FALSE**:
    * 如果代码调用了自定义函数（如 `$this->xssClean($v)`），但该函数的**源代码定义未在片段中给出**，必须标记为 False。
    * **原则**：看不见实现细节 = 不可信。不要根据函数名猜测。

3.  **标准库安全函数 (Built-in Security) -> TRUE**:
    * 调用了专用于安全的标准函数，包括但不限于内置函数，还有调用了业界公认的知名安全库 (如: DOMPurify, escape-html, validator)。
    * 典型特征：htmlentities, htmlspecialchars, strip_tags, intval (转整型视为防御SQLi), (int), mysqli_real_escape_string, escapeshellarg。

4.  **可见的自定义防御逻辑 (Visible Logic) -> TRUE**:
    * 自定义代码中显式展示了**针对攻击向量**的防御逻辑。
    * **关键条件**：不仅仅是使用了 `str_replace`，而是替换了敏感字符（如 `<script>`, `'`, `../`, `javascript:`）。
    * **反例**：`str_replace(" ", "-", $text)` 只是业务替换，标记为 False。
"""

_llm = None
logger = get_logger(__name__)


class _ScanRunDeduper:
    def __init__(self) -> None:
        self._processed_hashes: set[str] = set()
        self._lock = threading.Lock()

    def claim(self, code_hash: str) -> bool:
        with self._lock:
            if code_hash in self._processed_hashes:
                return False
            self._processed_hashes.add(code_hash)
            return True


def _get_llm():
    global _llm
    if _llm is None:
        logger.debug("Initializing scanner LLM model=%s", DEFAULT_LLM_MODEL)
        _llm = llm_factory(llm_type="dashscope", llm_model=DEFAULT_LLM_MODEL)
    return _llm


def _load_function_splitter():
    try:
        from .func_split import FunctionSplitter
    except ImportError as exc:
        raise RuntimeError(
            "FunctionSplitter is unavailable. Ensure scanner function-splitting helpers are installed correctly."
        ) from exc
    logger.debug("Loaded FunctionSplitter implementation from scanner.func_split")
    return FunctionSplitter


def derive_debug_save_path(save_path: str | os.PathLike[str]) -> Path:
    output_path = Path(save_path)
    return output_path.with_name(f"{output_path.stem}{DEBUG_FILE_SUFFIX}")


def calculate_hash(content: str) -> str:
    return hashlib.md5(content.strip().encode("utf-8")).hexdigest()


def is_generated_or_minified(file_path: str | os.PathLike[str]) -> bool:
    try:
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            return True

        filename = os.path.basename(file_path).lower()
        if filename.endswith(".pb.go") or filename.endswith("_pb2.py") or ".min." in filename:
            return True

        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            head = list(islice(handle, 5))
        content_head = "".join(head)

        if "GENERATED CODE" in content_head or "DO NOT EDIT" in content_head:
            return True

        for line in head:
            if len(line) > MAX_LINE_LENGTH:
                return True
    except Exception:
        return True
    return False


def call_llm_with_retry(code: str, retries: int = 3):
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=code),
    ]

    last_error: dict[str, Any] | None = None
    for attempt in range(retries):
        try:
            response = _get_llm().invoke(messages)
            return response, None
        except Exception as exc:
            err_str = str(exc)
            last_error = {
                "type": type(exc).__name__,
                "message": err_str,
                "attempt": attempt + 1,
                "retries": retries,
            }
            if "429" in err_str or "Too Many Requests" in err_str:
                logger.warning(
                    "Scanner LLM rate limited on attempt %s/%s; backing off before retry",
                    attempt + 1,
                    retries,
                )
                time.sleep(20 * (attempt + 1))
            else:
                logger.exception("Scanner LLM call failed: %s", err_str[:100])
                return None, last_error
    return None, last_error


def _build_debug_record(
    *,
    file_path: str | os.PathLike[str],
    status: str,
    message: str,
    item: dict[str, Any] | None = None,
    code_hash: str | None = None,
    llm_response: str | None = None,
    llm_error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "file_path": str(file_path),
        "status": status,
        "message": message,
    }
    if item:
        record.update(
            {
                "start_line": item.get("start_line"),
                "end_line": item.get("end_line"),
                "type": item.get("type"),
                "code": item.get("code", ""),
                "context_enrichment_applied": item.get("context_enrichment_applied", False),
                "enriched_context_symbols": item.get("enriched_context_symbols", []),
                "enriched_definition_count": item.get("enriched_definition_count", 0),
                "enriched_language_tier": item.get("enriched_language_tier"),
            }
        )
    if code_hash:
        record["code_hash"] = code_hash
    if llm_response is not None:
        record["llm_response"] = llm_response
    if llm_error is not None:
        record["llm_error"] = llm_error
    return record


def _append_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")


def process_single_file(
    file_path: str | os.PathLike[str],
    deduper: _ScanRunDeduper,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results: list[dict[str, Any]] = []
    debug_records: list[dict[str, Any]] = []
    if is_generated_or_minified(file_path):
        debug_records.append(
            _build_debug_record(
                file_path=file_path,
                status="file_skipped",
                message="generated_or_minified",
            )
        )
        return results, debug_records

    try:
        function_splitter_cls = _load_function_splitter()
        splitter = function_splitter_cls(file_path)
        functions = splitter.split()
        if not functions:
            logger.debug("No function-level snippets found in %s", file_path)
            debug_records.append(
                _build_debug_record(
                    file_path=file_path,
                    status="file_skipped",
                    message="no_function_snippets",
                )
            )
            return results, debug_records

        for item in functions:
            code_content = item.get("code", "")
            if not code_content or len(code_content) < 20:
                debug_records.append(
                    _build_debug_record(
                        file_path=file_path,
                        status="snippet_skipped",
                        message="code_too_short",
                        item=item,
                    )
                )
                continue
            if len(code_content) > 6000:
                debug_records.append(
                    _build_debug_record(
                        file_path=file_path,
                        status="snippet_skipped",
                        message="code_too_long",
                        item=item,
                    )
                )
                continue

            code_hash = calculate_hash(code_content)
            if not deduper.claim(code_hash):
                debug_records.append(
                    _build_debug_record(
                        file_path=file_path,
                        status="snippet_skipped",
                        message="duplicate_code_hash",
                        item=item,
                        code_hash=code_hash,
                    )
                )
                continue

            response, llm_error = call_llm_with_retry(code_content)
            if not response:
                debug_records.append(
                    _build_debug_record(
                        file_path=file_path,
                        status="llm_error",
                        message="llm_call_failed",
                        item=item,
                        code_hash=code_hash,
                        llm_error=llm_error,
                    )
                )
                continue

            content_lower = response.content.lower()
            idx = content_lower.find("issanitizer")
            verdict_region = content_lower[idx:] if idx != -1 else content_lower
            if "true" in verdict_region or "yes" in verdict_region:
                candidate = {
                    "file_path": str(file_path),
                    "start_line": item.get("start_line"),
                    "end_line": item.get("end_line"),
                    "code_hash": code_hash,
                    "code": code_content,
                    "llm_reasoning": response.content.strip(),
                }
                results.append(candidate)
                debug_records.append(
                    _build_debug_record(
                        file_path=file_path,
                        status="candidate_selected",
                        message="llm_positive_match",
                        item=item,
                        code_hash=code_hash,
                        llm_response=response.content.strip(),
                    )
                )
            else:
                debug_records.append(
                    _build_debug_record(
                        file_path=file_path,
                        status="candidate_rejected",
                        message="llm_negative_match",
                        item=item,
                        code_hash=code_hash,
                        llm_response=response.content.strip(),
                    )
                )
    except LookupError:
        logger.debug("Skipping unsupported file for function splitting: %s", file_path)
        debug_records.append(
            _build_debug_record(
                file_path=file_path,
                status="file_skipped",
                message="unsupported_language",
            )
        )
    except Exception as exc:
        logger.exception("Error processing scanner file %s: %s", file_path, exc)
        debug_records.append(
            _build_debug_record(
                file_path=file_path,
                status="file_error",
                message=str(exc),
                llm_error={"type": type(exc).__name__, "message": str(exc)},
            )
        )

    return results, debug_records


def main(
    project_path: str,
    save_path: str | os.PathLike[str] | None = None,
    debug_save_path: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    if not project_path:
        raise ValueError("project_path is required.")

    resolved_debug_save_path = None
    if debug_save_path:
        resolved_debug_save_path = Path(debug_save_path)
    elif save_path:
        resolved_debug_save_path = derive_debug_save_path(save_path)

    if resolved_debug_save_path:
        resolved_debug_save_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_debug_save_path.write_text("", encoding="utf-8")

    logger.info(
        "Starting scanner run project_path=%s save_path=%s debug_save_path=%s",
        project_path,
        save_path,
        resolved_debug_save_path,
    )

    all_sanitizers: list[dict[str, Any]] = []
    # Share dedup state across workers for this scan only; each main() call gets a fresh container.
    deduper = _ScanRunDeduper()
    futures = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        file_count = 0

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [item for item in dirs if item not in IGNORED_DIRS and not item.startswith(".")]

            for file_name in files:
                _, ext = os.path.splitext(file_name)
                if ext.lower() not in VALID_EXTENSIONS:
                    continue
                if file_name.endswith(("_test.go", ".test.js", ".spec.js", ".spec.ts", "test.py")):
                    continue

                file_path = os.path.join(root, file_name)
                futures.append(executor.submit(process_single_file, file_path, deduper))
                file_count += 1

        logger.info("Scanner submitted %s files for auditing", file_count)

        for future in tqdm(as_completed(futures), total=len(futures), desc="Auditing"):
            try:
                result, debug_records = future.result()
                if result:
                    all_sanitizers.extend(result)
                if resolved_debug_save_path and debug_records:
                    _append_jsonl(resolved_debug_save_path, debug_records)
            except Exception as exc:
                logger.exception("Unhandled scanner worker error: %s", exc)

    logger.info("Scanner completed with %s sanitizer candidates", len(all_sanitizers))

    if save_path:
        output_path = Path(save_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(all_sanitizers, ensure_ascii=False, indent=4), encoding="utf-8")
        logger.info("Scanner results written to %s", output_path)
    if resolved_debug_save_path:
        logger.info("Scanner debug decisions written to %s", resolved_debug_save_path)

    return all_sanitizers
