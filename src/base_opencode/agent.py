from __future__ import annotations

import json
import os
import re
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
from uuid import uuid4

from dotenv import load_dotenv
from json_repair import repair_json
from langchain_core.output_parsers import PydanticOutputParser
from langgraph.graph import END, START, StateGraph
from sangraph_logging import get_logger

from llm_factory.llm_factory import DEFAULT_DASHSCOPE_CHAT_MODEL, llm_factory
from rag import rag_search

from .llm_struct import (
    AnalysisDecisionStruct,
    DeepAnalysisStruct,
    FinalResultStruct,
    OpenCodeAnalysisStruct,
    RAGRelevanceStruct,
    ReviewDecisionStruct,
    SanitizerCodeStruct,
    SanitizerLogicStruct,
    StateGraphStruct,
    state_to_jsonable,
)
from .script import DEFAULT_OPENCODE_MODEL, OpenCodeAgent

load_dotenv(override=True)

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parents[1]
PROMPT_DIR = PACKAGE_DIR / "prompt"
DEFAULT_AUDIT_ROOT = REPO_ROOT / "other" / "artifacts" / "audit"
VALID_ANALYSIS_PROFILES = {"standard", "enhanced_search"}
logger = get_logger(__name__)


StageFn = Callable[[StateGraphStruct], Awaitable[StateGraphStruct]]
CODE_FENCE_PATTERN = re.compile(r"```(?:json)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)


def _resolve_repo_path(path: str | Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute() or candidate.exists():
        return candidate
    if candidate.parts and candidate.parts[0] in {"artifacts", "data", "plan"}:
        return REPO_ROOT / "other" / candidate
    repo_relative = REPO_ROOT / candidate
    if repo_relative.exists():
        return repo_relative
    return candidate


def _prompt_text(name: str) -> str:
    return (PROMPT_DIR / name).read_text(encoding="utf-8")


def _patch_text(path: str) -> str:
    return _resolve_repo_path(path).read_text(encoding="utf-8", errors="ignore")


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return ""
    matches = CODE_FENCE_PATTERN.findall(stripped)
    if matches:
        return matches[-1].strip()
    return stripped


def _parse_deep_analysis_response(
    response: str,
    parser: PydanticOutputParser,
) -> DeepAnalysisStruct:
    try:
        return parser.parse(response)
    except Exception:
        stripped = _strip_code_fence(response)
        if stripped:
            try:
                repaired = repair_json(stripped, return_objects=True)
                if isinstance(repaired, dict):
                    return DeepAnalysisStruct.model_validate(repaired)
            except Exception:
                pass
        raise


def _default_llm():
    return llm_factory(
        llm_type="dashscope",
        llm_model=os.getenv("DASHSCOPE_CHAT_MODEL", DEFAULT_DASHSCOPE_CHAT_MODEL),
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _resolve_audit_dir(patch_path: str, audit_dir: str | Path | None) -> Path:
    if audit_dir is not None:
        return _resolve_repo_path(audit_dir)
    patch_stem = Path(patch_path).stem or "patch"
    timestamp = _utc_now().strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_AUDIT_ROOT / f"{timestamp}-{patch_stem}-{uuid4().hex[:8]}"


def _normalize_optional_text(value: str | None) -> str:
    if value is None:
        return ""
    return value.strip()


def _normalize_optional_int(value: int | None) -> int | None:
    if value is None:
        return None
    return int(value)


def _normalize_candidate_metadata(value: dict[str, Any] | None) -> dict[str, Any]:
    if not value:
        return {}
    return dict(value)


def _normalize_analysis_profile(value: str | None) -> str:
    normalized = (value or "standard").strip().lower()
    if normalized not in VALID_ANALYSIS_PROFILES:
        raise ValueError(f"Unsupported analysis_profile: {value}")
    return normalized


def _opencode_project_path(state: StateGraphStruct) -> str:
    repo_path = state.get("repo_path", "").strip()
    if repo_path:
        return repo_path
    patch_path = state.get("patch_path", "").strip()
    if patch_path:
        return str(_resolve_repo_path(patch_path).resolve().parent)
    return str(REPO_ROOT.resolve())


def _prepare_initial_state(
    repo_path: str | None,
    patch_path: str | None,
    sanitizer_code: str | None,
    candidate_code: str | None = None,
    candidate_path: str | None = None,
    candidate_start_line: int | None = None,
    candidate_end_line: int | None = None,
    candidate_symbol: str | None = None,
    candidate_language: str | None = None,
    candidate_metadata: dict[str, Any] | None = None,
    analysis_profile: str = "standard",
) -> StateGraphStruct:
    normalized_repo_path = _normalize_optional_text(repo_path)
    normalized_patch_path = _normalize_optional_text(patch_path)
    provided_sanitizer_code = sanitizer_code or ""
    normalized_sanitizer_code = provided_sanitizer_code.strip()
    provided_candidate_code = candidate_code or ""
    normalized_candidate_code = provided_candidate_code.strip()

    if sanitizer_code is not None and not normalized_sanitizer_code:
        raise ValueError("sanitizer_code 不能为空白内容。")
    if candidate_code is not None and not normalized_candidate_code:
        raise ValueError("candidate_code 不能为空白内容。")

    if normalized_sanitizer_code:
        input_mode = "sanitizer_code"
        input_source = "sanitizer_code"
        sanitizer_extraction_source = "provided"
    elif normalized_candidate_code:
        input_mode = "scanner_candidate"
        input_source = "scanner_candidate_extraction"
        sanitizer_extraction_source = "scanner_candidate"
    elif normalized_patch_path:
        input_mode = "patch"
        input_source = "patch_extraction"
        sanitizer_extraction_source = "patch"
    else:
        raise ValueError("patch_path、sanitizer_code 与 candidate_code 至少提供一个。")

    resolved_profile = _normalize_analysis_profile(analysis_profile)
    return {
        "repo_path": normalized_repo_path,
        "patch_path": normalized_patch_path,
        "analysis_profile": resolved_profile,
        "analysis_backend": "opencode",
        "input_mode": input_mode,
        "input_source": input_source,
        "sanitizer_extraction_source": sanitizer_extraction_source,
        "sanitizer_code_provided": provided_sanitizer_code,
        "candidate_code": provided_candidate_code,
        "candidate_path": _normalize_optional_text(candidate_path),
        "candidate_start_line": _normalize_optional_int(candidate_start_line),
        "candidate_end_line": _normalize_optional_int(candidate_end_line),
        "candidate_symbol": _normalize_optional_text(candidate_symbol),
        "candidate_language": _normalize_optional_text(candidate_language),
        "candidate_metadata": _normalize_candidate_metadata(candidate_metadata),
        "sanitizer_code": normalized_sanitizer_code,
        "external_evidence_used": False,
        "external_evidence_sources": [],
        "external_evidence_reason": "",
        "final_verdict_source": "",
        "final_verdict_source_detail": "",
    }


def should_extract_sanitizer(state: StateGraphStruct) -> bool:
    return state.get("input_mode") in {"patch", "scanner_candidate"}


def route_sanitizer_input(state: StateGraphStruct) -> str:
    input_mode = state.get("input_mode", "patch")
    if input_mode == "sanitizer_code":
        return "sanitizer_code"
    if input_mode == "scanner_candidate":
        return "scanner_candidate"
    return "patch"


def _patch_context_for_review(state: StateGraphStruct) -> str:
    patch_path = state.get("patch_path", "").strip()
    if patch_path:
        return _patch_text(patch_path)
    candidate_code = state.get("candidate_code", "").strip()
    if candidate_code:
        location_parts = []
        candidate_path = state.get("candidate_path", "").strip()
        candidate_symbol = state.get("candidate_symbol", "").strip()
        candidate_language = state.get("candidate_language", "").strip()
        candidate_start_line = state.get("candidate_start_line")
        candidate_end_line = state.get("candidate_end_line")

        if candidate_path:
            location_parts.append(f"path={candidate_path}")
        if candidate_symbol:
            location_parts.append(f"symbol={candidate_symbol}")
        if candidate_language:
            location_parts.append(f"language={candidate_language}")
        if candidate_start_line is not None or candidate_end_line is not None:
            if candidate_start_line is not None and candidate_end_line is not None:
                location_parts.append(f"lines={candidate_start_line}-{candidate_end_line}")
            elif candidate_start_line is not None:
                location_parts.append(f"start_line={candidate_start_line}")
            else:
                location_parts.append(f"end_line={candidate_end_line}")

        location = ", ".join(location_parts) or "未提供额外定位信息"
        return (
            "未提供 patch_path；以下为扫描候选代码背景，可用于复核提取出的 sanitizer 逻辑：\n"
            f"[{location}]\n\n"
            f"{candidate_code}"
        )
    return "未提供 patch_path；本次仅基于 sanitizer_code 进行分析，缺少 patch 背景。"


def _deep_analysis_skip_reason(state: StateGraphStruct) -> str:
    input_mode = state.get("input_mode")
    if input_mode == "sanitizer_code":
        return (
            "analysis 认为存在问题，但当前仅提供 sanitizer_code，缺少源码上下文，"
            "且 repo_path 缺失，无法继续深挖。"
        )
    if input_mode == "scanner_candidate":
        return (
            "analysis 认为存在问题，当前仅提供 scanner candidate 片段，"
            "且 repo_path 缺失，无法继续基于完整源码上下文深挖。"
        )
    return "analysis 认为存在问题，但 repo_path 缺失，无法继续基于完整源码上下文深挖。"


def _sanitizer_extraction_stage_node(state: StateGraphStruct) -> str:
    input_mode = state.get("input_mode")
    if input_mode == "scanner_candidate":
        return "extract_sanitizer_from_candidate"
    if input_mode == "patch":
        return "extract_sanitizer_from_patch"
    return "sanitizer_extraction"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _extract_opencode_debug(exc: Exception) -> dict[str, Any] | None:
    debug = getattr(exc, "opencode_debug", None)
    if isinstance(debug, dict):
        return debug
    return None


def _build_error_payload(node_name: str, exc: Exception) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "node": node_name,
        "message": str(exc),
        "type": type(exc).__name__,
        "traceback": traceback.format_exc(),
    }
    opencode_debug = _extract_opencode_debug(exc)
    if opencode_debug is not None:
        payload["opencode_debug"] = opencode_debug
    return payload


def _append_recoverable_error(state: StateGraphStruct, error_payload: dict[str, Any]) -> None:
    recoverable_errors = list(state.get("recoverable_errors", []))
    recoverable_errors.append(error_payload)
    state["recoverable_errors"] = recoverable_errors


def _deep_context_failure_state(error_payload: dict[str, Any]) -> StateGraphStruct:
    short_message = error_payload.get("message", "").splitlines()[0].strip()
    if not short_message:
        short_message = error_payload.get("type", "unknown error")
    return {
        "deep_analysis_attempted": True,
        "deep_analysis_skipped": True,
        "deep_analysis_skip_reason": (
            f"源码上下文深挖执行失败（{short_message}），已保留前序分析结论；详细日志见 audit artifact。"
        ),
        "deep_analysis_error": error_payload,
    }


def _build_summary(
    state: StateGraphStruct,
    *,
    audit_dir: Path,
    started_at: datetime,
    finished_at: datetime,
    status: str,
    completed_nodes: list[str],
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "repo_path": state.get("repo_path", ""),
        "patch_path": state.get("patch_path", ""),
        "analysis_profile": state.get("analysis_profile", "standard"),
        "analysis_backend": state.get("analysis_backend", "opencode"),
        "input_mode": state.get("input_mode", ""),
        "input_source": state.get("input_source", ""),
        "sanitizer_extraction_source": state.get("sanitizer_extraction_source", ""),
        "sanitizer_code_provided": state.get("sanitizer_code_provided", ""),
        "candidate_path": state.get("candidate_path", ""),
        "candidate_symbol": state.get("candidate_symbol", ""),
        "candidate_start_line": state.get("candidate_start_line"),
        "candidate_end_line": state.get("candidate_end_line"),
        "candidate_language": state.get("candidate_language", ""),
        "candidate_metadata": state.get("candidate_metadata", {}),
        "audit_dir": str(audit_dir),
        "status": status,
        "started_at": _format_timestamp(started_at),
        "finished_at": _format_timestamp(finished_at),
        "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
        "completed_nodes": completed_nodes,
        "sanitizer_code": state.get("sanitizer_code", ""),
        "sanitizer_extraction_skipped": state.get("sanitizer_extraction_source") == "provided",
        "sanitizer_logic_str": state.get("sanitizer_logic_str", ""),
        "rag_hits_count": len(state.get("rag_hits", [])),
        "rag_relevance": state_to_jsonable({"value": state.get("rag_relevance")}).get("value"),
        "external_evidence_used": state.get("external_evidence_used", False),
        "external_evidence_sources": state.get("external_evidence_sources", []),
        "external_evidence_reason": state.get("external_evidence_reason", ""),
        "opencode_analysis": state_to_jsonable({"value": state.get("opencode_analysis")}).get("value"),
        "full_analysis_decision": state_to_jsonable({"value": state.get("full_analysis_decision")}).get("value"),
        "review_result": state_to_jsonable({"value": state.get("review_result")}).get("value"),
        "recoverable_errors": state_to_jsonable({"value": state.get("recoverable_errors", [])}).get("value"),
        "deep_analysis_attempted": bool(
            state.get("deep_analysis_attempted", bool(state.get("deep_analysis")))
        ),
        "deep_analysis_triggered": bool(
            state.get("deep_analysis_attempted", bool(state.get("deep_analysis")))
        ),
        "deep_analysis_skipped": state.get("deep_analysis_skipped", False),
        "deep_analysis_skip_reason": state.get("deep_analysis_skip_reason", ""),
        "deep_analysis_error": state_to_jsonable({"value": state.get("deep_analysis_error")}).get("value"),
        "deep_analysis_verdict": state_to_jsonable({"value": state.get("deep_analysis")}).get("value"),
        "poc_text": state.get("poc_text", ""),
        "evidence_summary": state.get("evidence_summary", ""),
        "final_verdict_source": state.get("final_verdict_source", ""),
        "final_verdict_source_detail": state.get("final_verdict_source_detail", ""),
        "result": state_to_jsonable({"value": state.get("result")}).get("value"),
    }
    if error:
        summary["error"] = error
    return summary


def _write_stage_artifact(
    audit_dir: Path,
    file_name: str,
    *,
    node: str,
    started_at: datetime,
    finished_at: datetime,
    state_before: StateGraphStruct,
    state_after: StateGraphStruct,
    node_output: dict[str, Any],
) -> None:
    _write_json(
        audit_dir / file_name,
        {
            "node": node,
            "started_at": _format_timestamp(started_at),
            "finished_at": _format_timestamp(finished_at),
            "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
            "input_state": state_to_jsonable(state_before),
            "node_output": state_to_jsonable(node_output),
            "state": state_to_jsonable(state_after),
        },
    )


def process_logic(sanitizer_logic: SanitizerLogicStruct | None) -> str:
    if not sanitizer_logic:
        return ""
    parts = [
        sanitizer_logic.logic_with_nlp.strip(),
        ", ".join(item.strip() for item in sanitizer_logic.actions if item.strip()),
        ", ".join(item.strip() for item in sanitizer_logic.details if item.strip()),
    ]
    return "; ".join(part for part in parts if part)


def _sort_rag_hits(rag_data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(item: dict[str, Any]) -> tuple[float, float]:
        rank = item.get("rank")
        if rank is not None:
            return (0.0, float(rank))
        return (1.0, float(item.get("raw_distance", item.get("distance", 1.0))))

    return sorted(rag_data, key=key)


# Keep the existing case formatting so historical examples remain visible in audit artifacts.
def format_rag_results_for_llm(rag_data: list[dict[str, Any]], top_k: int = 10) -> str:
    if not rag_data:
        return "未检索到相关参考案例。"

    context = ["以下是基于检索系统找到的相似漏洞案例（按相关性排序）：", ""]
    sorted_data = _sort_rag_hits(rag_data)

    for item in sorted_data[:top_k]:
        entity = item.get("entity", {})
        cve_id = entity.get("CVE_ID") or "N/A"
        cwe_list = entity.get("cwe_id") or []
        cwe_str = ", ".join(cwe_list) if cwe_list else "Unknown"
        code_snippet = entity.get("vulnerable_code_snippet", "").strip() or "N/A"
        logic_desc = entity.get("unsafe_sanitizer_logic", "").strip() or "无描述"
        bypass_poc = entity.get("bypass_poc", "").strip() or "无"
        reason = entity.get("unsafe_sanitizer_info", {}).get("缺陷原因")
        if not reason:
            reason = str(entity.get("unsafe_sanitizer_info", {})) or "无"

        context.append(
            "\n".join(
                [
                    f"<case cve=\"{cve_id}\" cwe=\"{cwe_str}\">",
                    f"### 相似案例 {cve_id} (CWE: {cwe_str})",
                    "1. 缺陷代码片段:",
                    "```",
                    code_snippet,
                    "```",
                    "2. 不安全过滤逻辑:",
                    logic_desc,
                    "3. 缺陷原因:",
                    reason,
                    "4. 绕过方法:",
                    bypass_poc,
                    "</case>",
                    "",
                ]
            )
        )

    return "\n".join(context).strip()


def assess_rag_relevance(rag_hits: list[dict[str, Any]]) -> RAGRelevanceStruct:
    if not rag_hits:
        return RAGRelevanceStruct(
            label="none",
            reason="未检索到相似案例，无法用历史失败模式支撑当前判断。",
            top_case_count=0,
            usable_case_count=0,
        )

    sorted_hits = _sort_rag_hits(rag_hits)
    top_hits = sorted_hits[:3]
    usable_case_count = 0
    for item in top_hits:
        entity = item.get("entity", {})
        if entity.get("unsafe_sanitizer_logic") or entity.get("vulnerable_code_snippet"):
            usable_case_count += 1

    if len(top_hits) < 2:
        return RAGRelevanceStruct(
            label="low",
            reason="仅检索到 1 条参考案例，样本过少，只能作为弱参考。",
            top_case_count=len(top_hits),
            usable_case_count=usable_case_count,
        )

    best_distance = float(top_hits[0].get("raw_distance", top_hits[0].get("distance", 1.0)))
    if len(top_hits) >= 3 and usable_case_count >= 2 and best_distance <= 0.25:
        label = "high"
        reason = "前排命中数量充足，且最相近案例距离较低，可直接参考历史失败模式。"
    elif usable_case_count >= 2 and best_distance <= 0.45:
        label = "medium"
        reason = "存在多条可用案例，但相似性还不足以单独支撑最终判断。"
    else:
        label = "low"
        reason = "检索结果可参考，但相似性偏弱，需要谨慎对待历史案例映射。"

    return RAGRelevanceStruct(
        label=label,
        reason=reason,
        top_case_count=len(top_hits),
        usable_case_count=usable_case_count,
    )


def _conservative_analysis(reasoning: str) -> AnalysisDecisionStruct:
    return AnalysisDecisionStruct(
        reasoning=reasoning,
        is_vuln=False,
        confidence="low",
    )


def _state_json(value: Any) -> str:
    return json.dumps(state_to_jsonable({"value": value}).get("value"), ensure_ascii=False, indent=2)


def _should_allow_public_evidence_search(state: StateGraphStruct) -> bool:
    if state.get("analysis_profile", "standard") != "enhanced_search":
        return False
    rag_relevance = state.get("rag_relevance")
    if not rag_relevance:
        return False
    return rag_relevance.label in {"low", "none"}


def _default_public_evidence_reason(state: StateGraphStruct, external_evidence_used: bool) -> str:
    if external_evidence_used:
        return "基于公开资料补充了低相关 RAG 案例之外的防御性证据。"
    if state.get("analysis_profile", "standard") != "enhanced_search":
        return "standard 模式不会主动检索公开资料。"
    rag_relevance = state.get("rag_relevance")
    if rag_relevance and rag_relevance.label not in {"low", "none"}:
        return "RAG 参考性已足够，本次无需额外检索公开资料。"
    return "允许公开资料补证，但当前无法确认是否需要或是否可用。"


def _normalize_sources(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        candidate = value.strip()
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized


def _opencode_review_reasoning(parsed: OpenCodeAnalysisStruct) -> str:
    return parsed.evidence_summary.strip() or parsed.reasoning.strip()


async def extract_sanitizer_from_patch(state: StateGraphStruct) -> StateGraphStruct:
    parser = PydanticOutputParser(pydantic_object=SanitizerCodeStruct)
    agent = OpenCodeAgent(
        project_path=_opencode_project_path(state),
        model=os.getenv("OPENCODE_MODEL", DEFAULT_OPENCODE_MODEL),
    )
    prompt = _prompt_text("analyze_sanitizer_prompt.txt").format(
        PATCH_CONTENT=_patch_text(state["patch_path"])
    )
    response = agent.chat(
        f"{prompt}\n\n请仅按以下 JSON 结构回复，不要添加额外说明：\n"
        f"{parser.get_format_instructions()}"
    )
    parsed = parser.parse(response)
    return {
        "analysis_result": response,
        "sanitizer_code": parsed.code.strip(),
        "sanitizer_extraction_source": "patch",
    }


async def prepare_input_node(state: StateGraphStruct) -> StateGraphStruct:
    return {}


async def extract_sanitizer_from_candidate(state: StateGraphStruct) -> StateGraphStruct:
    parser = PydanticOutputParser(pydantic_object=SanitizerCodeStruct)
    prompt = _prompt_text("extract_sanitizer_from_candidate_prompt.txt").format(
        CANDIDATE_PATH=state.get("candidate_path", "") or "N/A",
        CANDIDATE_SYMBOL=state.get("candidate_symbol", "") or "N/A",
        CANDIDATE_LANGUAGE=state.get("candidate_language", "") or "N/A",
        CANDIDATE_START_LINE=state.get("candidate_start_line")
        if state.get("candidate_start_line") is not None
        else "N/A",
        CANDIDATE_END_LINE=state.get("candidate_end_line")
        if state.get("candidate_end_line") is not None
        else "N/A",
        CANDIDATE_METADATA=json.dumps(state.get("candidate_metadata", {}), ensure_ascii=False, indent=2),
        CANDIDATE_CODE=state.get("candidate_code", ""),
    )
    resp = await _default_llm().ainvoke(
        f"{prompt}\n\n请仅按以下 JSON 结构回复，不要添加额外说明：\n"
        f"{parser.get_format_instructions()}"
    )
    parsed = parser.parse(resp.content)
    return {
        "analysis_result": resp.content,
        "sanitizer_code": parsed.code.strip(),
        "sanitizer_extraction_source": "scanner_candidate",
    }


async def analyze_sanitizer_logic_node(state: StateGraphStruct) -> StateGraphStruct:
    sanitizer_code = state.get("sanitizer_code", "").strip()
    if not sanitizer_code:
        return {
            "sanitizer_logic_result": "",
            "sanitizer_logic_str": "",
        }

    parser = PydanticOutputParser(pydantic_object=SanitizerLogicStruct)
    prompt = _prompt_text("format_knowledge.txt").format(
        defense_code_content=sanitizer_code,
        format_instructions=parser.get_format_instructions(),
    )
    resp = await _default_llm().ainvoke(prompt)
    sanitizer_logic = parser.parse(resp.content)
    return {
        "sanitizer_logic_result": resp.content,
        "sanitizer_logic": sanitizer_logic,
        "sanitizer_logic_str": process_logic(sanitizer_logic),
    }


async def search_rag(state: StateGraphStruct) -> StateGraphStruct:
    logic_text = state.get("sanitizer_logic_str", "")
    code_text = state.get("sanitizer_code", "")
    if not code_text.strip() and not logic_text.strip():
        rag_context = "未检索到相关参考案例。"
        rag_relevance = assess_rag_relevance([])
        return {
            "rag_hits": [],
            "rag_relevance": rag_relevance,
            "rag_context": rag_context,
            "rag_search_result": rag_context,
        }
    hits = await rag_search.search(logic_text=logic_text, code_text=code_text)
    rag_context = format_rag_results_for_llm(hits)
    rag_relevance = assess_rag_relevance(hits)
    return {
        "rag_hits": hits,
        "rag_relevance": rag_relevance,
        "rag_context": rag_context,
        "rag_search_result": rag_context,
    }


async def full_analysis(state: StateGraphStruct) -> StateGraphStruct:
    sanitizer_code = state.get("sanitizer_code", "").strip()
    if not sanitizer_code:
        decision = _conservative_analysis("无法提取有效的核心防御代码，证据不足，暂不判定为真实漏洞。")
        return {
            "full_analysis_result": decision.model_dump_json(ensure_ascii=False),
            "full_analysis_decision": decision,
        }

    parser = PydanticOutputParser(pydantic_object=AnalysisDecisionStruct)
    prompt = _prompt_text("full_analysis.txt").format(
        sanitizer_code=sanitizer_code,
        rag_knowledge=state.get("rag_context", "未检索到相关参考案例。"),
    )
    prompt = (
        f"{prompt}\n\n"
        "请输出稳定 JSON，字段必须包含 reasoning、is_vuln、confidence。\n"
        f"{parser.get_format_instructions()}"
    )
    resp = await _default_llm().ainvoke(prompt)
    decision = parser.parse(resp.content)
    return {
        "full_analysis_result": resp.content,
        "full_analysis_decision": decision,
    }


async def review_result(state: StateGraphStruct) -> StateGraphStruct:
    analysis_decision = state.get("full_analysis_decision")
    sanitizer_code = state.get("sanitizer_code", "").strip()
    if not sanitizer_code:
        review = ReviewDecisionStruct(
            reasoning="未提取到有效的核心防御代码，无法完成可靠复核，因此保持保守结论。",
            is_real_vuln=False,
            confidence="low",
        )
        return {"review_result": review}

    parser = PydanticOutputParser(pydantic_object=ReviewDecisionStruct)
    prompt = _prompt_text("review_report.txt").format(
        analyse_report=state.get("full_analysis_result", ""),
        patch_content=_patch_context_for_review(state),
        format_instructions=parser.get_format_instructions(),
    )
    if not state.get("rag_hits"):
        prompt += "\n\n补充说明：RAG 未返回相似案例，请重点判断当前结论是否存在证据不足。"
    if analysis_decision:
        prompt += (
            "\n\n当前结构化初判如下：\n"
            f"{analysis_decision.model_dump_json(ensure_ascii=False)}"
        )
    resp = await _default_llm().ainvoke(prompt)
    review = parser.parse(resp.content)
    return {
        "review_result_raw": resp.content,
        "review_result": review,
    }


def _build_opencode_prompt(state: StateGraphStruct, parser: PydanticOutputParser) -> str:
    prompt_name = "opencode_analysis_enhanced_search.txt"
    if state.get("analysis_profile", "standard") == "standard":
        prompt_name = "opencode_analysis_standard.txt"

    rag_relevance = state.get("rag_relevance")
    allow_public_evidence = _should_allow_public_evidence_search(state)
    public_evidence_policy = (
        "允许在 RAG 参考性偏低时检索公开资料补证。只允许引用公开的补丁、CVE、官方文档或安全分析，"
        "不得输出利用代码、攻击步骤或可直接复现的 payload。"
        if allow_public_evidence
        else "本次禁止主动检索公开资料；请仅基于输入代码、RAG 和仓库上下文给出结论。"
    )
    return _prompt_text(prompt_name).format(
        SANITIZER_CODE=state.get("sanitizer_code", ""),
        SANITIZER_LOGIC=state.get("sanitizer_logic_str", ""),
        RAG_CONTEXT=state.get("rag_context", "未检索到相关参考案例。"),
        RAG_RELEVANCE=_state_json(rag_relevance) if rag_relevance else "{}",
        INPUT_CONTEXT=_patch_context_for_review(state),
        PUBLIC_EVIDENCE_POLICY=public_evidence_policy,
        FORMAT_INSTRUCTIONS=parser.get_format_instructions(),
    )


async def opencode_analysis(state: StateGraphStruct) -> StateGraphStruct:
    sanitizer_code = state.get("sanitizer_code", "").strip()
    if not sanitizer_code:
        parsed = OpenCodeAnalysisStruct(
            reasoning="无法提取有效的核心防御代码，证据不足，暂不判定为真实漏洞。",
            is_vuln=False,
            confidence="low",
            evidence_summary="缺少可供分析的核心防御逻辑。",
            external_evidence_used=False,
            external_evidence_sources=[],
            external_evidence_reason=_default_public_evidence_reason(state, False),
        )
    else:
        parser = PydanticOutputParser(pydantic_object=OpenCodeAnalysisStruct)
        prompt = _build_opencode_prompt(state, parser)
        opencode = OpenCodeAgent(
            project_path=_opencode_project_path(state),
            model=os.getenv("OPENCODE_MODEL", DEFAULT_OPENCODE_MODEL),
        )
        response = opencode.chat(prompt)
        parsed = parser.parse(response)
        parsed = parsed.model_copy(
            update={
                "external_evidence_sources": _normalize_sources(parsed.external_evidence_sources),
                "external_evidence_reason": parsed.external_evidence_reason.strip()
                or _default_public_evidence_reason(state, parsed.external_evidence_used),
            }
        )
        raw_result = response
        review_reasoning = _opencode_review_reasoning(parsed)
        verdict_source = (
            "opencode_analysis_with_public_evidence"
            if parsed.external_evidence_used
            else "opencode_analysis"
        )
        return {
            "analysis_backend": "opencode",
            "opencode_analysis_result": raw_result,
            "opencode_analysis": parsed,
            "full_analysis_result": parsed.model_dump_json(ensure_ascii=False),
            "full_analysis_decision": AnalysisDecisionStruct(
                reasoning=parsed.reasoning,
                is_vuln=parsed.is_vuln,
                confidence=parsed.confidence,
            ),
            "review_result_raw": review_reasoning,
            "review_result": ReviewDecisionStruct(
                reasoning=review_reasoning,
                is_real_vuln=parsed.is_vuln,
                confidence=parsed.confidence,
            ),
            "evidence_summary": parsed.evidence_summary.strip(),
            "external_evidence_used": parsed.external_evidence_used,
            "external_evidence_sources": parsed.external_evidence_sources,
            "external_evidence_reason": parsed.external_evidence_reason,
            "final_verdict_source": verdict_source,
            "final_verdict_source_detail": verdict_source,
        }

    review_reasoning = _opencode_review_reasoning(parsed)
    verdict_source = (
        "opencode_analysis_with_public_evidence"
        if parsed.external_evidence_used
        else "opencode_analysis"
    )
    return {
        "analysis_backend": "opencode",
        "opencode_analysis_result": parsed.model_dump_json(ensure_ascii=False),
        "opencode_analysis": parsed,
        "full_analysis_result": parsed.model_dump_json(ensure_ascii=False),
        "full_analysis_decision": AnalysisDecisionStruct(
            reasoning=parsed.reasoning,
            is_vuln=parsed.is_vuln,
            confidence=parsed.confidence,
        ),
        "review_result_raw": review_reasoning,
        "review_result": ReviewDecisionStruct(
            reasoning=review_reasoning,
            is_real_vuln=parsed.is_vuln,
            confidence=parsed.confidence,
        ),
        "evidence_summary": parsed.evidence_summary.strip(),
        "external_evidence_used": parsed.external_evidence_used,
        "external_evidence_sources": parsed.external_evidence_sources,
        "external_evidence_reason": parsed.external_evidence_reason,
        "final_verdict_source": verdict_source,
        "final_verdict_source_detail": verdict_source,
    }


async def run_llm_fallback(
    state: StateGraphStruct,
    *,
    opencode_error: Exception | None = None,
) -> StateGraphStruct:
    fallback_state = dict(state)
    analysis_output = await full_analysis(fallback_state)
    fallback_state.update(analysis_output)
    review_output = await review_result(fallback_state)
    fallback_state.update(review_output)

    review = fallback_state.get("review_result")
    should_have_external_search = _should_allow_public_evidence_search(state)
    if should_have_external_search and opencode_error is not None:
        external_reason = (
            "OpenCode 分析失败，已降级到纯 LLM fallback；因此未执行公开资料补证。"
        )
    else:
        external_reason = _default_public_evidence_reason(state, False)

    return {
        **analysis_output,
        **review_output,
        "analysis_backend": "llm_fallback",
        "evidence_summary": review.reasoning if review else "",
        "external_evidence_used": False,
        "external_evidence_sources": [],
        "external_evidence_reason": external_reason,
        "final_verdict_source": "review_result",
        "final_verdict_source_detail": "llm_fallback_review",
    }


def should_run_deep_context_analysis(state: StateGraphStruct) -> bool:
    review = state.get("review_result")
    return bool(review and review.is_real_vuln and state.get("repo_path", "").strip())


def should_record_deep_context_skip(state: StateGraphStruct) -> bool:
    review = state.get("review_result")
    return bool(review and review.is_real_vuln and not state.get("repo_path", "").strip())


async def deep_context_analysis(state: StateGraphStruct) -> StateGraphStruct:
    review = state.get("review_result")
    if not review or not review.is_real_vuln:
        return {}

    parser = PydanticOutputParser(pydantic_object=DeepAnalysisStruct)
    prompt = _prompt_text("deep_context_analysis.txt").format(
        REVIEW_REASONING=review.reasoning,
        FULL_ANALYSIS=state.get("full_analysis_result", ""),
        SANITIZER_CODE=state.get("sanitizer_code", ""),
        RAG_CONTEXT=state.get("rag_context", "未检索到相关参考案例。"),
    )
    prompt = f"{prompt}\n\n{parser.get_format_instructions()}"
    opencode = OpenCodeAgent(
        project_path=state["repo_path"],
        model=os.getenv("OPENCODE_MODEL", DEFAULT_OPENCODE_MODEL),
    )
    response = opencode.chat(prompt)
    deep_result = _parse_deep_analysis_response(response, parser)
    return {
        "deep_analysis_attempted": True,
        "deep_analysis_result": response,
        "deep_analysis": deep_result,
        "deep_analysis_skipped": False,
        "deep_analysis_skip_reason": "",
        "deep_analysis_error": None,
        "poc_text": deep_result.poc.strip(),
        "final_verdict_source": "deep_context_analysis",
        "final_verdict_source_detail": "deep_context_analysis",
    }


async def get_result(state: StateGraphStruct) -> StateGraphStruct:
    analysis_profile = state.get("analysis_profile", "standard")
    analysis_backend = state.get("analysis_backend", "opencode")
    rag_relevance = state.get("rag_relevance")
    analysis_decision = state.get("full_analysis_decision")
    review = state.get("review_result")
    deep_analysis = state.get("deep_analysis")
    opencode_result = state.get("opencode_analysis")

    if not analysis_decision:
        analysis_decision = _conservative_analysis("缺少初步分析结果，无法给出更强结论。")
    if not review:
        review = ReviewDecisionStruct(
            reasoning="缺少复核结果，沿用初步分析。",
            is_real_vuln=analysis_decision.is_vuln,
            confidence=analysis_decision.confidence,
        )

    deep_skip_reason = state.get("deep_analysis_skip_reason", "")
    if not deep_skip_reason and should_record_deep_context_skip(state):
        deep_skip_reason = _deep_analysis_skip_reason(state)

    verdict_source = state.get("final_verdict_source", "review_result")
    verdict_source_detail = state.get("final_verdict_source_detail", verdict_source)
    evidence_summary = state.get("evidence_summary", "") or (opencode_result.evidence_summary if opencode_result else "")
    external_evidence_used = bool(state.get("external_evidence_used", False))
    external_evidence_sources = _normalize_sources(list(state.get("external_evidence_sources", [])))
    external_evidence_reason = state.get("external_evidence_reason", "")
    if not external_evidence_reason:
        external_evidence_reason = _default_public_evidence_reason(state, external_evidence_used)

    if deep_analysis:
        base_reasoning = opencode_result.reasoning if opencode_result else analysis_decision.reasoning
        final_is_vuln = deep_analysis.is_vuln
        final_reasoning = (
            f"基础分析：{base_reasoning}\n\n"
            f"复核结论：{review.reasoning}\n\n"
            f"源码上下文深挖：路径 {deep_analysis.vulnerable_path}\n"
            f"绕过分析：{deep_analysis.bypass_reasoning}\n\n"
            "最终以源码上下文深挖结论为准。"
        )
        final_confidence = review.confidence if review else analysis_decision.confidence
        poc_text = deep_analysis.poc.strip()
        verdict_source = "deep_context_analysis"
        verdict_source_detail = "deep_context_analysis"
        review_reasoning = review.reasoning
    elif opencode_result and analysis_backend == "opencode":
        final_is_vuln = opencode_result.is_vuln
        final_reasoning = opencode_result.reasoning.strip()
        if evidence_summary and evidence_summary not in final_reasoning:
            final_reasoning = f"{final_reasoning}\n\n关键证据：{evidence_summary}".strip()
        if external_evidence_reason and external_evidence_used:
            final_reasoning = f"{final_reasoning}\n\n公开资料补证：{external_evidence_reason}".strip()
        elif external_evidence_reason and _should_allow_public_evidence_search(state):
            final_reasoning = f"{final_reasoning}\n\n公开资料补证：{external_evidence_reason}".strip()
        final_confidence = opencode_result.confidence
        poc_text = state.get("poc_text", "")
        review_reasoning = review.reasoning
        verdict_source = verdict_source or "opencode_analysis"
        verdict_source_detail = verdict_source_detail or verdict_source
    elif review and review.is_real_vuln != analysis_decision.is_vuln:
        final_is_vuln = review.is_real_vuln
        final_reasoning = (
            f"初步分析：{analysis_decision.reasoning}\n\n"
            f"复核结论：{review.reasoning}\n\n"
            f"{deep_skip_reason}".strip()
        )
        if not final_reasoning.endswith("最终以复核结论为准。"):
            final_reasoning = f"{final_reasoning}\n\n最终以复核结论为准。".strip()
        final_confidence = review.confidence
        poc_text = state.get("poc_text", "")
        review_reasoning = review.reasoning
        verdict_source = verdict_source or "review_result"
        verdict_source_detail = verdict_source_detail or "llm_fallback_review"
    else:
        final_is_vuln = review.is_real_vuln if review else analysis_decision.is_vuln
        final_reasoning = review.reasoning if review else analysis_decision.reasoning
        if deep_skip_reason:
            final_reasoning = (
                f"{final_reasoning}\n\n{deep_skip_reason}"
            ).strip()
        final_confidence = review.confidence if review else analysis_decision.confidence
        poc_text = state.get("poc_text", "")
        review_reasoning = review.reasoning if review else analysis_decision.reasoning
        verdict_source = verdict_source or "review_result"
        verdict_source_detail = verdict_source_detail or "llm_fallback_review"

    if not deep_analysis and deep_skip_reason and deep_skip_reason not in final_reasoning:
        final_reasoning = f"{final_reasoning}\n\n{deep_skip_reason}".strip()

    final_result = FinalResultStruct(
        is_vuln=final_is_vuln,
        reasoning=final_reasoning,
        confidence=final_confidence,
        review_reasoning=review_reasoning,
        poc_text=poc_text,
        final_verdict_source=verdict_source,
        final_verdict_source_detail=verdict_source_detail,
        analysis_profile=analysis_profile,
        analysis_backend=analysis_backend,
        evidence_summary=evidence_summary,
        external_evidence_used=external_evidence_used,
        external_evidence_sources=external_evidence_sources,
        external_evidence_reason=external_evidence_reason,
        rag_relevance=rag_relevance,
    )
    return {
        "final_verdict_source": verdict_source,
        "final_verdict_source_detail": verdict_source_detail,
        "result": final_result,
    }


async def _run_analysis_pipeline(state: StateGraphStruct) -> StateGraphStruct:
    if should_extract_sanitizer(state):
        if state.get("input_mode") == "scanner_candidate":
            state.update(await extract_sanitizer_from_candidate(state))
        else:
            state.update(await extract_sanitizer_from_patch(state))

    state.update(await analyze_sanitizer_logic_node(state))
    state.update(await search_rag(state))

    try:
        state.update(await opencode_analysis(state))
    except Exception as exc:
        logger.warning("OpenCode analysis failed; switching to LLM fallback: %s", exc)
        _append_recoverable_error(state, _build_error_payload("opencode_analysis", exc))
        state.update(await run_llm_fallback(state, opencode_error=exc))

    if should_run_deep_context_analysis(state):
        try:
            state.update(await deep_context_analysis(state))
        except Exception as exc:
            logger.warning("Deep context analysis failed; preserving earlier verdict: %s", exc)
            error_payload = _build_error_payload("deep_context_analysis", exc)
            _append_recoverable_error(state, error_payload)
            state.update(_deep_context_failure_state(error_payload))
    elif should_record_deep_context_skip(state):
        state.update(
            {
                "deep_analysis_skipped": True,
                "deep_analysis_skip_reason": _deep_analysis_skip_reason(state),
            }
        )

    state.update(await get_result(state))
    return state


def build_graph():
    graph = StateGraph(StateGraphStruct)
    graph.add_node("prepare_input", prepare_input_node)
    graph.add_node("extract_sanitizer_from_patch", extract_sanitizer_from_patch)
    graph.add_node("extract_sanitizer_from_candidate", extract_sanitizer_from_candidate)
    graph.add_node("analyze_sanitizer_logic_node", analyze_sanitizer_logic_node)
    graph.add_node("search_rag", search_rag)
    graph.add_node("opencode_analysis", opencode_analysis)
    graph.add_node("deep_context_analysis", deep_context_analysis)
    graph.add_node("get_result", get_result)

    graph.add_edge(START, "prepare_input")
    graph.add_conditional_edges(
        "prepare_input",
        route_sanitizer_input,
        {
            "patch": "extract_sanitizer_from_patch",
            "scanner_candidate": "extract_sanitizer_from_candidate",
            "sanitizer_code": "analyze_sanitizer_logic_node",
        },
    )
    graph.add_edge("extract_sanitizer_from_patch", "analyze_sanitizer_logic_node")
    graph.add_edge("extract_sanitizer_from_candidate", "analyze_sanitizer_logic_node")
    graph.add_edge("analyze_sanitizer_logic_node", "search_rag")
    graph.add_edge("search_rag", "opencode_analysis")
    graph.add_conditional_edges(
        "opencode_analysis",
        should_run_deep_context_analysis,
        {
            True: "deep_context_analysis",
            False: "get_result",
        },
    )
    graph.add_edge("deep_context_analysis", "get_result")
    graph.add_edge("get_result", END)

    return graph.compile()


async def run_analysis(
    repo_path: str | None = None,
    patch_path: str | None = None,
    sanitizer_code: str | None = None,
    candidate_code: str | None = None,
    candidate_path: str | None = None,
    candidate_start_line: int | None = None,
    candidate_end_line: int | None = None,
    candidate_symbol: str | None = None,
    candidate_language: str | None = None,
    candidate_metadata: dict[str, Any] | None = None,
    analysis_profile: str = "standard",
) -> StateGraphStruct:
    logger.info(
        "Starting analysis pipeline input_mode_hint=%s repo_path_present=%s patch_path_present=%s candidate_code_present=%s analysis_profile=%s",
        "sanitizer_code" if sanitizer_code else "patch" if patch_path else "scanner_candidate" if candidate_code else "unknown",
        bool(repo_path),
        bool(patch_path),
        bool(candidate_code),
        analysis_profile,
    )
    return await _run_analysis_pipeline(
        _prepare_initial_state(
            repo_path,
            patch_path,
            sanitizer_code,
            candidate_code,
            candidate_path,
            candidate_start_line,
            candidate_end_line,
            candidate_symbol,
            candidate_language,
            candidate_metadata,
            analysis_profile,
        )
    )


async def run_analysis_with_audit(
    repo_path: str | None = None,
    patch_path: str | None = None,
    sanitizer_code: str | None = None,
    audit_dir: str | Path | None = None,
    *,
    candidate_code: str | None = None,
    candidate_path: str | None = None,
    candidate_start_line: int | None = None,
    candidate_end_line: int | None = None,
    candidate_symbol: str | None = None,
    candidate_language: str | None = None,
    candidate_metadata: dict[str, Any] | None = None,
    analysis_profile: str = "standard",
) -> StateGraphStruct:
    state = _prepare_initial_state(
        repo_path,
        patch_path,
        sanitizer_code,
        candidate_code,
        candidate_path,
        candidate_start_line,
        candidate_end_line,
        candidate_symbol,
        candidate_language,
        candidate_metadata,
        analysis_profile,
    )
    resolved_audit_dir = _resolve_audit_dir(state.get("patch_path", ""), audit_dir)
    resolved_audit_dir.mkdir(parents=True, exist_ok=True)
    logger.info(
        "Starting analysis with audit input_mode=%s audit_dir=%s repo_path_present=%s analysis_profile=%s",
        state.get("input_mode"),
        resolved_audit_dir,
        bool(state.get("repo_path")),
        state.get("analysis_profile"),
    )

    started_at = _utc_now()
    completed_nodes: list[str] = []

    async def execute_stage(
        file_name: str,
        node_name: str,
        node_fn: StageFn,
        *,
        fallback_on_error: bool = False,
        on_error_state: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        node_started_at = _utc_now()
        state_before = dict(state)
        try:
            logger.debug("Running analysis stage node=%s audit_file=%s", node_name, file_name)
            node_output = await node_fn(state)
            state.update(node_output)
            node_finished_at = _utc_now()
            completed_nodes.append(node_name)
            _write_stage_artifact(
                resolved_audit_dir,
                file_name,
                node=node_name,
                started_at=node_started_at,
                finished_at=node_finished_at,
                state_before=state_before,
                state_after=state,
                node_output=node_output,
            )
            return None
        except Exception as exc:
            error_payload = _build_error_payload(node_name, exc)
            if fallback_on_error:
                _append_recoverable_error(state, error_payload)
                recovery_state = on_error_state(error_payload) if on_error_state else {}
                if recovery_state:
                    state.update(recovery_state)
                node_finished_at = _utc_now()
                completed_nodes.append(node_name)
                _write_stage_artifact(
                    resolved_audit_dir,
                    file_name,
                    node=node_name,
                    started_at=node_started_at,
                    finished_at=node_finished_at,
                    state_before=state_before,
                    state_after=state,
                    node_output={
                        "error": error_payload,
                        "fallback_triggered": True,
                        "recovery_state": recovery_state,
                    },
                )
                logger.warning("Analysis stage failed node=%s; switching to fallback", node_name)
                return error_payload

            finished_at = _utc_now()
            logger.exception("Analysis stage failed node=%s audit_dir=%s", node_name, resolved_audit_dir)
            _write_json(
                resolved_audit_dir / "error.json",
                {
                    **error_payload,
                    "state_before": state_to_jsonable(state_before),
                    "state_after": state_to_jsonable(state),
                    "completed_nodes": completed_nodes,
                },
            )
            _write_json(
                resolved_audit_dir / "audit_summary.json",
                _build_summary(
                    state,
                    audit_dir=resolved_audit_dir,
                    started_at=started_at,
                    finished_at=finished_at,
                    status="failed",
                    completed_nodes=completed_nodes,
                    error=error_payload,
                ),
            )
            raise

    if should_extract_sanitizer(state):
        if state.get("input_mode") == "scanner_candidate":
            await execute_stage(
                "01_sanitizer_extraction.json",
                "extract_sanitizer_from_candidate",
                extract_sanitizer_from_candidate,
            )
        else:
            await execute_stage(
                "01_sanitizer_extraction.json",
                "extract_sanitizer_from_patch",
                extract_sanitizer_from_patch,
            )
    else:
        node_started_at = _utc_now()
        state_before = dict(state)
        node_output = {
            "skipped": True,
            "reason": "sanitizer_code provided directly",
            "input_source": state.get("input_source", "sanitizer_code"),
            "sanitizer_extraction_source": state.get("sanitizer_extraction_source", "provided"),
            "sanitizer_code": state.get("sanitizer_code", ""),
            "candidate_path": state.get("candidate_path", ""),
            "candidate_symbol": state.get("candidate_symbol", ""),
            "candidate_start_line": state.get("candidate_start_line"),
            "candidate_end_line": state.get("candidate_end_line"),
        }
        node_finished_at = _utc_now()
        completed_nodes.append(_sanitizer_extraction_stage_node(state))
        _write_stage_artifact(
            resolved_audit_dir,
            "01_sanitizer_extraction.json",
            node=_sanitizer_extraction_stage_node(state),
            started_at=node_started_at,
            finished_at=node_finished_at,
            state_before=state_before,
            state_after=state,
            node_output=node_output,
        )

    await execute_stage("02_sanitizer_logic.json", "analyze_sanitizer_logic_node", analyze_sanitizer_logic_node)
    await execute_stage("03_rag_search.json", "search_rag", search_rag)

    next_stage_number = 5
    opencode_error = await execute_stage(
        "04_opencode_analysis.json",
        "opencode_analysis",
        opencode_analysis,
        fallback_on_error=True,
    )
    if opencode_error is not None:
        fallback_started_at = _utc_now()
        fallback_state_before = dict(state)
        state.update(
            await run_llm_fallback(
                state,
                opencode_error=RuntimeError(opencode_error["message"]),
            )
        )
        fallback_finished_at = _utc_now()
        _write_stage_artifact(
            resolved_audit_dir,
            f"{next_stage_number:02d}_llm_fallback_analysis.json",
            node="full_analysis",
            started_at=fallback_started_at,
            finished_at=fallback_finished_at,
            state_before=fallback_state_before,
            state_after=state,
            node_output={
                "full_analysis_result": state.get("full_analysis_result", ""),
                "full_analysis_decision": state.get("full_analysis_decision"),
            },
        )
        completed_nodes.append("full_analysis")
        next_stage_number += 1
        review_started_at = _utc_now()
        review_state_before = dict(state)
        review_finished_at = _utc_now()
        _write_stage_artifact(
            resolved_audit_dir,
            f"{next_stage_number:02d}_llm_fallback_review.json",
            node="review_result",
            started_at=review_started_at,
            finished_at=review_finished_at,
            state_before=review_state_before,
            state_after=state,
            node_output={
                "review_result_raw": state.get("review_result_raw", ""),
                "review_result": state.get("review_result"),
            },
        )
        completed_nodes.append("review_result")
        next_stage_number += 1
    elif state.get("analysis_profile") == "enhanced_search" and _should_allow_public_evidence_search(state):
        node_started_at = _utc_now()
        state_before = dict(state)
        node_output = {
            "rag_relevance": state.get("rag_relevance"),
            "external_evidence_used": state.get("external_evidence_used", False),
            "external_evidence_sources": state.get("external_evidence_sources", []),
            "external_evidence_reason": state.get("external_evidence_reason", ""),
        }
        node_finished_at = _utc_now()
        completed_nodes.append("public_evidence_summary")
        _write_stage_artifact(
            resolved_audit_dir,
            f"{next_stage_number:02d}_public_evidence.json",
            node="public_evidence_summary",
            started_at=node_started_at,
            finished_at=node_finished_at,
            state_before=state_before,
            state_after=state,
            node_output=node_output,
        )
        next_stage_number += 1

    if should_run_deep_context_analysis(state):
        await execute_stage(
            f"{next_stage_number:02d}_deep_context_analysis.json",
            "deep_context_analysis",
            deep_context_analysis,
            fallback_on_error=True,
            on_error_state=_deep_context_failure_state,
        )
        next_stage_number += 1
    elif should_record_deep_context_skip(state):
        logger.info("Skipping deep context analysis reason=%s", _deep_analysis_skip_reason(state))
        state.update(
            {
                "deep_analysis_skipped": True,
                "deep_analysis_skip_reason": _deep_analysis_skip_reason(state),
            }
        )

    node_name = "get_result"
    node_started_at = _utc_now()
    state_before = dict(state)
    try:
        node_output = await get_result(state)
        state.update(node_output)
        node_finished_at = _utc_now()
        completed_nodes.append(node_name)
        _write_stage_artifact(
            resolved_audit_dir,
            f"{next_stage_number:02d}_final_result.json",
            node=node_name,
            started_at=node_started_at,
            finished_at=node_finished_at,
            state_before=state_before,
            state_after=state,
            node_output=node_output,
        )
    except Exception as exc:
        finished_at = _utc_now()
        error_payload = {
            "node": node_name,
            "message": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.exception("Analysis final result stage failed audit_dir=%s", resolved_audit_dir)
        _write_json(
            resolved_audit_dir / "error.json",
            {
                **error_payload,
                "state_before": state_to_jsonable(state_before),
                "state_after": state_to_jsonable(state),
                "completed_nodes": completed_nodes,
            },
        )
        _write_json(
            resolved_audit_dir / "audit_summary.json",
            _build_summary(
                state,
                audit_dir=resolved_audit_dir,
                started_at=started_at,
                finished_at=finished_at,
                status="failed",
                completed_nodes=completed_nodes,
                error=error_payload,
            ),
        )
        raise

    finished_at = _utc_now()
    _write_json(
        resolved_audit_dir / "audit_summary.json",
        _build_summary(
            state,
            audit_dir=resolved_audit_dir,
            started_at=started_at,
            finished_at=finished_at,
            status="success",
            completed_nodes=completed_nodes,
        ),
    )
    logger.info(
        "Analysis completed input_mode=%s final_is_vuln=%s audit_dir=%s analysis_backend=%s",
        state.get("input_mode"),
        state["result"].is_vuln,
        resolved_audit_dir,
        state.get("analysis_backend"),
    )
    return state
