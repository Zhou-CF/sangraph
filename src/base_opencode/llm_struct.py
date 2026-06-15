import json
import os
from pathlib import Path
from typing import Any, Literal, TypedDict

from pydantic import BaseModel, Field


class SanitizerLogicStruct(BaseModel):
    reasoning: str = Field(..., description="你是如何识别出该 sanitizer 逻辑不安全或可能薄弱的")
    details: list[str] = Field(..., description="不安全 sanitizer 逻辑的细节描述")
    actions: list[str] = Field(..., description="sanitizer 执行的具体操作列表")
    logic_with_nlp: str = Field(..., description="使用自然语言描述的 sanitizer 逻辑")


class SanitizerCodeStruct(BaseModel):
    code: str = Field(..., description="仅提取补丁对应的核心防御代码")


class AnalysisDecisionStruct(BaseModel):
    reasoning: str = Field(..., description="基于目标代码与相似案例对比后的分析过程")
    is_vuln: bool = Field(..., description="判断目标代码是否仍然存在漏洞")
    confidence: Literal["low", "medium", "high"] = Field(
        default="medium",
        description="对该判断的置信度",
    )


class ReviewDecisionStruct(BaseModel):
    reasoning: str = Field(..., description="对初步分析结果的复核意见")
    is_real_vuln: bool = Field(..., description="复核后判断是否为真实漏洞")
    confidence: Literal["low", "medium", "high"] = Field(
        default="medium",
        description="对复核判断的置信度",
    )


class DeepAnalysisStruct(BaseModel):
    vulnerable_path: str = Field(..., description="从 Source 到 Sink 的关键数据流")
    bypass_reasoning: str = Field(..., description="为什么当前修复仍可被绕过，或为何不会被绕过")
    poc: str = Field(..., description="理论 PoC，可为 Python、HTTP 请求或 Bash 片段")
    is_vuln: bool = Field(..., description="结合源码上下文后，是否确认仍存在漏洞")
    verdict: Literal["confirmed", "plausible", "false_positive", "inaccurate"] = Field(
        ...,
        description="结合源码上下文后的最终裁定",
    )


class RAGRelevanceStruct(BaseModel):
    label: Literal["none", "low", "medium", "high"] = Field(
        default="none",
        description="RAG 命中的参考性等级",
    )
    reason: str = Field(default="", description="为何判定为该参考性等级")
    top_case_count: int = Field(default=0, description="纳入评估的前排案例数")
    usable_case_count: int = Field(default=0, description="可直接拿来对比的案例数")


class OpenCodeAnalysisStruct(BaseModel):
    reasoning: str = Field(..., description="OpenCode 对防御逻辑有效性的主分析")
    is_vuln: bool = Field(..., description="OpenCode 判断当前防御是否仍存在风险")
    confidence: Literal["low", "medium", "high"] = Field(
        default="medium",
        description="OpenCode 对该判断的置信度",
    )
    evidence_summary: str = Field(default="", description="支撑该判断的核心证据")
    external_evidence_used: bool = Field(
        default=False,
        description="是否使用了公开资料补证",
    )
    external_evidence_sources: list[str] = Field(
        default_factory=list,
        description="使用到的公开资料来源列表",
    )
    external_evidence_reason: str = Field(
        default="",
        description="为何启用、未启用或无法完成公开资料补证",
    )


class FinalResultStruct(BaseModel):
    is_vuln: bool = Field(..., description="最终是否判定为漏洞")
    reasoning: str = Field(..., description="最终结论与依据")
    confidence: Literal["low", "medium", "high"] = Field(
        default="medium",
        description="最终结论的置信度",
    )
    review_reasoning: str = Field(default="", description="复核阶段的关键理由")
    poc_text: str = Field(default="", description="最终保留的理论 PoC")
    final_verdict_source: str = Field(default="review_result", description="最终结论来源")
    final_verdict_source_detail: str = Field(default="", description="更细粒度的最终结论来源")
    analysis_profile: Literal["standard", "enhanced_search"] = Field(
        default="standard",
        description="本次分析所使用的产品模式",
    )
    analysis_backend: Literal["opencode", "llm_fallback"] = Field(
        default="opencode",
        description="本次分析最终采用的分析后端",
    )
    evidence_summary: str = Field(default="", description="关键证据摘要")
    external_evidence_used: bool = Field(default=False, description="是否使用公开资料补证")
    external_evidence_sources: list[str] = Field(
        default_factory=list,
        description="公开资料补证使用到的来源列表",
    )
    external_evidence_reason: str = Field(default="", description="公开资料补证的启用或跳过原因")
    rag_relevance: RAGRelevanceStruct | None = Field(default=None, description="RAG 参考性评估")


class StateGraphStruct(TypedDict, total=False):
    audit_dir: str
    repo_path: str
    patch_path: str
    analysis_profile: Literal["standard", "enhanced_search"]
    analysis_backend: Literal["opencode", "llm_fallback"]
    input_mode: Literal["patch", "sanitizer_code", "scanner_candidate"]
    input_source: str
    sanitizer_extraction_source: Literal["patch", "scanner_candidate", "provided"]
    sanitizer_code_provided: str
    candidate_code: str
    candidate_path: str
    candidate_start_line: int | None
    candidate_end_line: int | None
    candidate_symbol: str
    candidate_language: str
    candidate_metadata: dict[str, Any]
    analysis_result: str
    sanitizer_code: str
    sanitizer_logic: SanitizerLogicStruct
    sanitizer_logic_result: str
    sanitizer_logic_str: str
    rag_hits: list[dict]
    rag_relevance: RAGRelevanceStruct
    rag_context: str
    rag_search_result: str
    opencode_analysis_result: str
    opencode_analysis: OpenCodeAnalysisStruct
    full_analysis_result: str
    full_analysis_decision: AnalysisDecisionStruct
    review_result_raw: str
    review_result: ReviewDecisionStruct
    deep_analysis_result: str
    deep_analysis: DeepAnalysisStruct
    deep_analysis_attempted: bool
    deep_analysis_skipped: bool
    deep_analysis_skip_reason: str
    deep_analysis_error: dict[str, Any] | None
    poc_text: str
    evidence_summary: str
    external_evidence_used: bool
    external_evidence_sources: list[str]
    external_evidence_reason: str
    final_verdict_source: str
    final_verdict_source_detail: str
    json_repair_events: list[dict[str, Any]]
    recoverable_errors: list[dict[str, Any]]
    result: FinalResultStruct


def _load_json_payload(json_file_path: str | dict | Path) -> dict:
    if isinstance(json_file_path, dict):
        return json_file_path
    if isinstance(json_file_path, str):
        if os.path.exists(json_file_path):
            with open(json_file_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        return json.loads(json_file_path)
    if isinstance(json_file_path, Path):
        with open(json_file_path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    raise ValueError("输入必须是 JSON 文件路径、JSON 字符串或 dict。")


def to_jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def state_to_jsonable(state: StateGraphStruct | dict[str, Any]) -> dict[str, Any]:
    return {str(key): to_jsonable(value) for key, value in dict(state).items()}


def load_json_to_state_graph(json_file_path: str | dict | Path) -> StateGraphStruct:
    data = _load_json_payload(json_file_path)
    input_mode = data.get("input_mode", "patch")
    sanitizer_extraction_source = data.get("sanitizer_extraction_source")
    if sanitizer_extraction_source is None:
        if input_mode == "sanitizer_code":
            sanitizer_extraction_source = "provided"
        elif input_mode == "scanner_candidate":
            sanitizer_extraction_source = "scanner_candidate"
        else:
            sanitizer_extraction_source = "patch"

    state: StateGraphStruct = {
        "repo_path": data.get("repo_path", ""),
        "patch_path": data.get("patch_path", ""),
        "analysis_profile": data.get("analysis_profile", "standard"),
        "analysis_backend": data.get("analysis_backend", "opencode"),
        "input_mode": input_mode,
        "input_source": data.get("input_source", ""),
        "sanitizer_extraction_source": sanitizer_extraction_source,
        "sanitizer_code_provided": data.get("sanitizer_code_provided", ""),
        "candidate_code": data.get("candidate_code", ""),
        "candidate_path": data.get("candidate_path", ""),
        "candidate_start_line": data.get("candidate_start_line"),
        "candidate_end_line": data.get("candidate_end_line"),
        "candidate_symbol": data.get("candidate_symbol", ""),
        "candidate_language": data.get("candidate_language", ""),
        "candidate_metadata": data.get("candidate_metadata", {}),
        "analysis_result": data.get("analysis_result", ""),
        "sanitizer_code": data.get("sanitizer_code", ""),
        "sanitizer_logic_result": data.get("sanitizer_logic_result", ""),
        "sanitizer_logic_str": data.get("sanitizer_logic_str", ""),
        "rag_hits": data.get("rag_hits", []),
        "rag_context": data.get("rag_context", ""),
        "rag_search_result": data.get("rag_search_result", data.get("rag_context", "")),
        "opencode_analysis_result": data.get("opencode_analysis_result", ""),
        "full_analysis_result": data.get("full_analysis_result", ""),
        "review_result_raw": data.get("review_result_raw", ""),
        "deep_analysis_result": data.get("deep_analysis_result", ""),
        "deep_analysis_attempted": data.get("deep_analysis_attempted", bool(data.get("deep_analysis"))),
        "deep_analysis_skipped": data.get("deep_analysis_skipped", False),
        "deep_analysis_skip_reason": data.get("deep_analysis_skip_reason", ""),
        "deep_analysis_error": data.get("deep_analysis_error"),
        "poc_text": data.get("poc_text", ""),
        "evidence_summary": data.get("evidence_summary", ""),
        "external_evidence_used": data.get("external_evidence_used", False),
        "external_evidence_sources": data.get("external_evidence_sources", []),
        "external_evidence_reason": data.get("external_evidence_reason", ""),
        "final_verdict_source": data.get("final_verdict_source", ""),
        "final_verdict_source_detail": data.get("final_verdict_source_detail", ""),
        "recoverable_errors": data.get("recoverable_errors", []),
    }

    if data.get("sanitizer_logic"):
        state["sanitizer_logic"] = SanitizerLogicStruct(**data["sanitizer_logic"])
    if data.get("rag_relevance"):
        state["rag_relevance"] = RAGRelevanceStruct(**data["rag_relevance"])
    if data.get("opencode_analysis"):
        state["opencode_analysis"] = OpenCodeAnalysisStruct(**data["opencode_analysis"])
    if data.get("full_analysis_decision"):
        state["full_analysis_decision"] = AnalysisDecisionStruct(**data["full_analysis_decision"])
    if data.get("review_result"):
        state["review_result"] = ReviewDecisionStruct(**data["review_result"])
    if data.get("deep_analysis"):
        state["deep_analysis"] = DeepAnalysisStruct(**data["deep_analysis"])
    if data.get("result"):
        state["result"] = FinalResultStruct(**data["result"])

    return state
