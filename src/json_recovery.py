from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from json_repair import repair_json
from pydantic import BaseModel, ValidationError


RepairLLM = Callable[[str], Awaitable[str]]


@dataclass(slots=True)
class ParseRepairResult:
    value: BaseModel
    raw_text: str
    normalized_text: str
    repair_attempted: bool
    repair_method: str
    repair_succeeded: bool
    parse_error: str
    llm_retry_error: str
    artifacts: dict[str, str]


class JsonRecoveryError(RuntimeError):
    def __init__(
        self,
        *,
        stage_name: str,
        message: str,
        raw_text: str,
        normalized_text: str,
        parse_error: str,
        llm_retry_error: str,
        artifacts: dict[str, str],
    ) -> None:
        super().__init__(message)
        self.stage_name = stage_name
        self.raw_text = raw_text
        self.normalized_text = normalized_text
        self.parse_error = parse_error
        self.llm_retry_error = llm_retry_error
        self.artifacts = artifacts

    def to_payload(self) -> dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "message": str(self),
            "parse_error": self.parse_error,
            "llm_retry_error": self.llm_retry_error,
            "artifacts": self.artifacts,
        }


def _write_text(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _extract_balanced_block(text: str, opening: str, closing: str) -> list[str]:
    blocks: list[str] = []
    for start_index, char in enumerate(text):
        if char != opening:
            continue
        depth = 0
        in_string = False
        escape = False
        for index in range(start_index, len(text)):
            current = text[index]
            if escape:
                escape = False
                continue
            if current == "\\":
                escape = True
                continue
            if current == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if current == opening:
                depth += 1
            elif current == closing:
                depth -= 1
                if depth == 0:
                    blocks.append(text[start_index : index + 1].strip())
                    break
    return blocks


def extract_json_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for candidate in (text.strip(), strip_code_fence(text)):
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    balanced_blocks = _extract_balanced_block(text, "{", "}")
    balanced_blocks.extend(_extract_balanced_block(text, "[", "]"))
    for candidate in sorted(balanced_blocks, key=len, reverse=True):
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _model_schema_hint(schema_model: type[BaseModel]) -> str:
    return json.dumps(schema_model.model_json_schema(), ensure_ascii=False, indent=2)


def _coerce_model(
    schema_model: type[BaseModel],
    candidate: str,
) -> BaseModel:
    try:
        return schema_model.model_validate_json(candidate)
    except Exception:
        repaired = repair_json(candidate, return_objects=True)
        return schema_model.model_validate(repaired)


def _format_error(error: Exception) -> str:
    if isinstance(error, ValidationError):
        return error.json(indent=2)
    return str(error)


def build_json_repair_prompt(
    *,
    raw_text: str,
    normalized_text: str,
    stage_name: str,
    schema_model: type[BaseModel],
    parse_error: str,
) -> str:
    return (
        "You are repairing malformed structured output.\n"
        "Your task is to convert the provided content into a valid JSON object that matches the target schema.\n"
        "Do not add explanations. Do not wrap the output in markdown.\n"
        "Do not invent new security findings or execution evidence. Preserve the original meaning.\n\n"
        f"## Stage\n{stage_name}\n\n"
        "## Target JSON Schema\n"
        f"{_model_schema_hint(schema_model)}\n\n"
        "## Parsing Error\n"
        f"{parse_error or '<none>'}\n\n"
        "## Original Output\n"
        f"{raw_text.strip() or '<empty>'}\n\n"
        "## Normalized Candidate\n"
        f"{normalized_text.strip() or '<empty>'}\n\n"
        "Return JSON only."
    )


async def parse_or_repair_json(
    raw_text: str,
    *,
    schema_model: type[BaseModel],
    stage_name: str,
    audit_dir: str | Path | None = None,
    repair_llm: RepairLLM | None = None,
    allow_llm_retry: bool = True,
) -> ParseRepairResult:
    normalized_text = strip_code_fence(raw_text)
    parse_error = ""
    llm_retry_error = ""
    artifacts: dict[str, str] = {}
    audit_path = Path(audit_dir) if audit_dir is not None else None
    prefix = stage_name

    if audit_path is not None:
        raw_output_path = audit_path / f"{prefix}_llm_raw_output.txt"
        _write_text(raw_output_path, raw_text)
        artifacts["raw_output_path"] = str(raw_output_path.resolve())

    if not raw_text.strip():
        message = "Structured output is empty."
        if audit_path is not None:
            error_path = audit_path / f"{prefix}_json_parse_error.json"
            _write_json(error_path, {"stage_name": stage_name, "message": message})
            artifacts["parse_error_path"] = str(error_path.resolve())
        raise JsonRecoveryError(
            stage_name=stage_name,
            message=message,
            raw_text=raw_text,
            normalized_text=normalized_text,
            parse_error=message,
            llm_retry_error="",
            artifacts=artifacts,
        )

    candidates = extract_json_candidates(raw_text)
    if audit_path is not None:
        candidate_path = audit_path / f"{prefix}_json_candidate.txt"
        _write_text(candidate_path, "\n\n-----\n\n".join(candidates))
        artifacts["candidate_path"] = str(candidate_path.resolve())

    for candidate in candidates:
        try:
            value = _coerce_model(schema_model, candidate)
            method = "direct" if candidate == raw_text.strip() else "local_repair"
            return ParseRepairResult(
                value=value,
                raw_text=raw_text,
                normalized_text=candidate,
                repair_attempted=method != "direct",
                repair_method=method,
                repair_succeeded=True,
                parse_error=parse_error,
                llm_retry_error="",
                artifacts=artifacts,
            )
        except Exception as exc:
            parse_error = _format_error(exc)

    if audit_path is not None:
        error_path = audit_path / f"{prefix}_json_parse_error.json"
        _write_json(
            error_path,
            {
                "stage_name": stage_name,
                "parse_error": parse_error,
                "candidate_count": len(candidates),
            },
        )
        artifacts["parse_error_path"] = str(error_path.resolve())

    if allow_llm_retry and repair_llm is not None:
        repair_prompt = build_json_repair_prompt(
            raw_text=raw_text,
            normalized_text=normalized_text,
            stage_name=stage_name,
            schema_model=schema_model,
            parse_error=parse_error,
        )
        if audit_path is not None:
            retry_prompt_path = audit_path / f"{prefix}_json_repair_retry_prompt.txt"
            _write_text(retry_prompt_path, repair_prompt)
            artifacts["retry_prompt_path"] = str(retry_prompt_path.resolve())
        try:
            repaired_text = await repair_llm(repair_prompt)
            if audit_path is not None:
                retry_response_path = audit_path / f"{prefix}_json_repair_retry_response.txt"
                _write_text(retry_response_path, repaired_text)
                artifacts["retry_response_path"] = str(retry_response_path.resolve())
            repaired_result = await parse_or_repair_json(
                repaired_text,
                schema_model=schema_model,
                stage_name=stage_name,
                audit_dir=None,
                repair_llm=None,
                allow_llm_retry=False,
            )
            if audit_path is not None:
                repaired_json_path = audit_path / f"{prefix}_json_repair_result.json"
                _write_json(
                    repaired_json_path,
                    repaired_result.value.model_dump(mode="json"),
                )
                artifacts["repair_result_path"] = str(repaired_json_path.resolve())
            return ParseRepairResult(
                value=repaired_result.value,
                raw_text=raw_text,
                normalized_text=repaired_result.normalized_text,
                repair_attempted=True,
                repair_method="llm_repair",
                repair_succeeded=True,
                parse_error=parse_error,
                llm_retry_error="",
                artifacts=artifacts,
            )
        except Exception as exc:
            llm_retry_error = _format_error(exc)

    raise JsonRecoveryError(
        stage_name=stage_name,
        message=f"Failed to recover structured output for stage {stage_name}.",
        raw_text=raw_text,
        normalized_text=normalized_text,
        parse_error=parse_error,
        llm_retry_error=llm_retry_error,
        artifacts=artifacts,
    )
