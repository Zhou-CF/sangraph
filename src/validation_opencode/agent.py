from __future__ import annotations

import json
import os
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from json_repair import repair_json
from sangraph_logging import get_logger

from base_opencode.script import DEFAULT_OPENCODE_MODEL, OpenCodeAgent

from .llm_struct import ValidationResultStruct, ValidationStateStruct

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parents[1]
SKILL_DIR = PACKAGE_DIR / "skills" / "vuln-verification"
SKILL_FILE = SKILL_DIR / "SKILL.md"
REFERENCE_FILE = SKILL_DIR / "references" / "verification-rules.md"
DEFAULT_AUDIT_ROOT = REPO_ROOT / "other" / "artifacts" / "validation"
logger = get_logger(__name__)


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


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_text(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def _resolve_audit_dir(report_path: str, audit_dir: str | Path | None) -> Path:
    if audit_dir is not None:
        return _resolve_repo_path(audit_dir)
    report_stem = Path(report_path).stem or "report"
    timestamp = _utc_now().strftime("%Y%m%dT%H%M%SZ")
    return DEFAULT_AUDIT_ROOT / f"{timestamp}-{report_stem}-{uuid4().hex[:8]}"


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return stripped


def _load_report(report_path: str | Path) -> tuple[str, str, dict[str, Any] | None]:
    path = _resolve_repo_path(report_path)
    report_text = path.read_text(encoding="utf-8", errors="ignore")
    stripped = report_text.strip()
    if not stripped:
        return report_text, "text", None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return report_text, "text", None
    if isinstance(payload, dict):
        return report_text, "json", payload
    return report_text, "json", {"value": payload}


def _summarize_report(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not payload:
        return {}
    return {
        "repo_path": payload.get("repo_path", ""),
        "patch_path": payload.get("patch_path", ""),
        "status": payload.get("status", ""),
        "review_result": payload.get("review_result"),
        "result": payload.get("result"),
    }


def _skill_text() -> str:
    body = SKILL_FILE.read_text(encoding="utf-8")
    reference = REFERENCE_FILE.read_text(encoding="utf-8")
    return f"{body.strip()}\n\n## Reference Rules\n\n{reference.strip()}"


def _result_schema_instructions() -> str:
    return json.dumps(
        {
            "strategy": "full_env | native_test | minimal_harness",
            "verdict": "confirmed | not_reproduced | inconclusive",
            "reasoning": "evidence-based summary",
            "artifact_paths": {
                "audit_notebook": "/abs/path/to/audit_notebook.md",
                "main_artifact": "/abs/path/to/reproduce.py",
                "run_script": "/abs/path/to/run.sh",
            },
            "executed_command": "bash /abs/path/to/run.sh",
            "blockers": ["optional blocker 1", "optional blocker 2"],
        },
        ensure_ascii=False,
        indent=2,
    )


def build_validation_prompt(
    *,
    report_path: str,
    repo_path: str,
    workspace_dir: str,
    report_text: str,
) -> str:
    return (
        "You are validating a vulnerability report against a real codebase.\n"
        "Use the following mounted skill as the operating procedure.\n\n"
        f"{_skill_text()}\n\n"
        "## Runtime Inputs\n"
        f"- report_path: {report_path}\n"
        f"- repo_path: {repo_path}\n"
        f"- validation_workspace: {workspace_dir}\n\n"
        "## Execution Requirements\n"
        "- Perform the full validation flow, not just planning.\n"
        "- Create all generated artifacts inside validation_workspace.\n"
        "- The main validation artifact may be a script or a native test file.\n"
        "- Execute the generated validation and base the verdict on execution evidence.\n"
        "- Return JSON only. Do not wrap it in markdown.\n\n"
        "## Report Content\n"
        f"{report_text.strip()}\n\n"
        "## Required JSON Output\n"
        f"{_result_schema_instructions()}"
    )


def _parse_validation_result(response_text: str) -> ValidationResultStruct:
    stripped = _strip_code_fence(response_text)
    if not stripped:
        raise ValueError("OpenCode returned empty output.")
    repaired = repair_json(stripped, return_objects=True)
    if not isinstance(repaired, dict):
        preview = stripped[:400]
        raise ValueError(f"OpenCode response is not a JSON object. Preview: {preview}")
    return ValidationResultStruct.model_validate(repaired)


def _write_opencode_debug_outputs(audit_dir: Path, opencode: OpenCodeAgent | None) -> None:
    if opencode is None:
        return
    stdout = getattr(opencode, "last_stdout", "")
    stderr = getattr(opencode, "last_stderr", "")
    if stdout:
        _write_text(audit_dir / "03_opencode_raw_stdout.txt", stdout)
    if stderr:
        _write_text(audit_dir / "03_opencode_raw_stderr.txt", stderr)


def _initial_state(report_path: str, repo_path: str, audit_dir: Path) -> ValidationStateStruct:
    resolved_report_path = _resolve_repo_path(report_path)
    resolved_repo_path = _resolve_repo_path(repo_path)
    report_text, report_format, report_payload = _load_report(resolved_report_path)
    workspace_dir = audit_dir / "workspace"
    return {
        "report_path": str(resolved_report_path.resolve()),
        "repo_path": str(resolved_repo_path.resolve()),
        "audit_dir": str(audit_dir.resolve()),
        "workspace_dir": str(workspace_dir.resolve()),
        "report_text": report_text,
        "report_format": report_format,
        "report_payload": report_payload,
        "report_summary": _summarize_report(report_payload),
    }


async def run_validation(
    report_path: str,
    repo_path: str,
) -> ValidationStateStruct:
    return await run_validation_with_audit(report_path=report_path, repo_path=repo_path)


async def run_validation_with_audit(
    *,
    report_path: str,
    repo_path: str,
    audit_dir: str | Path | None = None,
) -> ValidationStateStruct:
    if not report_path:
        raise ValueError("report_path is required.")
    if not repo_path:
        raise ValueError("repo_path is required.")

    resolved_audit_dir = _resolve_audit_dir(report_path, audit_dir)
    resolved_audit_dir.mkdir(parents=True, exist_ok=True)
    state = _initial_state(report_path, repo_path, resolved_audit_dir)
    logger.info(
        "Starting validation report_path=%s repo_path=%s audit_dir=%s",
        state["report_path"],
        state["repo_path"],
        resolved_audit_dir,
    )

    started_at = _utc_now()

    _write_json(
        resolved_audit_dir / "01_report_input.json",
        {
            "report_path": state["report_path"],
            "repo_path": state["repo_path"],
            "audit_dir": state["audit_dir"],
            "workspace_dir": state["workspace_dir"],
            "report_format": state["report_format"],
            "report_summary": state["report_summary"],
            "report_payload": state["report_payload"],
            "report_text": state["report_text"],
        },
    )

    prompt_text = build_validation_prompt(
        report_path=state["report_path"],
        repo_path=state["repo_path"],
        workspace_dir=state["workspace_dir"],
        report_text=state["report_text"],
    )
    state["prompt_text"] = prompt_text
    _write_text(resolved_audit_dir / "02_validation_prompt.txt", prompt_text)

    opencode: OpenCodeAgent | None = None
    try:
        opencode = OpenCodeAgent(
            project_path=state["repo_path"],
            model=os.getenv("OPENCODE_MODEL", DEFAULT_OPENCODE_MODEL),
        )
        logger.debug("Submitting validation prompt to OpenCode workspace_dir=%s", state["workspace_dir"])
        response = opencode.chat(prompt_text)
        _write_opencode_debug_outputs(resolved_audit_dir, opencode)
        state["opencode_response"] = response
        _write_text(resolved_audit_dir / "03_opencode_response.txt", response)
        result = _parse_validation_result(response)
        state["result"] = result
    except Exception as exc:
        finished_at = _utc_now()
        _write_opencode_debug_outputs(resolved_audit_dir, opencode)
        error_payload = {
            "message": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc(),
        }
        logger.exception(
            "Validation failed report_path=%s repo_path=%s audit_dir=%s",
            state["report_path"],
            state["repo_path"],
            resolved_audit_dir,
        )
        _write_json(
            resolved_audit_dir / "error.json",
            {
                **error_payload,
                "report_path": state["report_path"],
                "repo_path": state["repo_path"],
                "audit_dir": state["audit_dir"],
                "workspace_dir": state["workspace_dir"],
            },
        )
        _write_json(
            resolved_audit_dir / "validation_summary.json",
            {
                "report_path": state["report_path"],
                "repo_path": state["repo_path"],
                "audit_dir": state["audit_dir"],
                "workspace_dir": state["workspace_dir"],
                "status": "failed",
                "started_at": _format_timestamp(started_at),
                "finished_at": _format_timestamp(finished_at),
                "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
                "error": error_payload,
            },
        )
        raise

    finished_at = _utc_now()
    _write_json(
        resolved_audit_dir / "validation_summary.json",
        {
            "report_path": state["report_path"],
            "repo_path": state["repo_path"],
            "audit_dir": state["audit_dir"],
            "workspace_dir": state["workspace_dir"],
            "status": "success",
            "started_at": _format_timestamp(started_at),
            "finished_at": _format_timestamp(finished_at),
            "duration_seconds": round((finished_at - started_at).total_seconds(), 3),
            "report_format": state["report_format"],
            "report_summary": state["report_summary"],
            "result": state["result"].model_dump(mode="json"),
        },
    )
    logger.info(
        "Validation completed verdict=%s strategy=%s audit_dir=%s",
        state["result"].verdict,
        state["result"].strategy,
        resolved_audit_dir,
    )
    return state
