from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import threading
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel
from sangraph_logging import DEFAULT_LOG_FILE_NAME, get_log_file_path, get_logger

from base_opencode import run_analysis_with_audit
from base_opencode.llm_struct import state_to_jsonable
from scanner import derive_debug_save_path, main as run_scan
from validation_opencode import run_validation_with_audit

from .models import (
    AnalysisTaskRequest,
    DependencyCheck,
    E2ETaskRequest,
    HealthResponse,
    TaskError,
    TaskListResponse,
    TaskResultEnvelope,
    TaskStage,
    TaskStatus,
    TaskStatusResponse,
    TaskType,
    ValidationTaskRequest,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WEB_ARTIFACT_ROOT = REPO_ROOT / "other" / "artifacts" / "web"
TASK_STATE_FILE_NAME = "task.json"
logger = get_logger(__name__)

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".php": "php",
}


@dataclass(slots=True)
class TaskOutcome:
    status: TaskStatus
    result: dict[str, Any] | None = None
    error: TaskError | None = None


@dataclass(slots=True, frozen=True)
class ValidationPlan:
    should_validate: bool
    validation_attempted: bool
    validation_skipped: bool
    skip_reason: str | None = None


@dataclass(slots=True, frozen=True)
class TaskLogBundle:
    archive_path: Path
    file_name: str
    cleanup_root: Path

    def cleanup(self) -> None:
        shutil.rmtree(self.cleanup_root, ignore_errors=True)


class TaskNotFoundError(KeyError):
    pass


class TaskResultNotReadyError(RuntimeError):
    pass


class WebTaskService:
    def __init__(self, artifact_root: str | Path | None = None):
        self.artifact_root = self._resolve_output_path(artifact_root) if artifact_root else DEFAULT_WEB_ARTIFACT_ROOT
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self._tasks: dict[str, dict[str, Any]] = {}
        self._futures: dict[str, asyncio.Task[None]] = {}
        self._lock = threading.Lock()
        self._restore_tasks_from_disk()
        logger.info("Initialized WebTaskService artifact_root=%s", self.artifact_root)

    async def submit_e2e(self, request: E2ETaskRequest) -> str:
        task_id = self._create_task("e2e", request.model_dump(exclude_none=True))
        self._futures[task_id] = asyncio.create_task(self._execute(task_id, self._run_e2e_task, request))
        return task_id

    async def submit_analysis(self, request: AnalysisTaskRequest) -> str:
        task_id = self._create_task("analysis", request.model_dump(exclude_none=True))
        self._futures[task_id] = asyncio.create_task(self._execute(task_id, self._run_analysis_task, request))
        return task_id

    async def submit_validation(self, request: ValidationTaskRequest) -> str:
        task_id = self._create_task("validation", request.model_dump(exclude_none=True))
        self._futures[task_id] = asyncio.create_task(self._execute(task_id, self._run_validation_task, request))
        return task_id

    def get_task_status(self, task_id: str) -> TaskResultEnvelope:
        with self._lock:
            payload = self._tasks.get(task_id)
        if payload is None:
            payload = self._load_task_from_disk(task_id)
            if payload is None:
                raise TaskNotFoundError(task_id)
            with self._lock:
                self._tasks[task_id] = payload
        return TaskResultEnvelope.model_validate(dict(payload))

    def get_task_result(self, task_id: str) -> TaskResultEnvelope:
        envelope = self.get_task_status(task_id)
        if envelope.status not in {"succeeded", "failed"}:
            raise TaskResultNotReadyError(task_id)
        if envelope.status == "succeeded" and envelope.result is None:
            raise TaskResultNotReadyError(task_id)
        return envelope

    def list_tasks(self, limit: int = 10) -> TaskListResponse:
        with self._lock:
            payloads = [dict(task) for task in self._tasks.values()]
        grouped: list[dict[str, Any]] = []
        active_tasks = sorted(
            (payload for payload in payloads if payload.get("status") in {"queued", "running"}),
            key=lambda payload: payload.get("created_at") or "",
            reverse=True,
        )
        completed_tasks = sorted(
            (payload for payload in payloads if payload.get("status") not in {"queued", "running"}),
            key=lambda payload: payload.get("created_at") or "",
            reverse=True,
        )
        grouped.extend(active_tasks)
        grouped.extend(completed_tasks)

        tasks = [TaskStatusResponse.model_validate(self._status_response_payload(payload)) for payload in grouped[: max(limit, 0)]]
        return TaskListResponse(tasks=tasks)

    async def wait_for_completion(
        self,
        task_id: str,
        *,
        timeout: float = 30.0,
        poll_interval: float = 0.05,
    ) -> TaskResultEnvelope:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        future = self._futures.get(task_id)
        while True:
            envelope = self.get_task_status(task_id)
            if envelope.status in {"succeeded", "failed"}:
                if future is None or future.done():
                    if future is not None:
                        future.result()
                    return envelope
            if loop.time() >= deadline:
                raise TimeoutError(f"Task did not finish within {timeout} seconds: {task_id}")
            await asyncio.sleep(poll_interval)

    def health(self) -> HealthResponse:
        opencode_available = shutil.which("opencode") is not None
        func_split_available, func_split_detail = self._function_splitter_health()
        dashscope_key = bool(os.getenv("DASHSCOPE_API_KEY"))
        milvus_uri = os.getenv("MILVUS_URI", "http://127.0.0.1:19530")

        checks = {
            "opencode": DependencyCheck(
                available=opencode_available,
                detail="CLI available on PATH" if opencode_available else "Install @opencode/cli and expose `opencode` on PATH.",
            ),
            "func_split": DependencyCheck(
                available=func_split_available,
                detail=func_split_detail,
            ),
            "dashscope_api_key": DependencyCheck(
                available=dashscope_key,
                detail="DASHSCOPE_API_KEY is set" if dashscope_key else "Set DASHSCOPE_API_KEY for default analysis and RAG flows.",
            ),
            "milvus": DependencyCheck(
                available=bool(milvus_uri),
                detail=f"Configured URI: {milvus_uri}",
            ),
        }
        status = "ok" if all(check.available for check in checks.values()) else "degraded"
        logger.debug("Health check computed status=%s", status)
        return HealthResponse(status=status, checks=checks, artifact_root=str(self.artifact_root.resolve()))

    def build_task_log_bundle(self, task_id: str) -> TaskLogBundle:
        envelope = self.get_task_status(task_id)
        if envelope.status not in {"succeeded", "failed"}:
            raise TaskResultNotReadyError(task_id)

        bundle_root = Path(tempfile.mkdtemp(prefix=f"sangraph-task-{task_id}-"))
        staging_root = bundle_root / f"sangraph-task-{task_id}"
        artifacts_root = staging_root / "artifacts"
        logs_root = staging_root / "logs"
        artifacts_root.mkdir(parents=True, exist_ok=True)
        logs_root.mkdir(parents=True, exist_ok=True)

        try:
            included_paths, missing_paths = self._copy_bundle_artifacts(task_id, envelope, artifacts_root)
            log_sources, matched_log_lines = self._write_task_log(task_id, logs_root / "task.log")
            manifest = {
                "task_id": envelope.task_id,
                "task_type": envelope.task_type,
                "status": envelope.status,
                "created_at": envelope.created_at,
                "finished_at": envelope.finished_at,
                "summary": envelope.result.get("summary") if envelope.result else None,
                "error": envelope.error.model_dump(mode="json") if envelope.error else None,
                "included_artifacts": included_paths,
                "missing_artifacts": missing_paths,
                "log_files_scanned": [str(path.resolve()) for path in log_sources],
                "log_match_count": matched_log_lines,
            }
            self._write_json(staging_root / "manifest.json", manifest)

            archive_base = bundle_root / f"sangraph-task-{task_id}"
            archive_path = Path(
                shutil.make_archive(
                    str(archive_base),
                    "zip",
                    root_dir=bundle_root,
                    base_dir=staging_root.name,
                )
            )
            logger.info(
                "Built task log bundle task_id=%s archive_path=%s included_artifacts=%s",
                task_id,
                archive_path,
                len(included_paths),
            )
            return TaskLogBundle(
                archive_path=archive_path,
                file_name=f"sangraph-task-{task_id}.zip",
                cleanup_root=bundle_root,
            )
        except Exception:
            shutil.rmtree(bundle_root, ignore_errors=True)
            raise

    async def _execute(self, task_id: str, runner: Any, request: BaseModel) -> None:
        self._set_status(task_id, status="running")
        logger.info("Executing task task_id=%s task_type=%s", task_id, self._require_task(task_id)["task_type"])
        try:
            outcome = await asyncio.to_thread(runner, task_id, request)
        except Exception as exc:
            logger.exception("Task execution crashed task_id=%s", task_id)
            self._finalize_failure(
                task_id,
                TaskError(
                    code=type(exc).__name__,
                    message=str(exc),
                    detail={"traceback": traceback.format_exc()},
                ),
            )
            return

        if outcome.error is not None:
            self._set_error(task_id, outcome.error)
        self._finalize_task(task_id, outcome.status, outcome.result)

    def _run_analysis_task(self, task_id: str, request: AnalysisTaskRequest) -> TaskOutcome:
        task_dir = self._task_dir(task_id)
        analysis_dir = task_dir / "analysis"
        report_path = task_dir / "analysis_report.json"

        self._set_stage(task_id, "analysis")
        logger.info(
            "Running analysis task task_id=%s repo_path_present=%s patch_path_present=%s sanitizer_code_present=%s analysis_profile=%s",
            task_id,
            bool(request.repo_path),
            bool(request.patch_path),
            bool(request.sanitizer_code),
            request.analysis_profile,
        )
        analysis_state = self._run_analysis_sync(
            repo_path=request.repo_path,
            patch_path=request.patch_path,
            sanitizer_code=request.sanitizer_code,
            audit_dir=analysis_dir,
            analysis_profile=request.analysis_profile,
        )
        serialized_analysis = state_to_jsonable(analysis_state)
        self._write_json(report_path, serialized_analysis)
        final_result = analysis_state["result"].model_dump(mode="json")
        validation_plan = self._build_validation_plan(request.repo_path, analysis_state)

        validation_state = None
        validation_result = None
        validation_dir: Path | None = None

        if validation_plan.should_validate:
            self._set_stage(task_id, "validation")
            logger.info("Continuing analysis task into validation task_id=%s", task_id)
            validation_dir = task_dir / "validation"
            validation_state = self._run_validation_sync(
                report_path=str(report_path.resolve()),
                repo_path=request.repo_path or "",
                audit_dir=validation_dir,
            )
            validation_result = validation_state["result"].model_dump(mode="json")
        else:
            logger.info(
                "Skipping validation for analysis task task_id=%s reason=%s",
                task_id,
                validation_plan.skip_reason,
            )

        payload = {
            "task_type": "analysis",
            "status": "succeeded",
            "inputs": request.model_dump(exclude_none=True),
            "summary": {
                "analysis_profile": request.analysis_profile,
                "analysis_backend": final_result.get("analysis_backend"),
                "input_mode": analysis_state.get("input_mode"),
                "is_vuln": final_result["is_vuln"],
                "confidence": final_result["confidence"],
                "rag_relevance": final_result.get("rag_relevance"),
                "external_evidence_used": final_result.get("external_evidence_used"),
                "validation_attempted": validation_plan.validation_attempted,
                "validation_skipped": validation_plan.validation_skipped,
                "validation_verdict": validation_result["verdict"] if validation_result else None,
            },
            "artifacts": {
                "analysis_audit_dir": str(analysis_dir.resolve()),
                "analysis_report_path": str(report_path.resolve()),
                "validation_audit_dir": str(validation_dir.resolve()) if validation_dir else None,
            },
            "raw_result": {
                "analysis": serialized_analysis,
                "validation": validation_state,
            },
            "analysis_result": final_result,
            "analysis_report_path": str(report_path.resolve()),
            "validation_attempted": validation_plan.validation_attempted,
            "validation_skipped": validation_plan.validation_skipped,
            "skip_reason": validation_plan.skip_reason,
            "validation_result": validation_result,
            "analysis_audit_dir": str(analysis_dir.resolve()),
            "validation_audit_dir": str(validation_dir.resolve()) if validation_dir else None,
        }
        logger.info(
            "Analysis task complete task_id=%s validation_attempted=%s final_is_vuln=%s",
            task_id,
            validation_plan.validation_attempted,
            final_result["is_vuln"],
        )
        return TaskOutcome(status="succeeded", result=payload)

    def _run_validation_task(self, task_id: str, request: ValidationTaskRequest) -> TaskOutcome:
        task_dir = self._task_dir(task_id)
        validation_dir = self._resolve_output_path(request.audit_dir) if request.audit_dir else task_dir / "validation"

        self._set_stage(task_id, "validation")
        logger.info("Running validation task task_id=%s report_path=%s", task_id, request.report_path)
        validation_state = self._run_validation_sync(
            report_path=request.report_path,
            repo_path=request.repo_path,
            audit_dir=validation_dir,
        )
        validation_result = validation_state["result"].model_dump(mode="json")
        payload = {
            "task_type": "validation",
            "status": "succeeded",
            "inputs": request.model_dump(exclude_none=True),
            "summary": {
                "verdict": validation_result["verdict"],
                "strategy": validation_result["strategy"],
            },
            "artifacts": {
                "validation_audit_dir": str(validation_dir.resolve()),
            },
            "raw_result": {
                "validation": validation_state,
            },
            "validation_result": validation_result,
            "validation_audit_dir": str(validation_dir.resolve()),
        }
        logger.info(
            "Validation task complete task_id=%s verdict=%s strategy=%s",
            task_id,
            validation_result["verdict"],
            validation_result["strategy"],
        )
        return TaskOutcome(status="succeeded", result=payload)

    def _run_e2e_task(self, task_id: str, request: E2ETaskRequest) -> TaskOutcome:
        task_dir = self._task_dir(task_id)
        scan_output_path = self._resolve_output_path(request.scan_save_path) if request.scan_save_path else task_dir / "scan_candidates.json"
        scan_debug_path = derive_debug_save_path(scan_output_path)

        self._set_stage(task_id, "scan")
        logger.info("Running e2e scan task_id=%s repo_path=%s", task_id, request.repo_path)
        candidates = run_scan(request.repo_path, str(scan_output_path), str(scan_debug_path))
        if not candidates:
            payload = {
                "task_type": "e2e",
                "status": "failed",
                "inputs": request.model_dump(exclude_none=True),
                "summary": {
                    "scan_candidate_count": 0,
                    "partial_failures": False,
                },
                "artifacts": {
                    "scan_output_path": str(scan_output_path.resolve()),
                    "scan_debug_path": str(scan_debug_path.resolve()),
                },
                "raw_result": {
                    "scan_candidates": [],
                },
                "scan_candidate_count": 0,
                "scan_output_path": str(scan_output_path.resolve()),
                "scan_debug_path": str(scan_debug_path.resolve()),
                "candidate_runs": [],
            }
            return TaskOutcome(
                status="failed",
                result=payload,
                error=TaskError(
                    code="no_candidate_found",
                    message="Scanner did not return any sanitizer candidates.",
                ),
            )

        candidate_runs: list[dict[str, Any]] = []
        success_count = 0
        failure_count = 0
        logger.info("E2E scan produced %s candidates task_id=%s", len(candidates), task_id)

        for index, candidate in enumerate(candidates, start=1):
            candidate_dir = task_dir / f"candidate-{index:03d}"
            analysis_dir = candidate_dir / "analysis"
            report_path = candidate_dir / "analysis_report.json"
            validation_dir = candidate_dir / "validation"
            candidate_payload: dict[str, Any] = {
                "candidate_index": index,
                "candidate_path": candidate.get("file_path"),
                "start_line": candidate.get("start_line"),
                "end_line": candidate.get("end_line"),
                "candidate_code": candidate.get("code", ""),
                "analysis_report_path": str(report_path.resolve()),
                "validation_attempted": False,
                "validation_skipped": False,
                "skip_reason": None,
                "validation_result": None,
                "validation_audit_dir": None,
                "status": "failed",
                "error": None,
            }
            try:
                logger.info(
                    "Processing e2e candidate task_id=%s candidate_index=%s candidate_path=%s",
                    task_id,
                    index,
                    candidate.get("file_path"),
                )
                self._set_stage(task_id, "analysis")
                analysis_state = self._run_analysis_sync(
                    repo_path=request.repo_path,
                    patch_path=None,
                    sanitizer_code=None,
                    audit_dir=analysis_dir,
                    candidate_code=candidate.get("code", ""),
                    candidate_path=candidate.get("file_path"),
                    candidate_start_line=candidate.get("start_line"),
                    candidate_end_line=candidate.get("end_line"),
                    candidate_language=self._candidate_language(candidate.get("file_path")),
                    candidate_metadata={
                        "code_hash": candidate.get("code_hash"),
                        "llm_reasoning": candidate.get("llm_reasoning"),
                    },
                    analysis_profile="standard",
                )
                serialized_analysis = state_to_jsonable(analysis_state)
                self._write_json(report_path, serialized_analysis)
                candidate_payload["analysis_result"] = analysis_state["result"].model_dump(mode="json")
                candidate_payload["analysis_audit_dir"] = str(analysis_dir.resolve())
                candidate_payload["raw_result"] = {
                    "analysis": serialized_analysis,
                    "validation": None,
                }
                validation_plan = self._build_validation_plan(request.repo_path, analysis_state)
                candidate_payload["validation_attempted"] = validation_plan.validation_attempted
                candidate_payload["validation_skipped"] = validation_plan.validation_skipped
                candidate_payload["skip_reason"] = validation_plan.skip_reason

                if validation_plan.should_validate:
                    self._set_stage(task_id, "validation")
                    validation_state = self._run_validation_sync(
                        report_path=str(report_path.resolve()),
                        repo_path=request.repo_path,
                        audit_dir=validation_dir,
                    )
                    candidate_payload["validation_result"] = validation_state["result"].model_dump(mode="json")
                    candidate_payload["validation_audit_dir"] = str(validation_dir.resolve())
                    candidate_payload["raw_result"]["validation"] = validation_state
                    logger.info(
                        "Candidate validation complete task_id=%s candidate_index=%s validation_verdict=%s",
                        task_id,
                        index,
                        candidate_payload["validation_result"]["verdict"],
                    )
                else:
                    logger.info(
                        "Skipping validation for e2e candidate task_id=%s candidate_index=%s reason=%s",
                        task_id,
                        index,
                        validation_plan.skip_reason,
                    )

                candidate_payload["status"] = "succeeded"
                candidate_runs.append(candidate_payload)
                success_count += 1
                if candidate_payload["validation_result"] is not None:
                    logger.info(
                        "Candidate succeeded task_id=%s candidate_index=%s validation_verdict=%s",
                        task_id,
                        index,
                        candidate_payload["validation_result"]["verdict"],
                    )
                else:
                    logger.info(
                        "Candidate succeeded task_id=%s candidate_index=%s validation_skipped=%s reason=%s",
                        task_id,
                        index,
                        candidate_payload["validation_skipped"],
                        candidate_payload["skip_reason"],
                    )
            except Exception as exc:
                logger.exception(
                    "Candidate processing failed task_id=%s candidate_index=%s candidate_path=%s",
                    task_id,
                    index,
                    candidate.get("file_path"),
                )
                candidate_payload["error"] = {
                    "code": type(exc).__name__,
                    "message": str(exc),
                }
                if candidate_payload.get("analysis_result") is None:
                    candidate_payload["validation_attempted"] = False
                    candidate_payload["validation_skipped"] = False
                    candidate_payload["skip_reason"] = None
                candidate_runs.append(candidate_payload)
                failure_count += 1

        overall_status: TaskStatus = "succeeded" if success_count > 0 else "failed"
        payload = {
            "task_type": "e2e",
            "status": overall_status,
            "inputs": request.model_dump(exclude_none=True),
            "summary": {
                "scan_candidate_count": len(candidates),
                "successful_candidates": success_count,
                "failed_candidates": failure_count,
                "partial_failures": failure_count > 0 and success_count > 0,
            },
            "artifacts": {
                "scan_output_path": str(scan_output_path.resolve()),
                "scan_debug_path": str(scan_debug_path.resolve()),
                "task_dir": str(task_dir.resolve()),
            },
            "raw_result": {
                "scan_candidates": candidates,
            },
            "scan_candidate_count": len(candidates),
            "scan_output_path": str(scan_output_path.resolve()),
            "scan_debug_path": str(scan_debug_path.resolve()),
            "candidate_runs": candidate_runs,
        }
        error = None
        if success_count == 0:
            error = TaskError(
                code="all_candidates_failed",
                message="All scanned candidates failed during analysis or validation.",
            )
        logger.info(
            "E2E task complete task_id=%s success_count=%s failure_count=%s overall_status=%s",
            task_id,
            success_count,
            failure_count,
            overall_status,
        )
        return TaskOutcome(status=overall_status, result=payload, error=error)

    @staticmethod
    def _run_analysis_sync(
        repo_path: str | None,
        patch_path: str | None,
        sanitizer_code: str | None,
        audit_dir: str | Path,
        candidate_code: str | None = None,
        candidate_path: str | None = None,
        candidate_start_line: int | None = None,
        candidate_end_line: int | None = None,
        candidate_language: str | None = None,
        candidate_metadata: dict[str, Any] | None = None,
        analysis_profile: str = "standard",
    ) -> dict[str, Any]:
        return asyncio.run(
            run_analysis_with_audit(
                repo_path=repo_path,
                patch_path=patch_path,
                sanitizer_code=sanitizer_code,
                audit_dir=audit_dir,
                candidate_code=candidate_code,
                candidate_path=candidate_path,
                candidate_start_line=candidate_start_line,
                candidate_end_line=candidate_end_line,
                candidate_language=candidate_language,
                candidate_metadata=candidate_metadata,
                analysis_profile=analysis_profile,
            )
        )

    @staticmethod
    def _run_validation_sync(report_path: str, repo_path: str, audit_dir: str | Path) -> dict[str, Any]:
        return asyncio.run(
            run_validation_with_audit(
                report_path=report_path,
                repo_path=repo_path,
                audit_dir=audit_dir,
            )
        )

    def _create_task(self, task_type: TaskType, inputs: dict[str, Any]) -> str:
        task_id = uuid4().hex
        now = self._timestamp()
        payload = {
            "task_id": task_id,
            "task_type": task_type,
            "status": "queued",
            "progress_stage": "queued",
            "created_at": now,
            "finished_at": None,
            "inputs": inputs,
            "error": None,
            "result": None,
        }
        with self._lock:
            self._tasks[task_id] = payload
        self._persist_task_snapshot(task_id, payload)
        logger.info("Created task task_id=%s task_type=%s inputs=%s", task_id, task_type, inputs)
        return task_id

    def _finalize_failure(self, task_id: str, error: TaskError) -> None:
        with self._lock:
            payload = self._require_task(task_id)
            payload["status"] = "failed"
            payload["progress_stage"] = "completed"
            payload["finished_at"] = self._timestamp()
            payload["error"] = error.model_dump(mode="json")
            snapshot = dict(payload)
        self._persist_task_snapshot(task_id, snapshot)
        logger.error("Task failed task_id=%s error_code=%s error_message=%s", task_id, error.code, error.message)

    def _finalize_task(self, task_id: str, status: TaskStatus, result: dict[str, Any] | None) -> None:
        with self._lock:
            payload = self._require_task(task_id)
            payload["status"] = status
            payload["progress_stage"] = "completed"
            payload["finished_at"] = self._timestamp()
            payload["result"] = self._jsonable(result)
            snapshot = dict(payload)
        self._persist_task_snapshot(task_id, snapshot)
        logger.info("Task finalized task_id=%s status=%s", task_id, status)

    def _set_error(self, task_id: str, error: TaskError) -> None:
        with self._lock:
            payload = self._require_task(task_id)
            payload["error"] = error.model_dump(mode="json")
            snapshot = dict(payload)
        self._persist_task_snapshot(task_id, snapshot)
        logger.warning("Task recorded non-fatal error task_id=%s error_code=%s", task_id, error.code)

    def _set_stage(self, task_id: str, stage: TaskStage) -> None:
        with self._lock:
            payload = self._require_task(task_id)
            payload["progress_stage"] = stage
            snapshot = dict(payload)
        self._persist_task_snapshot(task_id, snapshot)
        logger.info("Task stage updated task_id=%s stage=%s", task_id, stage)

    def _set_status(self, task_id: str, status: TaskStatus) -> None:
        with self._lock:
            payload = self._require_task(task_id)
            payload["status"] = status
            snapshot = dict(payload)
        self._persist_task_snapshot(task_id, snapshot)
        logger.info("Task status updated task_id=%s status=%s", task_id, status)

    def _task_dir(self, task_id: str) -> Path:
        path = self.artifact_root / task_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _task_state_path(self, task_id: str) -> Path:
        return self._task_dir(task_id) / TASK_STATE_FILE_NAME

    def _require_task(self, task_id: str) -> dict[str, Any]:
        payload = self._tasks.get(task_id)
        if payload is None:
            raise TaskNotFoundError(task_id)
        return payload

    @classmethod
    def _resolve_output_path(cls, path: str | Path | None) -> Path:
        if path is None:
            return DEFAULT_WEB_ARTIFACT_ROOT
        candidate = Path(path)
        if candidate.is_absolute():
            return candidate
        return (REPO_ROOT / candidate).resolve()

    @staticmethod
    def _write_json(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _persist_task_snapshot(self, task_id: str, payload: dict[str, Any]) -> None:
        self._write_json(self._task_state_path(task_id), self._jsonable(payload))

    def _restore_tasks_from_disk(self) -> None:
        restored_count = 0
        interrupted_count = 0
        for task_dir in sorted(path for path in self.artifact_root.iterdir() if path.is_dir()):
            state_path = task_dir / TASK_STATE_FILE_NAME
            if not state_path.is_file():
                continue
            payload = self._read_task_snapshot(state_path)
            if payload is None:
                continue
            payload, was_interrupted = self._normalize_restored_task(payload)
            self._tasks[payload["task_id"]] = payload
            restored_count += 1
            if was_interrupted:
                interrupted_count += 1
                self._persist_task_snapshot(payload["task_id"], payload)
        if restored_count:
            logger.info(
                "Restored %s task snapshots from %s interrupted=%s",
                restored_count,
                self.artifact_root,
                interrupted_count,
            )

    def _load_task_from_disk(self, task_id: str) -> dict[str, Any] | None:
        state_path = self.artifact_root / task_id / TASK_STATE_FILE_NAME
        payload = self._read_task_snapshot(state_path)
        if payload is not None:
            logger.info("Loaded task snapshot from disk task_id=%s path=%s", task_id, state_path)
        return payload

    def _read_task_snapshot(self, state_path: Path) -> dict[str, Any] | None:
        try:
            payload = json.loads(state_path.read_text(encoding="utf-8"))
            envelope = TaskResultEnvelope.model_validate(payload)
        except FileNotFoundError:
            return None
        except Exception:
            logger.exception("Failed to restore task snapshot path=%s", state_path)
            return None
        return envelope.model_dump(mode="json")

    def _normalize_restored_task(self, payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        if payload["status"] not in {"queued", "running"}:
            return payload, False
        interrupted_payload = dict(payload)
        interrupted_payload["status"] = "failed"
        interrupted_payload["progress_stage"] = "completed"
        interrupted_payload["finished_at"] = interrupted_payload.get("finished_at") or self._timestamp()
        interrupted_payload["error"] = TaskError(
            code="server_restarted",
            message="Task was interrupted because the API process restarted before completion.",
            detail={
                "restored_from_disk": True,
                "previous_status": payload["status"],
                "previous_stage": payload.get("progress_stage"),
            },
        ).model_dump(mode="json")
        return interrupted_payload, True

    @staticmethod
    def _status_response_payload(payload: dict[str, Any]) -> dict[str, Any]:
        status_payload = dict(payload)
        status_payload.pop("result", None)
        return status_payload

    @classmethod
    def _jsonable(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            return value.model_dump(mode="json")
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, dict):
            return {str(key): cls._jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._jsonable(item) for item in value]
        return value

    @staticmethod
    def _candidate_language(file_path: str | None) -> str:
        if not file_path:
            return ""
        return LANGUAGE_BY_SUFFIX.get(Path(file_path).suffix.lower(), "")

    @classmethod
    def _build_validation_plan(cls, repo_path: str | None, analysis_state: dict[str, Any]) -> ValidationPlan:
        if not (repo_path or "").strip():
            return ValidationPlan(
                should_validate=False,
                validation_attempted=False,
                validation_skipped=True,
                skip_reason="repo_path_not_provided",
            )
        if not cls._analysis_result_is_vuln(analysis_state):
            return ValidationPlan(
                should_validate=False,
                validation_attempted=False,
                validation_skipped=True,
                skip_reason="analysis_negative",
            )
        return ValidationPlan(
            should_validate=True,
            validation_attempted=True,
            validation_skipped=False,
            skip_reason=None,
        )

    @staticmethod
    def _analysis_result_is_vuln(analysis_state: dict[str, Any]) -> bool:
        analysis_result = analysis_state["result"]
        if isinstance(analysis_result, BaseModel):
            return bool(analysis_result.is_vuln)
        if isinstance(analysis_result, dict):
            return bool(analysis_result["is_vuln"])
        return bool(analysis_result.is_vuln)

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _function_splitter_health() -> tuple[bool, str]:
        try:
            from scanner.func_split import FunctionSplitter  # noqa: F401
        except Exception as exc:
            return False, f"Scanner helper import failed: {exc}"
        return True, "Built-in scanner function splitter is importable."

    def _copy_bundle_artifacts(
        self,
        task_id: str,
        envelope: TaskResultEnvelope,
        artifacts_root: Path,
    ) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        included_paths: list[dict[str, str]] = []
        missing_paths: list[dict[str, str]] = []
        selected_paths = self._select_bundle_artifact_paths(task_id, envelope.result)
        task_dir = self.artifact_root / task_id

        external_index = 0
        for path in selected_paths:
            source_path = path.resolve()
            if not source_path.exists():
                missing_paths.append({"source_path": str(source_path), "reason": "path_missing"})
                continue

            if source_path == task_dir.resolve():
                destination = artifacts_root / "task"
            else:
                external_index += 1
                destination = artifacts_root / "external" / f"{external_index:02d}-{source_path.name}"

            if source_path.is_dir():
                shutil.copytree(source_path, destination)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, destination)

            included_paths.append(
                {
                    "source_path": str(source_path),
                    "archive_path": str(destination.relative_to(artifacts_root.parent)),
                    "kind": "directory" if source_path.is_dir() else "file",
                }
            )

        return included_paths, missing_paths

    def _select_bundle_artifact_paths(self, task_id: str, result: dict[str, Any] | None) -> list[Path]:
        candidates: list[Path] = [self.artifact_root / task_id]
        result_payload = result or {}

        artifacts = result_payload.get("artifacts")
        if isinstance(artifacts, dict):
            for raw_path in self._iter_path_strings(artifacts):
                candidates.append(self._resolve_output_path(raw_path))

        for key in (
            "analysis_report_path",
            "analysis_audit_dir",
            "validation_audit_dir",
            "scan_output_path",
            "scan_debug_path",
        ):
            raw_path = result_payload.get(key)
            if isinstance(raw_path, str) and raw_path.strip():
                candidates.append(self._resolve_output_path(raw_path))

        unique_candidates: list[Path] = []
        seen = set()
        for candidate in candidates:
            resolved = candidate.resolve()
            resolved_key = str(resolved)
            if resolved_key in seen:
                continue
            seen.add(resolved_key)
            unique_candidates.append(resolved)

        unique_candidates.sort(key=lambda path: (0 if path.is_dir() else 1, len(path.parts)))

        selected: list[Path] = []
        selected_dirs: list[Path] = []
        for candidate in unique_candidates:
            if any(parent == candidate or parent in candidate.parents for parent in selected_dirs):
                continue
            selected.append(candidate)
            if candidate.is_dir():
                selected_dirs.append(candidate)

        return selected

    @classmethod
    def _iter_path_strings(cls, value: Any) -> list[str]:
        paths: list[str] = []
        if isinstance(value, str):
            text = value.strip()
            if text:
                paths.append(text)
        elif isinstance(value, dict):
            for item in value.values():
                paths.extend(cls._iter_path_strings(item))
        elif isinstance(value, (list, tuple)):
            for item in value:
                paths.extend(cls._iter_path_strings(item))
        return paths

    def _write_task_log(self, task_id: str, destination: Path) -> tuple[list[Path], int]:
        destination.parent.mkdir(parents=True, exist_ok=True)
        log_sources = self._task_log_sources()
        matched_lines: list[str] = []

        for source in log_sources:
            with source.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if task_id in line:
                        matched_lines.append(line)

        if matched_lines:
            destination.write_text("".join(matched_lines), encoding="utf-8")
        else:
            destination.write_text(
                f"# No log lines found for task_id={task_id}\n",
                encoding="utf-8",
            )

        return log_sources, len(matched_lines)

    @staticmethod
    def _log_rotation_index(path: Path, base_name: str) -> int:
        suffix = path.name.removeprefix(base_name)
        if not suffix:
            return 0
        if suffix.startswith(".") and suffix[1:].isdigit():
            return int(suffix[1:])
        return -1

    def _task_log_sources(self) -> list[Path]:
        configured_logs: list[Path] = []
        for handler in logging.getLogger().handlers:
            base_name = getattr(handler, "baseFilename", None)
            if isinstance(base_name, str) and base_name:
                configured_logs.append(Path(base_name))

        if not configured_logs:
            configured_logs.append(get_log_file_path())

        collected: dict[Path, str] = {}
        for log_file in configured_logs:
            log_dir = log_file.parent
            if not log_dir.exists():
                continue
            base_name = log_file.name or DEFAULT_LOG_FILE_NAME
            for candidate in log_dir.glob(f"{base_name}*"):
                if not candidate.is_file():
                    continue
                if candidate.name != base_name and not candidate.name.startswith(f"{base_name}."):
                    continue
                resolved = candidate.resolve()
                collected.setdefault(resolved, base_name)

        return [
            path
            for path, _ in sorted(
                collected.items(),
                key=lambda item: (
                    1 if item[0].name == item[1] else 0,
                    -self._log_rotation_index(item[0], item[1]),
                    item[0].name,
                ),
            )
        ]
