from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

TaskType = Literal["e2e", "analysis", "validation"]
TaskStatus = Literal["queued", "running", "succeeded", "failed"]
TaskStage = Literal["queued", "scan", "analysis", "validation", "completed"]


class TaskError(BaseModel):
    code: str
    message: str
    detail: dict[str, Any] = Field(default_factory=dict)


class E2ETaskRequest(BaseModel):
    repo_path: str = Field(..., min_length=1)
    scan_save_path: str | None = None
    audit_root: str | None = None


class AnalysisTaskRequest(BaseModel):
    patch_path: str | None = None
    sanitizer_code: str | None = None
    repo_path: str | None = None
    analysis_profile: Literal["standard", "enhanced_search"] = "standard"

    @model_validator(mode="after")
    def validate_input_mode(self) -> "AnalysisTaskRequest":
        modes = [bool((self.patch_path or "").strip()), bool((self.sanitizer_code or "").strip())]
        if sum(modes) != 1:
            raise ValueError("Exactly one of patch_path or sanitizer_code must be provided.")
        return self


class ValidationTaskRequest(BaseModel):
    report_path: str = Field(..., min_length=1)
    repo_path: str = Field(..., min_length=1)
    audit_dir: str | None = None


class TaskCreatedResponse(BaseModel):
    task_id: str


class TaskStatusResponse(BaseModel):
    task_id: str
    task_type: TaskType
    status: TaskStatus
    progress_stage: TaskStage
    created_at: str
    finished_at: str | None = None
    inputs: dict[str, Any]
    error: TaskError | None = None


class TaskResultEnvelope(TaskStatusResponse):
    result: dict[str, Any] | None = None


class DependencyCheck(BaseModel):
    available: bool
    detail: str


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    checks: dict[str, DependencyCheck]
    artifact_root: str
