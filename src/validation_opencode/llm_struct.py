from __future__ import annotations

from typing import Any, Literal, TypedDict

from pydantic import BaseModel, Field


class ValidationArtifactPathsStruct(BaseModel):
    audit_notebook: str = Field(..., description="Absolute path to audit_notebook.md")
    main_artifact: str = Field(..., description="Absolute path to the main validation artifact")
    run_script: str = Field(..., description="Absolute path to run.sh")


class ValidationResultStruct(BaseModel):
    strategy: Literal["full_env", "native_test", "minimal_harness"] = Field(
        ...,
        description="Selected validation strategy",
    )
    verdict: Literal["confirmed", "not_reproduced", "inconclusive"] = Field(
        ...,
        description="Final verification verdict",
    )
    reasoning: str = Field(..., description="Evidence-based summary of the result")
    artifact_paths: ValidationArtifactPathsStruct = Field(..., description="Generated artifact paths")
    executed_command: str = Field(..., description="Command actually executed")
    blockers: list[str] = Field(default_factory=list, description="Operational blockers or fallback reasons")


class ValidationStateStruct(TypedDict, total=False):
    report_path: str
    repo_path: str
    audit_dir: str
    workspace_dir: str
    report_text: str
    report_format: Literal["json", "text"]
    report_payload: dict[str, Any] | None
    report_summary: dict[str, Any]
    prompt_text: str
    opencode_response: str
    json_repair: dict[str, Any]
    result: ValidationResultStruct
