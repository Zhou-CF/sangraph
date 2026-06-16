from __future__ import annotations

import time

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.requests import Request
from sangraph_logging import get_logger
from starlette.background import BackgroundTask

from .models import (
    AnalysisTaskRequest,
    E2ETaskRequest,
    HealthResponse,
    TaskCreatedResponse,
    TaskListResponse,
    TaskResultEnvelope,
    TaskStatusResponse,
    ValidationTaskRequest,
)
from .service import TaskNotFoundError, TaskResultNotReadyError, WebTaskService

logger = get_logger(__name__)


def create_app(service: WebTaskService | None = None) -> FastAPI:
    app = FastAPI(title="SanGraph Web API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.task_service = service or WebTaskService()

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.perf_counter() - started) * 1000
            logger.exception(
                "Unhandled HTTP error method=%s path=%s duration_ms=%.2f",
                request.method,
                request.url.path,
                duration_ms,
            )
            raise

        duration_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "HTTP request method=%s path=%s status_code=%s duration_ms=%.2f",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        return response

    @app.get("/api/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return app.state.task_service.health()

    @app.post("/api/tasks/e2e", response_model=TaskCreatedResponse, status_code=202)
    async def create_e2e_task(request: E2ETaskRequest) -> TaskCreatedResponse:
        task_id = await app.state.task_service.submit_e2e(request)
        return TaskCreatedResponse(task_id=task_id)

    @app.post("/api/tasks/analysis", response_model=TaskCreatedResponse, status_code=202)
    async def create_analysis_task(request: AnalysisTaskRequest) -> TaskCreatedResponse:
        task_id = await app.state.task_service.submit_analysis(request)
        return TaskCreatedResponse(task_id=task_id)

    @app.post("/api/tasks/validation", response_model=TaskCreatedResponse, status_code=202)
    async def create_validation_task(request: ValidationTaskRequest) -> TaskCreatedResponse:
        task_id = await app.state.task_service.submit_validation(request)
        return TaskCreatedResponse(task_id=task_id)

    @app.get("/api/tasks", response_model=TaskListResponse)
    async def list_tasks(limit: int = 10) -> TaskListResponse:
        return app.state.task_service.list_tasks(limit=limit)

    @app.get("/api/tasks/{task_id}", response_model=TaskStatusResponse)
    async def get_task_status(task_id: str) -> TaskStatusResponse:
        try:
            return app.state.task_service.get_task_status(task_id)
        except TaskNotFoundError as exc:
            raise HTTPException(status_code=404, detail=f"Unknown task: {exc.args[0]}") from exc

    @app.get("/api/tasks/{task_id}/result", response_model=TaskResultEnvelope)
    async def get_task_result(task_id: str) -> TaskResultEnvelope:
        try:
            return app.state.task_service.get_task_result(task_id)
        except TaskNotFoundError as exc:
            raise HTTPException(status_code=404, detail=f"Unknown task: {exc.args[0]}") from exc
        except TaskResultNotReadyError as exc:
            raise HTTPException(status_code=409, detail=f"Task is not finished yet: {exc.args[0]}") from exc

    @app.get("/api/tasks/{task_id}/log-bundle")
    async def download_task_log_bundle(task_id: str) -> FileResponse:
        try:
            bundle = app.state.task_service.build_task_log_bundle(task_id)
        except TaskNotFoundError as exc:
            raise HTTPException(status_code=404, detail=f"Unknown task: {exc.args[0]}") from exc
        except TaskResultNotReadyError as exc:
            raise HTTPException(status_code=409, detail=f"Task is not finished yet: {exc.args[0]}") from exc

        return FileResponse(
            path=bundle.archive_path,
            media_type="application/zip",
            filename=bundle.file_name,
            background=BackgroundTask(bundle.cleanup),
        )

    return app


app = create_app()
