from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_DIR = REPO_ROOT / "other" / "artifacts" / "logs"
DEFAULT_LOG_FILE_NAME = "sangraph.log"
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_BACKUP_COUNT = 5

_CONFIGURED = False
_LAST_SETTINGS: dict[str, Any] = {}


def _env_flag(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _resolve_level(level: str | int | None) -> int:
    raw = level if level is not None else os.getenv("SANGRAPH_LOG_LEVEL", "INFO")
    if isinstance(raw, int):
        return raw
    resolved = logging.getLevelName(str(raw).upper())
    if isinstance(resolved, int):
        return resolved
    return logging.INFO


def _resolve_log_dir(log_dir: str | Path | None) -> Path:
    if log_dir is None:
        configured = os.getenv("SANGRAPH_LOG_DIR")
        if configured:
            candidate = Path(configured)
        else:
            return DEFAULT_LOG_DIR
    else:
        candidate = Path(log_dir)

    if candidate.is_absolute():
        return candidate
    return (REPO_ROOT / candidate).resolve()


def get_log_file_path(log_dir: str | Path | None = None, file_name: str = DEFAULT_LOG_FILE_NAME) -> Path:
    return _resolve_log_dir(log_dir) / file_name


def setup_logging(
    *,
    level: str | int | None = None,
    log_dir: str | Path | None = None,
    console: bool | None = None,
    file_logging: bool | None = None,
    force: bool = False,
) -> logging.Logger:
    global _CONFIGURED, _LAST_SETTINGS

    resolved_level = _resolve_level(level)
    resolved_log_dir = _resolve_log_dir(log_dir)
    resolved_console = _env_flag("SANGRAPH_LOG_TO_CONSOLE", True) if console is None else console
    resolved_file_logging = _env_flag("SANGRAPH_LOG_TO_FILE", True) if file_logging is None else file_logging

    settings = {
        "level": resolved_level,
        "log_dir": str(resolved_log_dir),
        "console": resolved_console,
        "file_logging": resolved_file_logging,
    }
    root_logger = logging.getLogger()

    if _CONFIGURED and not force and settings == _LAST_SETTINGS:
        return root_logger

    if force or _CONFIGURED:
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)
            handler.close()

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(threadName)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root_logger.setLevel(resolved_level)

    if resolved_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    if resolved_file_logging:
        resolved_log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            resolved_log_dir / DEFAULT_LOG_FILE_NAME,
            maxBytes=DEFAULT_MAX_BYTES,
            backupCount=DEFAULT_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    if not root_logger.handlers:
        root_logger.addHandler(logging.NullHandler())

    for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(logger_name)
        uvicorn_logger.handlers = []
        uvicorn_logger.propagate = True
        uvicorn_logger.setLevel(resolved_level)

    _CONFIGURED = True
    _LAST_SETTINGS = settings

    app_logger = logging.getLogger("sangraph")
    app_logger.debug(
        "Logging configured",
        extra={
            "log_dir": str(resolved_log_dir),
            "console": resolved_console,
            "file_logging": resolved_file_logging,
            "level": resolved_level,
        },
    )
    return root_logger


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(name if name else "sangraph")
