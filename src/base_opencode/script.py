import subprocess
import os
import json
import shlex
import shutil
import tempfile
from typing import Any, Optional

from dotenv import load_dotenv
from sangraph_logging import get_logger

DEFAULT_OPENCODE_MODEL = "alibaba-cn/qwen3.7-plus"
DEFAULT_DASHSCOPE_API_KEY = "sk-326bf87f51154797a7a379fe7d960396"
DASHSCOPE_OPENAI_COMPAT_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
OPENCODE_PROVIDER_ID = "alibaba-cn"
logger = get_logger(__name__)

load_dotenv(override=True)


class OpenCodeAgent:
    """
    OpenCode CLI 的 Python 包装器，支持多轮对话上下文管理。
    """
    
    def __init__(
        self,
        project_path: str,
        model: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        """
        初始化 Agent
        :param project_path: 目标项目路径
        :param model: (可选) 指定模型，如 'anthropic/claude-3-5-sonnet'
        :param session_id: (可选) 如果想接续之前的会话，传入 ID
        """
        self.project_path = os.path.abspath(project_path)
        self.model = model or DEFAULT_OPENCODE_MODEL
        self.session_id = session_id
        self.last_stdout = ""
        self.last_stderr = ""
        self.last_events: list[dict[str, Any]] = []
        self.last_command: list[str] = []

        # 1. 环境检查
        if not shutil.which("opencode"):
            raise EnvironmentError("未找到 'opencode' 命令，请确保已安装: npm install -g opencode-ai")
        
        if not os.path.exists(self.project_path):
            raise FileNotFoundError(f"项目路径不存在: {self.project_path}")
        logger.debug(
            "Initialized OpenCodeAgent project_path=%s model=%s session_id=%s permission=%s",
            self.project_path,
            self.model,
            self.session_id,
            "allow",
        )

    def chat(self, prompt: str) -> str:
        """
        发送 Prompt 并获取回复（同步阻塞）。
        自动维护 Session ID 以保持多轮对话。
        """
        try:
            return self._run_chat(prompt, model=self.model)
        except RuntimeError as exc:
            if self.model and self._contains_model_not_found(str(exc)):
                logger.warning("OpenCode model %s not found; retrying with default model", self.model)
                return self._run_chat(prompt, model=None)
            logger.error("OpenCode chat failed: %s", exc)
            raise

    def _run_chat(self, prompt: str, model: Optional[str]) -> str:
        cmd = [
            "opencode",
            "run",
            "--format",
            "json",
            "--print-logs",
            "--dir",
            self.project_path,
        ]

        if self.session_id:
            cmd.extend(["--session", self.session_id])

        cli_model = self._resolve_cli_model(model)
        if cli_model:
            cmd.extend(["--model", cli_model])

        cmd.append(prompt)

        logger.debug(
            "Running OpenCode command cwd=%s model=%s session_id=%s prompt_length=%s",
            self.project_path,
            model,
            self.session_id,
            len(prompt),
        )

        self.last_command = list(cmd)
        with tempfile.TemporaryDirectory(prefix="opencode-config-") as config_dir:
            env = os.environ.copy()
            config_path = self._write_temp_config(config_dir)
            env["OPENCODE_CONFIG_DIR"] = config_dir
            logger.debug("Using temporary OpenCode config at %s", config_path)
            result = subprocess.run(
                cmd,
                cwd=self.project_path,
                env=env,
                capture_output=True,
                text=True,
                encoding='utf-8',
                check=False,
            )

        self.last_stdout = getattr(result, "stdout", "")
        self.last_stderr = getattr(result, "stderr", "")
        self.last_events = self._parse_event_stream(self.last_stdout)
        returncode = getattr(result, "returncode", 0)

        if returncode != 0:
            raise self._runtime_error(self._build_failure_message(returncode))

        response_text = self._extract_text_response(self.last_events).strip()
        if not response_text:
            raise self._runtime_error(self._build_empty_output_message())

        if not self.session_id:
            self._refresh_session_id()

        logger.debug(
            "OpenCode response received length=%s stderr_length=%s event_count=%s",
            len(response_text),
            len(self.last_stderr),
            len(self.last_events),
        )
        return response_text

    @staticmethod
    def _contains_model_not_found(text: str) -> bool:
        return "Model not found" in text

    def _resolve_cli_model(self, model: Optional[str]) -> str | None:
        if not model:
            return None
        if model == "qwen3.7-plus":
            return DEFAULT_OPENCODE_MODEL
        if "/" not in model:
            logger.warning(
                "Skipping explicit OpenCode model '%s' because CLI expects provider/model; falling back to configured default",
                model,
            )
            return None
        return model

    def _build_failure_message(self, returncode: int) -> str:
        debug = self.get_debug_snapshot()
        return (
            f"OpenCode 执行失败 (Exit Code {returncode}).\n"
            f"project_path: {debug['project_path']}\n"
            f"command: {debug['command_text'] or '<empty>'}\n"
            f"event_count: {debug['event_count']}\n"
            f"event_types: {', '.join(debug['event_types']) or '<none>'}\n"
            f"stdout preview:\n{debug['stdout_preview'] or '<empty>'}\n\n"
            f"stderr preview:\n{debug['stderr_preview'] or '<empty>'}"
        )

    def _build_empty_output_message(self) -> str:
        debug = self.get_debug_snapshot()
        return (
            "OpenCode returned no text response.\n"
            f"project_path: {debug['project_path']}\n"
            f"command: {debug['command_text'] or '<empty>'}\n"
            f"event_count: {debug['event_count']}\n"
            f"event_types: {', '.join(debug['event_types']) or '<none>'}\n"
            f"stdout preview:\n{debug['stdout_preview'] or '<empty>'}\n\n"
            f"stderr preview:\n{debug['stderr_preview'] or '<empty>'}"
        )

    def _runtime_error(self, message: str) -> RuntimeError:
        error = RuntimeError(message)
        error.opencode_debug = self.get_debug_snapshot()
        return error

    def get_debug_snapshot(self, *, preview_chars: int = 1200, max_events: int = 20) -> dict[str, Any]:
        command = self._sanitized_command()
        return {
            "project_path": self.project_path,
            "model": self.model,
            "session_id": self.session_id,
            "command": command,
            "command_text": shlex.join(command) if command else "",
            "stdout_length": len(self.last_stdout),
            "stderr_length": len(self.last_stderr),
            "stdout_preview": self._preview_text(self.last_stdout, preview_chars),
            "stderr_preview": self._preview_text(self.last_stderr, preview_chars),
            "event_count": len(self.last_events),
            "event_types": self._event_types(),
            "last_events": [self._summarize_event(event) for event in self.last_events[-max_events:]],
        }

    def _sanitized_command(self) -> list[str]:
        if not self.last_command:
            return []
        command = list(self.last_command)
        if command[:2] == ["opencode", "run"] and command[-1]:
            command[-1] = f"<prompt length={len(command[-1])}>"
        return command

    def _event_types(self) -> list[str]:
        event_types: list[str] = []
        for event in self.last_events:
            event_type = str(event.get("type") or "<unknown>")
            if event_type not in event_types:
                event_types.append(event_type)
        return event_types

    @staticmethod
    def _preview_text(value: str, limit: int) -> str:
        text = value.strip()
        if len(text) <= limit:
            return text
        return f"{text[:limit]}...(truncated {len(text) - limit} chars)"

    @classmethod
    def _summarize_event(cls, event: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {"type": event.get("type", "<unknown>")}
        part = event.get("part")
        if not isinstance(part, dict):
            return summary

        part_type = part.get("type")
        if part_type:
            summary["part_type"] = part_type

        text = part.get("text")
        if isinstance(text, str) and text.strip():
            summary["text_preview"] = cls._preview_text(text, 200)

        tool_name = part.get("tool")
        if isinstance(tool_name, str) and tool_name.strip():
            summary["tool"] = tool_name.strip()

        state = part.get("state")
        if isinstance(state, dict):
            status = state.get("status")
            if status:
                summary["status"] = status
            input_payload = state.get("input")
            if isinstance(input_payload, dict):
                description = input_payload.get("description")
                if isinstance(description, str) and description.strip():
                    summary["description"] = cls._preview_text(description, 200)
        return summary

    @staticmethod
    def _parse_event_stream(raw_stdout: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for line in raw_stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                events.append(payload)
        return events

    @staticmethod
    def _extract_text_response(events: list[dict[str, Any]]) -> str:
        text_parts: list[str] = []
        for event in events:
            if event.get("type") != "text":
                continue
            part = event.get("part")
            if isinstance(part, dict):
                text = part.get("text")
                if isinstance(text, str):
                    text_parts.append(text)
        return "".join(text_parts)

    def _write_temp_config(self, config_dir: str) -> str:
        payload = {
            "$schema": "https://opencode.ai/config.json",
            "model": self._resolve_cli_model(self.model) or DEFAULT_OPENCODE_MODEL,
            "provider": {
                OPENCODE_PROVIDER_ID: {
                    "options": {
                        "apiKey": self._dashscope_api_key(),
                        "baseURL": DASHSCOPE_OPENAI_COMPAT_BASE_URL,
                    },
                },
            },
            "permission": "allow",
        }
        path = os.path.join(config_dir, "opencode.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        return path

    @staticmethod
    def _dashscope_api_key() -> str:
        return os.getenv("DASHSCOPE_API_KEY") or DEFAULT_DASHSCOPE_API_KEY

    def _refresh_session_id(self):
        """内部方法：从 CLI 获取刚刚创建的 Session ID"""
        try:
            # 获取最近的一个 session
            cmd = ["opencode", "session", "list", "-n", "1", "--format", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            sessions = json.loads(result.stdout)
            if sessions and len(sessions) > 0:
                self.session_id = sessions[0].get('id')
                logger.debug("Refreshed OpenCode session_id=%s", self.session_id)
        except Exception:
            # 获取 ID 失败不应阻断程序，只是无法维持上下文
            logger.debug("Failed to refresh OpenCode session id", exc_info=True)

    def get_session_id(self) -> str:
        """获取当前的 Session ID，方便持久化存储"""
        return self.session_id
