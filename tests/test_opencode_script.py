import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from base_opencode.script import (
    DASHSCOPE_OPENAI_COMPAT_BASE_URL,
    DEFAULT_DASHSCOPE_API_KEY,
    DEFAULT_OPENCODE_MODEL,
    OPENCODE_PROVIDER_ID,
    OpenCodeAgent,
)


class OpenCodeScriptTests(unittest.TestCase):
    def test_parse_event_stream_extracts_text(self):
        raw = "\n".join(
            [
                '{"type":"step_start","part":{"type":"step-start"}}',
                '{"type":"text","part":{"type":"text","text":"{\\"ok\\": true}"}}',
            ]
        )
        events = OpenCodeAgent._parse_event_stream(raw)
        self.assertEqual(len(events), 2)
        self.assertEqual(OpenCodeAgent._extract_text_response(events), '{"ok": true}')

    def test_parse_event_stream_ignores_non_json_lines(self):
        raw = "\u001b[0m\n> build · qwen3.7-max\n{\"type\":\"text\",\"part\":{\"text\":\"done\"}}"
        events = OpenCodeAgent._parse_event_stream(raw)
        self.assertEqual(len(events), 1)
        self.assertEqual(OpenCodeAgent._extract_text_response(events), "done")

    def test_extract_text_response_uses_last_text_run(self):
        raw = "\n".join(
            [
                '{"type":"text","part":{"type":"text","text":"Now let me inspect the repo first."}}',
                '{"type":"tool_use","part":{"type":"tool","tool":"read"}}',
                '{"type":"text","part":{"type":"text","text":"{\\"ok\\":"}}',
                '{"type":"text","part":{"type":"text","text":" true}"}}',
            ]
        )
        events = OpenCodeAgent._parse_event_stream(raw)
        self.assertEqual(OpenCodeAgent._extract_text_response(events), '{"ok": true}')

    def test_extract_text_response_prefers_structured_text_run(self):
        raw = "\n".join(
            [
                '{"type":"text","part":{"type":"text","text":"thinking out loud"}}',
                '{"type":"step_finish","part":{"type":"step-finish"}}',
                '{"type":"text","part":{"type":"text","text":"```json\\n{\\"result\\": \\"ok\\"}\\n```"}}',
            ]
        )
        events = OpenCodeAgent._parse_event_stream(raw)
        self.assertEqual(
            OpenCodeAgent._extract_text_response(events),
            '```json\n{"result": "ok"}\n```',
        )

    def test_build_empty_output_message_includes_stdout_and_stderr_preview(self):
        agent = OpenCodeAgent.__new__(OpenCodeAgent)
        agent.project_path = "/tmp/project"
        agent.model = DEFAULT_OPENCODE_MODEL
        agent.session_id = "ses_test"
        agent.last_command = [
            "opencode",
            "run",
            "--format",
            "json",
            "--print-logs",
            "--dir",
            "/tmp/project",
            "prompt text",
        ]
        agent.last_stdout = '{"type":"step_start","part":{"type":"step-start"}}\n{"type":"tool_use","part":{"type":"tool","tool":"task"}}'
        agent.last_stderr = "something on stderr"
        agent.last_events = OpenCodeAgent._parse_event_stream(agent.last_stdout)
        message = agent._build_empty_output_message()
        self.assertIn("OpenCode returned no text response", message)
        self.assertIn("project_path: /tmp/project", message)
        self.assertIn("command:", message)
        self.assertIn("event_count: 2", message)
        self.assertIn("step_start", message)
        self.assertIn("tool_use", message)
        self.assertIn("something on stderr", message)

    def test_run_chat_passes_explicit_directory_and_print_logs(self):
        with TemporaryDirectory() as tmp_dir:
            result = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout='{"type":"text","part":{"text":"done"}}\n',
                stderr="debug line",
            )
            with patch("base_opencode.script.shutil.which", return_value="/usr/bin/opencode"):
                with patch("base_opencode.script.subprocess.run", return_value=result) as mock_run:
                    agent = OpenCodeAgent(project_path=tmp_dir, model=None, session_id="ses_existing")
                    response = agent.chat("inspect repo")

        self.assertEqual(response, "done")
        command = mock_run.call_args.kwargs["args"] if "args" in mock_run.call_args.kwargs else mock_run.call_args.args[0]
        self.assertIn("--dir", command)
        self.assertIn(str(Path(tmp_dir).resolve()), command)
        self.assertIn("--print-logs", command)
        self.assertEqual(mock_run.call_args.kwargs["cwd"], str(Path(tmp_dir).resolve()))

    def test_resolve_cli_model_uses_provider_model_for_opencode(self):
        with TemporaryDirectory() as tmp_dir:
            agent = OpenCodeAgent(project_path=tmp_dir, model=None)
            self.assertEqual(DEFAULT_OPENCODE_MODEL, "alibaba-cn/qwen3.7-plus")
            self.assertEqual(agent.model, "alibaba-cn/qwen3.7-plus")
            self.assertEqual(agent._resolve_cli_model("qwen3.7-plus"), "alibaba-cn/qwen3.7-plus")
            self.assertEqual(agent._resolve_cli_model("alibaba-cn/qwen3.7-plus"), "alibaba-cn/qwen3.7-plus")
            self.assertIsNone(agent._resolve_cli_model("custom-model-without-provider"))

    def test_temp_config_includes_alibaba_provider_defaults(self):
        original_key = os.environ.pop("DASHSCOPE_API_KEY", None)
        try:
            with TemporaryDirectory() as tmp_dir:
                agent = OpenCodeAgent.__new__(OpenCodeAgent)
                agent.project_path = str(Path(tmp_dir).resolve())
                agent.model = DEFAULT_OPENCODE_MODEL

                config_path = agent._write_temp_config(tmp_dir)
                payload = json.loads(Path(config_path).read_text(encoding="utf-8"))
        finally:
            if original_key is not None:
                os.environ["DASHSCOPE_API_KEY"] = original_key

        self.assertEqual(payload["model"], DEFAULT_OPENCODE_MODEL)
        provider_options = payload["provider"][OPENCODE_PROVIDER_ID]["options"]
        self.assertEqual(provider_options["apiKey"], DEFAULT_DASHSCOPE_API_KEY)
        self.assertEqual(provider_options["baseURL"], DASHSCOPE_OPENAI_COMPAT_BASE_URL)
        self.assertEqual(payload["permission"], "allow")

    def test_temp_config_prefers_dashscope_key_from_environment(self):
        original_key = os.environ.get("DASHSCOPE_API_KEY")
        os.environ["DASHSCOPE_API_KEY"] = "custom-dashscope-key"
        try:
            with TemporaryDirectory() as tmp_dir:
                agent = OpenCodeAgent.__new__(OpenCodeAgent)
                agent.project_path = str(Path(tmp_dir).resolve())
                agent.model = DEFAULT_OPENCODE_MODEL

                config_path = agent._write_temp_config(tmp_dir)
                payload = json.loads(Path(config_path).read_text(encoding="utf-8"))
        finally:
            if original_key is None:
                os.environ.pop("DASHSCOPE_API_KEY", None)
            else:
                os.environ["DASHSCOPE_API_KEY"] = original_key

        provider_options = payload["provider"][OPENCODE_PROVIDER_ID]["options"]
        self.assertEqual(provider_options["apiKey"], "custom-dashscope-key")


if __name__ == "__main__":
    unittest.main()
