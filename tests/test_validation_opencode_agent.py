import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from validation_opencode import agent
from validation_opencode.llm_struct import ValidationResultStruct
from scripts import run_validation_report


class ValidationModuleTests(unittest.IsolatedAsyncioTestCase):
    def test_build_validation_prompt_includes_skill_and_runtime_inputs(self):
        prompt = agent.build_validation_prompt(
            report_path="/tmp/report.json",
            repo_path="/tmp/repo",
            workspace_dir="/tmp/workspace",
            report_text='{"result": {"is_vuln": true}}',
        )

        self.assertIn("Vulnerability Verification", prompt)
        self.assertIn("/tmp/report.json", prompt)
        self.assertIn("/tmp/repo", prompt)
        self.assertIn("/tmp/workspace", prompt)
        self.assertIn("confirmed | not_reproduced | inconclusive", prompt)

    def test_load_report_supports_json_and_text(self):
        with TemporaryDirectory() as tmp_dir:
            json_path = Path(tmp_dir) / "report.json"
            json_path.write_text(json.dumps({"result": {"is_vuln": True}}), encoding="utf-8")
            text_path = Path(tmp_dir) / "report.md"
            text_path.write_text("# finding", encoding="utf-8")

            _, json_format, json_payload = agent._load_report(json_path)
            _, text_format, text_payload = agent._load_report(text_path)

        self.assertEqual(json_format, "json")
        self.assertEqual(json_payload["result"]["is_vuln"], True)
        self.assertEqual(text_format, "text")
        self.assertIsNone(text_payload)

    def test_parse_validation_result_rejects_empty_output(self):
        with TemporaryDirectory() as tmp_dir:
            with self.assertRaisesRegex(Exception, "Structured output is empty"):
                import asyncio

                asyncio.run(agent._parse_validation_result("", audit_dir=Path(tmp_dir)))

    async def test_parse_validation_result_repairs_fenced_json(self):
        with TemporaryDirectory() as tmp_dir:
            result = await agent._parse_validation_result(
                "```json\n"
                "{\n"
                '  "strategy": "native_test",\n'
                '  "verdict": "confirmed",\n'
                '  "reasoning": "ok",\n'
                '  "artifact_paths": {\n'
                '    "audit_notebook": "/tmp/a.md",\n'
                '    "main_artifact": "/tmp/b.py",\n'
                '    "run_script": "/tmp/run.sh"\n'
                "  },\n"
                '  "executed_command": "bash /tmp/run.sh",\n'
                '  "blockers": []\n'
                "}\n"
                "```",
                audit_dir=Path(tmp_dir),
            )
        self.assertEqual(result.value.verdict, "confirmed")
        self.assertIn(result.repair_method, {"direct", "local_repair"})

    async def test_run_validation_with_audit_writes_artifacts(self):
        original_open_code_agent = agent.OpenCodeAgent

        class FakeOpenCodeAgent:
            instances = []

            def __init__(self, project_path: str, model: str = None):
                self.project_path = project_path
                self.model = model
                self.last_stdout = '{"type":"text","part":{"text":"ok"}}'
                self.last_stderr = "stderr preview"
                self.__class__.instances.append(self)

            def chat(self, prompt: str) -> str:
                self.last_prompt = prompt
                return json.dumps(
                    {
                        "strategy": "native_test",
                        "verdict": "confirmed",
                        "reasoning": "The generated test reproduced the claimed sink effect.",
                        "artifact_paths": {
                            "audit_notebook": "/tmp/workspace/audit_notebook.md",
                            "main_artifact": "/tmp/workspace/test_vuln.py",
                            "run_script": "/tmp/workspace/run.sh",
                        },
                        "executed_command": "bash /tmp/workspace/run.sh",
                        "blockers": [],
                    }
                )

        agent.OpenCodeAgent = FakeOpenCodeAgent
        try:
            with TemporaryDirectory() as tmp_dir:
                report_path = Path(tmp_dir) / "report.json"
                report_path.write_text(
                    json.dumps(
                        {
                            "result": {"is_vuln": True},
                            "review_result": {"is_real_vuln": True},
                        }
                    ),
                    encoding="utf-8",
                )
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                audit_dir = Path(tmp_dir) / "validation"

                result = await agent.run_validation_with_audit(
                    report_path=str(report_path),
                    repo_path=str(repo_path),
                    audit_dir=audit_dir,
                )

                self.assertEqual(result["result"].verdict, "confirmed")
                self.assertTrue((audit_dir / "01_report_input.json").exists())
                self.assertTrue((audit_dir / "02_validation_prompt.txt").exists())
                self.assertTrue((audit_dir / "03_opencode_response.txt").exists())
                self.assertTrue((audit_dir / "03_opencode_raw_stdout.txt").exists())
                self.assertTrue((audit_dir / "03_opencode_raw_stderr.txt").exists())
                self.assertTrue((audit_dir / "validation_summary.json").exists())
                self.assertIn("review_result", json.loads((audit_dir / "01_report_input.json").read_text(encoding="utf-8"))["report_summary"])
                self.assertIn(str(repo_path.resolve()), FakeOpenCodeAgent.instances[0].last_prompt)
                summary = json.loads((audit_dir / "validation_summary.json").read_text(encoding="utf-8"))
                self.assertIn("json_repair", summary)
        finally:
            agent.OpenCodeAgent = original_open_code_agent

    async def test_run_validation_with_audit_writes_error_file(self):
        original_open_code_agent = agent.OpenCodeAgent

        class FailingOpenCodeAgent:
            def __init__(self, project_path: str, model: str = None):
                pass

            def chat(self, prompt: str) -> str:
                raise RuntimeError("boom")

        agent.OpenCodeAgent = FailingOpenCodeAgent
        try:
            with TemporaryDirectory() as tmp_dir:
                report_path = Path(tmp_dir) / "report.txt"
                report_path.write_text("finding", encoding="utf-8")
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                audit_dir = Path(tmp_dir) / "validation"

                with self.assertRaises(RuntimeError):
                    await agent.run_validation_with_audit(
                        report_path=str(report_path),
                        repo_path=str(repo_path),
                        audit_dir=audit_dir,
                    )

                self.assertTrue((audit_dir / "error.json").exists())
                summary = json.loads((audit_dir / "validation_summary.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["status"], "failed")
        finally:
            agent.OpenCodeAgent = original_open_code_agent

    def test_cli_requires_repo_path(self):
        with self.assertRaises(SystemExit):
            run_validation_report.parse_args(["--report-path", "/tmp/report.json"])

    def test_cli_prints_summary(self):
        original_runner = run_validation_report.run_validation_with_audit

        async def fake_runner(*, report_path: str, repo_path: str, audit_dir=None):
            return {
                "report_path": report_path,
                "repo_path": repo_path,
                "audit_dir": "/tmp/audit",
                "workspace_dir": "/tmp/audit/workspace",
                "result": ValidationResultStruct(
                    strategy="minimal_harness",
                    verdict="not_reproduced",
                    reasoning="The path executed without the expected sink effect.",
                    artifact_paths={
                        "audit_notebook": "/tmp/audit/workspace/audit_notebook.md",
                        "main_artifact": "/tmp/audit/workspace/reproduce.py",
                        "run_script": "/tmp/audit/workspace/run.sh",
                    },
                    executed_command="bash /tmp/audit/workspace/run.sh",
                    blockers=[],
                ),
            }

        run_validation_report.run_validation_with_audit = fake_runner
        try:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = run_validation_report.main(
                    ["--report-path", "/tmp/report.json", "--repo-path", "/tmp/repo"]
                )
        finally:
            run_validation_report.run_validation_with_audit = original_runner

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["result"]["verdict"], "not_reproduced")
