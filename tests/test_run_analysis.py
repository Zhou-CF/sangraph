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

from base_opencode.llm_struct import FinalResultStruct
from scripts import run_analysis


class RunAnalysisTests(unittest.TestCase):
    def test_parse_args_accepts_patch_mode(self):
        args = run_analysis.parse_args(["--patch-path", "/tmp/fix.patch"])
        self.assertEqual(args.patch_path, "/tmp/fix.patch")
        self.assertEqual(args.analysis_profile, "standard")

    def test_parse_args_accepts_sanitizer_code_mode(self):
        args = run_analysis.parse_args(["--sanitizer-code", "value = sanitize(value)"])
        self.assertEqual(args.sanitizer_code, "value = sanitize(value)")

    def test_parse_args_rejects_missing_input_mode(self):
        with self.assertRaises(SystemExit):
            run_analysis.parse_args([])

    def test_parse_args_rejects_multiple_input_modes(self):
        with self.assertRaises(SystemExit):
            run_analysis.parse_args(
                ["--patch-path", "/tmp/fix.patch", "--sanitizer-code", "value = sanitize(value)"]
            )

    def test_load_sanitizer_code_from_file(self):
        with TemporaryDirectory() as tmp_dir:
            code_path = Path(tmp_dir) / "sanitizer.py"
            code_path.write_text("value = sanitize(value)\n", encoding="utf-8")
            args = run_analysis.parse_args(["--sanitizer-code-file", str(code_path)])
            loaded = run_analysis._load_sanitizer_code(args)
        self.assertEqual(loaded, "value = sanitize(value)\n")

    def test_main_prints_summary_for_patch_mode(self):
        original_runner = run_analysis.run_analysis_with_audit

        async def fake_runner(**kwargs):
            return {
                "repo_path": kwargs.get("repo_path") or "",
                "patch_path": kwargs.get("patch_path") or "",
                "audit_dir": "/tmp/analysis-audit",
                "input_mode": "patch",
                "input_source": "patch_extraction",
                "final_verdict_source": "review_result",
                "result": FinalResultStruct(
                    is_vuln=True,
                    reasoning="Blacklist bypass remains possible.",
                    confidence="high",
                    review_reasoning="Review confirmed the gap.",
                    poc_text="payload",
                    final_verdict_source="review_result",
                    analysis_profile=kwargs.get("analysis_profile", "standard"),
                    analysis_backend="opencode",
                ),
            }

        run_analysis.run_analysis_with_audit = fake_runner
        try:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = run_analysis.main(
                    [
                        "--patch-path",
                        "/tmp/fix.patch",
                        "--repo-path",
                        "/tmp/repo",
                        "--analysis-profile",
                        "enhanced_search",
                    ]
                )
        finally:
            run_analysis.run_analysis_with_audit = original_runner

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["input_mode"], "patch")
        self.assertEqual(payload["patch_path"], "/tmp/fix.patch")
        self.assertEqual(payload["audit_dir"], "/tmp/analysis-audit")
        self.assertEqual(payload["result"]["analysis_profile"], "enhanced_search")

    def test_main_prints_summary_for_sanitizer_code_file_mode(self):
        original_runner = run_analysis.run_analysis_with_audit

        async def fake_runner(**kwargs):
            self.assertEqual(kwargs["sanitizer_code"], "value = value.replace('<script>', '')")
            return {
                "repo_path": kwargs.get("repo_path") or "",
                "patch_path": kwargs.get("patch_path") or "",
                "audit_dir": "/tmp/audit",
                "input_mode": "sanitizer_code",
                "input_source": "sanitizer_code",
                "final_verdict_source": "review_result",
                "result": FinalResultStruct(
                    is_vuln=False,
                    reasoning="The provided sanitizer appears contextually safe.",
                    confidence="medium",
                    review_reasoning="Review did not find a direct bypass.",
                    poc_text="",
                    final_verdict_source="review_result",
                    analysis_profile=kwargs.get("analysis_profile", "standard"),
                    analysis_backend="opencode",
                ),
            }

        run_analysis.run_analysis_with_audit = fake_runner
        try:
            with TemporaryDirectory() as tmp_dir:
                code_path = Path(tmp_dir) / "sanitizer.txt"
                code_path.write_text("value = value.replace('<script>', '')", encoding="utf-8")
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    exit_code = run_analysis.main(
                        [
                            "--sanitizer-code-file",
                            str(code_path),
                            "--audit-dir",
                            "/tmp/cli-audit",
                        ]
                    )
        finally:
            run_analysis.run_analysis_with_audit = original_runner

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["input_mode"], "sanitizer_code")
        self.assertEqual(payload["audit_dir"], "/tmp/audit")


if __name__ == "__main__":
    unittest.main()
