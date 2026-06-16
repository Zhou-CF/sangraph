import json
import logging
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile

from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from base_opencode.llm_struct import FinalResultStruct
from sangraph_logging import get_logger, setup_logging
from validation_opencode.llm_struct import ValidationResultStruct
from webapp.models import AnalysisTaskRequest, E2ETaskRequest
from webapp.service import TaskError, TaskResultNotReadyError, WebTaskService
import webapp.service as service_module


class WebTaskServiceTests(unittest.TestCase):
    def tearDown(self):
        setup_logging(force=True, console=False, file_logging=False)

    def test_analysis_request_requires_exactly_one_input_mode(self):
        with self.assertRaises(ValidationError):
            AnalysisTaskRequest()
        with self.assertRaises(ValidationError):
            AnalysisTaskRequest(patch_path="/tmp/fix.patch", sanitizer_code="echo unsafe")
        request = AnalysisTaskRequest(patch_path="/tmp/fix.patch", analysis_profile="enhanced_search")
        self.assertEqual(request.analysis_profile, "enhanced_search")

    def test_analysis_without_repo_path_skips_validation(self):
        original_analysis = service_module.run_analysis_with_audit
        original_validation = service_module.run_validation_with_audit

        async def fake_analysis_with_audit(**kwargs):
            return {
                "input_mode": "patch",
                "result": FinalResultStruct(
                    is_vuln=False,
                    reasoning="Looks like an allowlist.",
                    confidence="medium",
                    review_reasoning="Review agrees.",
                    poc_text="",
                    final_verdict_source="review_result",
                    analysis_profile="standard",
                    analysis_backend="opencode",
                ),
            }

        async def should_not_run_validation(**kwargs):
            raise AssertionError("validation should not run when repo_path is missing")

        service_module.run_analysis_with_audit = fake_analysis_with_audit
        service_module.run_validation_with_audit = should_not_run_validation
        try:
            with TemporaryDirectory() as tmp_dir:
                service = WebTaskService(artifact_root=tmp_dir)
                task_id = service._create_task("analysis", {"patch_path": "/tmp/fix.patch"})
                outcome = service._run_analysis_task(
                    task_id,
                    AnalysisTaskRequest(patch_path="/tmp/fix.patch"),
                )
                self.assertEqual(outcome.status, "succeeded")
                result = outcome.result
                self.assertTrue(result["validation_skipped"])
                self.assertFalse(result["validation_attempted"])
                self.assertEqual(result["skip_reason"], "repo_path_not_provided")
                self.assertEqual(result["summary"]["analysis_profile"], "standard")
                self.assertEqual(result["summary"]["analysis_backend"], "opencode")
                self.assertTrue(Path(result["analysis_report_path"]).exists())
        finally:
            service_module.run_analysis_with_audit = original_analysis
            service_module.run_validation_with_audit = original_validation

    def test_analysis_with_repo_path_runs_validation(self):
        original_analysis = service_module.run_analysis_with_audit
        original_validation = service_module.run_validation_with_audit
        captured = {}

        async def fake_analysis_with_audit(**kwargs):
            captured["analysis_profile"] = kwargs.get("analysis_profile")
            return {
                "input_mode": "patch",
                "repo_path": kwargs.get("repo_path"),
                "result": FinalResultStruct(
                    is_vuln=True,
                    reasoning="Blacklist can be bypassed.",
                    confidence="high",
                    review_reasoning="Review found a gap.",
                    poc_text="payload",
                    final_verdict_source="review_result",
                    analysis_profile=kwargs.get("analysis_profile", "standard"),
                    analysis_backend="opencode",
                ),
            }

        async def fake_validation_with_audit(**kwargs):
            captured.update(kwargs)
            report_payload = json.loads(Path(kwargs["report_path"]).read_text(encoding="utf-8"))
            assert report_payload["result"]["is_vuln"] is True
            return {
                "result": ValidationResultStruct(
                    strategy="native_test",
                    verdict="confirmed",
                    reasoning="Sink reached with attacker controlled input.",
                    artifact_paths={
                        "audit_notebook": "/tmp/audit.md",
                        "main_artifact": "/tmp/repro.py",
                        "run_script": "/tmp/run.sh",
                    },
                    executed_command="bash /tmp/run.sh",
                    blockers=[],
                )
            }

        service_module.run_analysis_with_audit = fake_analysis_with_audit
        service_module.run_validation_with_audit = fake_validation_with_audit
        try:
            with TemporaryDirectory() as tmp_dir:
                service = WebTaskService(artifact_root=tmp_dir)
                task_id = service._create_task(
                    "analysis",
                    {"patch_path": "/tmp/fix.patch", "repo_path": "/tmp/repo"},
                )
                outcome = service._run_analysis_task(
                    task_id,
                    AnalysisTaskRequest(
                        patch_path="/tmp/fix.patch",
                        repo_path="/tmp/repo",
                        analysis_profile="enhanced_search",
                    ),
                )
                result = outcome.result
                self.assertTrue(result["validation_attempted"])
                self.assertFalse(result["validation_skipped"])
                self.assertEqual(result["validation_result"]["verdict"], "confirmed")
                self.assertEqual(captured["repo_path"], "/tmp/repo")
                self.assertEqual(captured["analysis_profile"], "enhanced_search")
                self.assertEqual(captured["report_path"], result["analysis_report_path"])
                self.assertEqual(result["summary"]["analysis_profile"], "enhanced_search")
                self.assertTrue(Path(captured["report_path"]).exists())
        finally:
            service_module.run_analysis_with_audit = original_analysis
            service_module.run_validation_with_audit = original_validation

    def test_analysis_with_safe_result_skips_validation_even_with_repo_path(self):
        original_analysis = service_module.run_analysis_with_audit
        original_validation = service_module.run_validation_with_audit

        async def fake_analysis_with_audit(**kwargs):
            return {
                "input_mode": "patch",
                "result": FinalResultStruct(
                    is_vuln=False,
                    reasoning="This sanitizer looks safe.",
                    confidence="high",
                    review_reasoning="Review agrees.",
                    poc_text="",
                    final_verdict_source="review_result",
                    analysis_profile="standard",
                    analysis_backend="llm_fallback",
                ),
            }

        async def should_not_run_validation(**kwargs):
            raise AssertionError("validation should not run when analysis result is negative")

        service_module.run_analysis_with_audit = fake_analysis_with_audit
        service_module.run_validation_with_audit = should_not_run_validation
        try:
            with TemporaryDirectory() as tmp_dir:
                service = WebTaskService(artifact_root=tmp_dir)
                task_id = service._create_task(
                    "analysis",
                    {"patch_path": "/tmp/fix.patch", "repo_path": "/tmp/repo"},
                )
                outcome = service._run_analysis_task(
                    task_id,
                    AnalysisTaskRequest(patch_path="/tmp/fix.patch", repo_path="/tmp/repo"),
                )
                self.assertEqual(outcome.status, "succeeded")
                result = outcome.result
                self.assertFalse(result["validation_attempted"])
                self.assertTrue(result["validation_skipped"])
                self.assertEqual(result["skip_reason"], "analysis_negative")
                self.assertIsNone(result["validation_result"])
                self.assertEqual(result["summary"]["analysis_backend"], "llm_fallback")
        finally:
            service_module.run_analysis_with_audit = original_analysis
            service_module.run_validation_with_audit = original_validation

    def test_list_tasks_prioritizes_running_and_limits_results(self):
        with TemporaryDirectory() as tmp_dir:
            service = WebTaskService(artifact_root=tmp_dir)
            first_running = service._create_task("analysis", {"patch_path": "/tmp/one.patch"})
            second_running = service._create_task("validation", {"report_path": "/tmp/report.json", "repo_path": "/tmp/repo"})
            first_finished = service._create_task("e2e", {"repo_path": "/tmp/repo-a"})
            second_finished = service._create_task("analysis", {"patch_path": "/tmp/two.patch"})

            service._set_status(first_running, "running")
            service._set_stage(first_running, "analysis")
            service._set_status(second_running, "running")
            service._set_stage(second_running, "validation")
            service._finalize_task(first_finished, "failed", {"task_type": "e2e", "status": "failed"})
            service._finalize_task(second_finished, "succeeded", {"task_type": "analysis", "status": "succeeded"})

            listing = service.list_tasks(limit=3)

            self.assertEqual([task.task_id for task in listing.tasks], [second_running, first_running, second_finished])

    def test_list_tasks_includes_restored_snapshots(self):
        with TemporaryDirectory() as tmp_dir:
            artifact_root = Path(tmp_dir) / "artifacts"
            service = WebTaskService(artifact_root=artifact_root)
            task_id = service._create_task("analysis", {"patch_path": "/tmp/fix.patch"})
            service._finalize_task(task_id, "succeeded", {"task_type": "analysis", "status": "succeeded"})

            restored = WebTaskService(artifact_root=artifact_root)
            listing = restored.list_tasks()

            self.assertEqual(len(listing.tasks), 1)
            self.assertEqual(listing.tasks[0].task_id, task_id)

    def test_e2e_only_validates_candidates_flagged_by_analysis(self):
        original_scan = service_module.run_scan
        original_analysis = service_module.run_analysis_with_audit
        original_validation = service_module.run_validation_with_audit
        validated_reports = []

        def fake_scan(project_path, save_path, debug_save_path=None):
            return [
                {
                    "file_path": "/repo/a.py",
                    "start_line": 10,
                    "end_line": 24,
                    "code_hash": "hash-a",
                    "code": "sanitize_a()",
                    "llm_reasoning": "candidate a",
                },
                {
                    "file_path": "/repo/b.py",
                    "start_line": 30,
                    "end_line": 41,
                    "code_hash": "hash-b",
                    "code": "sanitize_b()",
                    "llm_reasoning": "candidate b",
                },
            ]

        async def fake_analysis_with_audit(**kwargs):
            candidate_code = kwargs.get("candidate_code")
            return {
                "input_mode": "scanner_candidate",
                "candidate_code": candidate_code,
                "result": FinalResultStruct(
                    is_vuln=candidate_code == "sanitize_b()",
                    reasoning=f"analysis for {candidate_code}",
                    confidence="medium",
                    review_reasoning="reviewed",
                    poc_text="",
                    final_verdict_source="review_result",
                    analysis_profile="standard",
                    analysis_backend="opencode",
                ),
            }

        async def fake_validation_with_audit(**kwargs):
            validated_reports.append(kwargs["report_path"])
            return {
                "result": ValidationResultStruct(
                    strategy="minimal_harness",
                    verdict="not_reproduced",
                    reasoning="No sink effect observed.",
                    artifact_paths={
                        "audit_notebook": "/tmp/audit.md",
                        "main_artifact": "/tmp/repro.py",
                        "run_script": "/tmp/run.sh",
                    },
                    executed_command="bash /tmp/run.sh",
                    blockers=[],
                )
            }

        service_module.run_scan = fake_scan
        service_module.run_analysis_with_audit = fake_analysis_with_audit
        service_module.run_validation_with_audit = fake_validation_with_audit
        try:
            with TemporaryDirectory() as tmp_dir:
                service = WebTaskService(artifact_root=tmp_dir)
                task_id = service._create_task("e2e", {"repo_path": "/tmp/repo"})
                outcome = service._run_e2e_task(task_id, E2ETaskRequest(repo_path="/tmp/repo"))
                result = outcome.result
                safe_candidate, vuln_candidate = result["candidate_runs"]
                self.assertEqual(result["scan_candidate_count"], 2)
                self.assertEqual(len(result["candidate_runs"]), 2)
                self.assertEqual(len(validated_reports), 1)
                self.assertTrue(result["scan_debug_path"].endswith(".debug.jsonl"))
                self.assertEqual(result["summary"]["successful_candidates"], 2)
                self.assertEqual(result["summary"]["failed_candidates"], 0)
                self.assertFalse(result["summary"]["partial_failures"])
                self.assertEqual(safe_candidate["status"], "succeeded")
                self.assertFalse(safe_candidate["validation_attempted"])
                self.assertTrue(safe_candidate["validation_skipped"])
                self.assertEqual(safe_candidate["skip_reason"], "analysis_negative")
                self.assertIsNone(safe_candidate["validation_result"])
                self.assertEqual(vuln_candidate["status"], "succeeded")
                self.assertTrue(vuln_candidate["validation_attempted"])
                self.assertFalse(vuln_candidate["validation_skipped"])
                self.assertEqual(vuln_candidate["validation_result"]["verdict"], "not_reproduced")
        finally:
            service_module.run_scan = original_scan
            service_module.run_analysis_with_audit = original_analysis
            service_module.run_validation_with_audit = original_validation

    def test_e2e_partial_failures_still_complete(self):
        original_scan = service_module.run_scan
        original_analysis = service_module.run_analysis_with_audit
        original_validation = service_module.run_validation_with_audit
        validation_calls = []

        def fake_scan(project_path, save_path, debug_save_path=None):
            return [
                {
                    "file_path": "/repo/a.py",
                    "start_line": 10,
                    "end_line": 24,
                    "code_hash": "hash-a",
                    "code": "sanitize_a()",
                    "llm_reasoning": "candidate a",
                },
                {
                    "file_path": "/repo/b.py",
                    "start_line": 30,
                    "end_line": 41,
                    "code_hash": "hash-b",
                    "code": "sanitize_b()",
                    "llm_reasoning": "candidate b",
                },
            ]

        async def fake_analysis_with_audit(**kwargs):
            candidate_code = kwargs.get("candidate_code")
            if candidate_code == "sanitize_b()":
                raise RuntimeError("analysis boom")
            return {
                "input_mode": "scanner_candidate",
                "candidate_code": candidate_code,
                "result": FinalResultStruct(
                    is_vuln=False,
                    reasoning="analysis ok",
                    confidence="medium",
                    review_reasoning="reviewed",
                    poc_text="",
                    final_verdict_source="review_result",
                    analysis_profile="standard",
                    analysis_backend="opencode",
                ),
            }

        async def fake_validation_with_audit(**kwargs):
            validation_calls.append(kwargs["report_path"])
            return {
                "result": ValidationResultStruct(
                    strategy="full_env",
                    verdict="inconclusive",
                    reasoning="Target environment was flaky.",
                    artifact_paths={
                        "audit_notebook": "/tmp/audit.md",
                        "main_artifact": "/tmp/repro.py",
                        "run_script": "/tmp/run.sh",
                    },
                    executed_command="bash /tmp/run.sh",
                    blockers=["flaky env"],
                )
            }

        service_module.run_scan = fake_scan
        service_module.run_analysis_with_audit = fake_analysis_with_audit
        service_module.run_validation_with_audit = fake_validation_with_audit
        try:
            with TemporaryDirectory() as tmp_dir:
                service = WebTaskService(artifact_root=tmp_dir)
                task_id = service._create_task("e2e", {"repo_path": "/tmp/repo"})
                outcome = service._run_e2e_task(task_id, E2ETaskRequest(repo_path="/tmp/repo"))
                self.assertEqual(outcome.status, "succeeded")
                result = outcome.result
                self.assertTrue(result["summary"]["partial_failures"])
                self.assertEqual(result["summary"]["successful_candidates"], 1)
                self.assertEqual(result["summary"]["failed_candidates"], 1)
                self.assertTrue(result["scan_debug_path"].endswith(".debug.jsonl"))
                self.assertEqual(validation_calls, [])
                failed = [item for item in result["candidate_runs"] if item["status"] == "failed"]
                self.assertEqual(failed[0]["error"]["code"], "RuntimeError")
        finally:
            service_module.run_scan = original_scan
            service_module.run_analysis_with_audit = original_analysis
            service_module.run_validation_with_audit = original_validation

    def test_build_task_log_bundle_includes_task_artifacts_and_filtered_logs(self):
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            log_dir = tmp_path / "logs"
            setup_logging(force=True, console=False, file_logging=True, log_dir=log_dir)

            service = WebTaskService(artifact_root=tmp_path / "artifacts")
            task_id = service._create_task("analysis", {"patch_path": "/tmp/fix.patch"})
            other_task_id = service._create_task("analysis", {"patch_path": "/tmp/other.patch"})

            task_dir = service._task_dir(task_id)
            analysis_dir = task_dir / "analysis"
            analysis_dir.mkdir(parents=True, exist_ok=True)
            report_path = task_dir / "analysis_report.json"
            report_path.write_text('{"ok": true}', encoding="utf-8")
            (analysis_dir / "audit_summary.json").write_text('{"step": "analysis"}', encoding="utf-8")

            external_dir = tmp_path / "external"
            external_dir.mkdir(parents=True, exist_ok=True)
            external_file = external_dir / "evidence.txt"
            external_file.write_text("external evidence", encoding="utf-8")

            logger = get_logger("tests.webapp.bundle")
            logger.info("task bundle line task_id=%s", task_id)
            logger.info("task bundle line task_id=%s", other_task_id)
            for handler in logging.getLogger().handlers:
                handler.flush()

            service._finalize_task(
                task_id,
                "succeeded",
                {
                    "task_type": "analysis",
                    "status": "succeeded",
                    "summary": {"is_vuln": True},
                    "artifacts": {
                        "analysis_audit_dir": str(analysis_dir.resolve()),
                        "analysis_report_path": str(report_path.resolve()),
                        "supporting_note_path": str(external_file.resolve()),
                    },
                    "analysis_report_path": str(report_path.resolve()),
                    "analysis_audit_dir": str(analysis_dir.resolve()),
                },
            )

            bundle = service.build_task_log_bundle(task_id)
            try:
                with ZipFile(bundle.archive_path) as archive:
                    archive_names = set(archive.namelist())
                    bundle_root = f"sangraph-task-{task_id}"
                    self.assertIn(f"{bundle_root}/manifest.json", archive_names)
                    self.assertIn(f"{bundle_root}/logs/task.log", archive_names)
                    self.assertIn(f"{bundle_root}/artifacts/task/analysis_report.json", archive_names)
                    self.assertIn(f"{bundle_root}/artifacts/task/analysis/audit_summary.json", archive_names)
                    self.assertTrue(
                        any(name.endswith("/artifacts/external/01-evidence.txt") for name in archive_names),
                        archive_names,
                    )

                    task_log = archive.read(f"{bundle_root}/logs/task.log").decode("utf-8")
                    self.assertIn(task_id, task_log)
                    self.assertNotIn(other_task_id, task_log)

                    manifest = json.loads(archive.read(f"{bundle_root}/manifest.json").decode("utf-8"))
                    included_sources = {item["source_path"] for item in manifest["included_artifacts"]}
                    self.assertIn(str((service.artifact_root / task_id).resolve()), included_sources)
                    self.assertIn(str(external_file.resolve()), included_sources)
                    self.assertEqual(manifest["missing_artifacts"], [])
                    self.assertEqual(manifest["log_match_count"], 3)
            finally:
                cleanup_root = bundle.cleanup_root
                bundle.cleanup()
                self.assertFalse(cleanup_root.exists())

    def test_build_task_log_bundle_allows_failed_tasks_without_result(self):
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            log_dir = tmp_path / "logs"
            setup_logging(force=True, console=False, file_logging=True, log_dir=log_dir)

            service = WebTaskService(artifact_root=tmp_path / "artifacts")
            task_id = service._create_task("validation", {"report_path": "/tmp/report.json"})
            get_logger("tests.webapp.bundle").error("failed bundle task_id=%s", task_id)
            for handler in logging.getLogger().handlers:
                handler.flush()
            service._finalize_failure(
                task_id,
                TaskError(code="RuntimeError", message="validation failed"),
            )

            bundle = service.build_task_log_bundle(task_id)
            try:
                with ZipFile(bundle.archive_path) as archive:
                    bundle_root = f"sangraph-task-{task_id}"
                    manifest = json.loads(archive.read(f"{bundle_root}/manifest.json").decode("utf-8"))
                    task_log = archive.read(f"{bundle_root}/logs/task.log").decode("utf-8")
                    self.assertEqual(manifest["status"], "failed")
                    self.assertEqual(manifest["error"]["code"], "RuntimeError")
                    self.assertIn(task_id, task_log)
            finally:
                bundle.cleanup()

    def test_build_task_log_bundle_rejects_unfinished_task(self):
        with TemporaryDirectory() as tmp_dir:
            service = WebTaskService(artifact_root=Path(tmp_dir) / "artifacts")
            task_id = service._create_task("analysis", {"patch_path": "/tmp/fix.patch"})

            with self.assertRaises(TaskResultNotReadyError):
                service.build_task_log_bundle(task_id)

    def test_restores_finished_task_from_disk_after_service_restart(self):
        with TemporaryDirectory() as tmp_dir:
            artifact_root = Path(tmp_dir) / "artifacts"
            original_service = WebTaskService(artifact_root=artifact_root)
            task_id = original_service._create_task("analysis", {"patch_path": "/tmp/fix.patch"})
            original_service._finalize_task(
                task_id,
                "succeeded",
                {
                    "task_type": "analysis",
                    "status": "succeeded",
                    "summary": {"is_vuln": False},
                    "artifacts": {},
                },
            )

            restored_service = WebTaskService(artifact_root=artifact_root)
            restored = restored_service.get_task_result(task_id)

            self.assertEqual(restored.task_id, task_id)
            self.assertEqual(restored.status, "succeeded")
            self.assertFalse(restored.result["summary"]["is_vuln"])

    def test_restores_inflight_task_as_failed_after_service_restart(self):
        with TemporaryDirectory() as tmp_dir:
            artifact_root = Path(tmp_dir) / "artifacts"
            original_service = WebTaskService(artifact_root=artifact_root)
            task_id = original_service._create_task("validation", {"report_path": "/tmp/report.json", "repo_path": "/tmp/repo"})
            original_service._set_status(task_id, "running")
            original_service._set_stage(task_id, "validation")

            restored_service = WebTaskService(artifact_root=artifact_root)
            restored = restored_service.get_task_result(task_id)

            self.assertEqual(restored.status, "failed")
            self.assertEqual(restored.progress_stage, "completed")
            self.assertIsNotNone(restored.finished_at)
            self.assertEqual(restored.error.code, "server_restarted")
            self.assertIsNone(restored.result)

    def test_get_task_status_falls_back_to_disk_when_memory_is_empty(self):
        with TemporaryDirectory() as tmp_dir:
            artifact_root = Path(tmp_dir) / "artifacts"
            service = WebTaskService(artifact_root=artifact_root)
            task_id = service._create_task("analysis", {"patch_path": "/tmp/fix.patch"})
            service._finalize_task(
                task_id,
                "succeeded",
                {
                    "task_type": "analysis",
                    "status": "succeeded",
                    "summary": {"is_vuln": True},
                    "artifacts": {},
                },
            )

            service._tasks.clear()
            restored = service.get_task_status(task_id)

            self.assertEqual(restored.task_id, task_id)
            self.assertEqual(restored.status, "succeeded")


if __name__ == "__main__":
    unittest.main()
