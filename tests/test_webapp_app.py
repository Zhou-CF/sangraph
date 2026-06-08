import json
import logging
import sys
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipFile

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from sangraph_logging import get_logger, setup_logging
from webapp.app import create_app
from webapp.service import TaskError, WebTaskService


class WebappAppTests(unittest.TestCase):
    def tearDown(self):
        setup_logging(force=True, console=False, file_logging=False)

    def test_log_bundle_endpoint_returns_zip_for_finished_task(self):
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            setup_logging(force=True, console=False, file_logging=True, log_dir=tmp_path / "logs")
            service = WebTaskService(artifact_root=tmp_path / "artifacts")
            task_id = service._create_task("analysis", {"patch_path": "/tmp/fix.patch"})
            task_dir = service._task_dir(task_id)
            report_path = task_dir / "analysis_report.json"
            report_path.write_text('{"ok": true}', encoding="utf-8")

            get_logger("tests.webapp.app").info("download endpoint task_id=%s", task_id)
            for handler in logging.getLogger().handlers:
                handler.flush()

            service._finalize_task(
                task_id,
                "succeeded",
                {
                    "task_type": "analysis",
                    "status": "succeeded",
                    "summary": {"is_vuln": False},
                    "artifacts": {"analysis_report_path": str(report_path.resolve())},
                    "analysis_report_path": str(report_path.resolve()),
                },
            )

            client = TestClient(create_app(service))
            response = client.get(f"/api/tasks/{task_id}/log-bundle")

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["content-type"], "application/zip")
            self.assertIn(f'sangraph-task-{task_id}.zip', response.headers["content-disposition"])

            with ZipFile(BytesIO(response.content)) as archive:
                self.assertIn(f"sangraph-task-{task_id}/manifest.json", archive.namelist())
                task_log = archive.read(f"sangraph-task-{task_id}/logs/task.log").decode("utf-8")
                self.assertIn(task_id, task_log)

    def test_log_bundle_endpoint_returns_409_for_unfinished_task(self):
        with TemporaryDirectory() as tmp_dir:
            service = WebTaskService(artifact_root=Path(tmp_dir) / "artifacts")
            task_id = service._create_task("analysis", {"patch_path": "/tmp/fix.patch"})

            client = TestClient(create_app(service))
            response = client.get(f"/api/tasks/{task_id}/log-bundle")

            self.assertEqual(response.status_code, 409)
            payload = response.json()
            self.assertIn(task_id, payload["detail"])

    def test_log_bundle_endpoint_returns_404_for_unknown_task(self):
        with TemporaryDirectory() as tmp_dir:
            client = TestClient(create_app(WebTaskService(artifact_root=Path(tmp_dir) / "artifacts")))
            response = client.get("/api/tasks/missing/log-bundle")

            self.assertEqual(response.status_code, 404)
            payload = response.json()
            self.assertEqual(payload["detail"], "Unknown task: missing")

    def test_log_bundle_endpoint_supports_failed_tasks_without_result(self):
        with TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            setup_logging(force=True, console=False, file_logging=True, log_dir=tmp_path / "logs")
            service = WebTaskService(artifact_root=tmp_path / "artifacts")
            task_id = service._create_task("validation", {"report_path": "/tmp/report.json"})
            get_logger("tests.webapp.app").error("failed endpoint task_id=%s", task_id)
            for handler in logging.getLogger().handlers:
                handler.flush()
            service._finalize_failure(
                task_id,
                TaskError(code="RuntimeError", message="validation failed"),
            )

            client = TestClient(create_app(service))
            response = client.get(f"/api/tasks/{task_id}/log-bundle")

            self.assertEqual(response.status_code, 200)
            with ZipFile(BytesIO(response.content)) as archive:
                manifest = json.loads(archive.read(f"sangraph-task-{task_id}/manifest.json").decode("utf-8"))
                self.assertEqual(manifest["status"], "failed")


if __name__ == "__main__":
    unittest.main()
