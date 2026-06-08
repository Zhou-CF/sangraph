import logging
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from sangraph_logging import get_log_file_path, get_logger, setup_logging
from webapp.service import WebTaskService


class LoggingConfigTests(unittest.TestCase):
    def tearDown(self):
        setup_logging(force=True, console=False, file_logging=False)

    def test_setup_logging_writes_rotating_file(self):
        with TemporaryDirectory() as tmp_dir:
            log_dir = Path(tmp_dir)
            setup_logging(force=True, console=False, file_logging=True, log_dir=log_dir)
            logger = get_logger("tests.logging")
            logger.info("hello logging")
            for handler in logging.getLogger().handlers:
                handler.flush()

            log_path = get_log_file_path(log_dir)
            self.assertTrue(log_path.exists())
            self.assertIn("hello logging", log_path.read_text(encoding="utf-8"))

    def test_setup_logging_is_idempotent_for_same_settings(self):
        with TemporaryDirectory() as tmp_dir:
            setup_logging(force=True, console=False, file_logging=True, log_dir=tmp_dir)
            first_handlers = list(logging.getLogger().handlers)
            setup_logging(console=False, file_logging=True, log_dir=tmp_dir)
            second_handlers = list(logging.getLogger().handlers)
            self.assertEqual(len(first_handlers), 1)
            self.assertEqual(len(second_handlers), 1)
            self.assertIs(first_handlers[0], second_handlers[0])

    def test_env_log_level_can_switch_to_debug(self):
        with patch.dict(os.environ, {"SANGRAPH_LOG_LEVEL": "DEBUG"}, clear=False):
            setup_logging(force=True, console=False, file_logging=False)
            self.assertEqual(logging.getLogger().level, logging.DEBUG)

    def test_web_task_service_emits_task_lifecycle_logs(self):
        with TemporaryDirectory() as tmp_dir:
            log_dir = Path(tmp_dir) / "logs"
            setup_logging(force=True, console=False, file_logging=True, log_dir=log_dir)
            service = WebTaskService(artifact_root=Path(tmp_dir) / "artifacts")
            task_id = service._create_task("analysis", {"patch_path": "/tmp/fix.patch"})
            service._set_stage(task_id, "analysis")
            service._finalize_task(task_id, "succeeded", {"ok": True})
            for handler in logging.getLogger().handlers:
                handler.flush()

            contents = get_log_file_path(log_dir).read_text(encoding="utf-8")
            self.assertIn("Created task", contents)
            self.assertIn(task_id, contents)
            self.assertIn("Task stage updated", contents)
            self.assertIn("Task finalized", contents)


if __name__ == "__main__":
    unittest.main()
