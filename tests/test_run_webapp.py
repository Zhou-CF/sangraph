import unittest
from unittest.mock import patch

from scripts import run_webapp


class RunWebappTests(unittest.TestCase):
    def test_default_port_is_8010(self):
        args = run_webapp.parse_args([])

        self.assertEqual(args.port, 8010)

    def test_reload_passes_import_string_to_uvicorn(self):
        with (
            patch.object(run_webapp, "setup_logging"),
            patch.object(run_webapp.uvicorn, "run") as uvicorn_run,
        ):
            result = run_webapp.main(["--host", "127.0.0.1", "--port", "8123", "--reload"])

        self.assertEqual(result, 0)
        uvicorn_run.assert_called_once_with(
            "webapp.app:app",
            host="127.0.0.1",
            port=8123,
            reload=True,
            reload_dirs=[str(run_webapp.SRC_DIR)],
            log_config=None,
        )


if __name__ == "__main__":
    unittest.main()
