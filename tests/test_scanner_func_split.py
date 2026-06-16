import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from scanner.func_split import FunctionSplitter
from scanner.parsers import filename_to_lang
from scanner.scan import _load_function_splitter
import scanner.scan as scan_module


class ScannerFunctionSplitterTests(unittest.TestCase):
    def test_filename_to_lang_maps_supported_extensions(self):
        self.assertEqual(filename_to_lang("example.py"), "python")
        self.assertEqual(filename_to_lang("example.php"), "php")
        self.assertEqual(filename_to_lang("example.tsx"), "typescript")

    def test_load_function_splitter_returns_local_class(self):
        splitter_cls = _load_function_splitter()
        self.assertEqual(splitter_cls.__name__, "FunctionSplitter")
        self.assertEqual(splitter_cls.__module__, "scanner.func_split")

    def test_python_split_enriches_regex_and_path_constants(self):
        sample = """import re
from pathlib import Path

STATIC_DIR = \"/app/static\"
SAFE_HOST_RE = re.compile(r\"^[A-Za-z0-9.-]{1,253}$\")

def is_valid_ping_host(host):
    return bool(SAFE_HOST_RE.fullmatch(host))

def get_backup_file_path(name):
    backup_dir = Path(STATIC_DIR, \"backup\").resolve()
    return str((backup_dir / name).resolve())
"""
        with TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.py"
            path.write_text(sample, encoding="utf-8")
            items = FunctionSplitter(path).split()

        ping_item = next(item for item in items if "is_valid_ping_host" in item["code"])
        self.assertTrue(ping_item["context_enrichment_applied"])
        self.assertIn("SAFE_HOST_RE", ping_item["enriched_context_symbols"])
        self.assertIn("SAFE_HOST_RE = re.compile", ping_item["code"])

        backup_item = next(item for item in items if "get_backup_file_path" in item["code"])
        self.assertTrue(backup_item["context_enrichment_applied"])
        self.assertIn("STATIC_DIR", backup_item["enriched_context_symbols"])
        self.assertIn('STATIC_DIR = "/app/static"', backup_item["code"])

    def test_javascript_split_enriches_regex_definition(self):
        sample = """const SAFE_HOST_RE = /^[A-Za-z0-9.-]{1,253}$/;

function isValidPingHost(host) {
  return SAFE_HOST_RE.test(host);
}
"""
        with TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.js"
            path.write_text(sample, encoding="utf-8")
            items = FunctionSplitter(path).split()

        item = next(item for item in items if "isValidPingHost" in item["code"])
        self.assertTrue(item["context_enrichment_applied"])
        self.assertIn("SAFE_HOST_RE", item["enriched_context_symbols"])
        self.assertIn("const SAFE_HOST_RE", item["code"])

    def test_javascript_object_property_function_is_split(self):
        sample = """var obj = {
  foo: function(x) {
    return x;
  }
};
"""
        with TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.js"
            path.write_text(sample, encoding="utf-8")
            items = FunctionSplitter(path).split()

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["type"], "method")
        self.assertIn("foo: function", items[0]["code"])

    def test_javascript_object_property_arrow_function_is_split(self):
        sample = """var obj = {
  foo: () => 1
};
"""
        with TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.js"
            path.write_text(sample, encoding="utf-8")
            items = FunctionSplitter(path).split()

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["type"], "method")
        self.assertIn("foo: () => 1", items[0]["code"])

    def test_javascript_assignment_function_is_split(self):
        sample = """exports.run = function() {
  return true;
};
"""
        with TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.js"
            path.write_text(sample, encoding="utf-8")
            items = FunctionSplitter(path).split()

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["type"], "function")
        self.assertIn("exports.run = function()", items[0]["code"])

    def test_javascript_callback_function_expression_is_not_split(self):
        sample = """setTimeout(function() {
  work();
}, 100);
"""
        with TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.js"
            path.write_text(sample, encoding="utf-8")
            items = FunctionSplitter(path).split()

        self.assertEqual(items, [])

    def test_javascript_amd_wrapper_function_is_not_split(self):
        sample = """define([], function() {
  return {};
});
"""
        with TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.js"
            path.write_text(sample, encoding="utf-8")
            items = FunctionSplitter(path).split()

        self.assertEqual(items, [])

    def test_javascript_object_property_function_enriches_regex_definition(self):
        sample = """const SAFE_HOST_RE = /^[A-Za-z0-9.-]{1,253}$/;

var validator = {
  isValidPingHost: function(host) {
    return SAFE_HOST_RE.test(host);
  }
};
"""
        with TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "sample.js"
            path.write_text(sample, encoding="utf-8")
            items = FunctionSplitter(path).split()

        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["context_enrichment_applied"])
        self.assertIn("SAFE_HOST_RE", items[0]["enriched_context_symbols"])
        self.assertIn("const SAFE_HOST_RE", items[0]["code"])

    def test_java_method_enriches_class_field_pattern(self):
        sample = """class Demo {
    static final Pattern SAFE_HOST_RE = Pattern.compile("^[A-Za-z0-9.-]{1,253}$");

    boolean isValid(String host) {
        return SAFE_HOST_RE.matcher(host).matches();
    }
}
"""
        with TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "Demo.java"
            path.write_text(sample, encoding="utf-8")
            items = FunctionSplitter(path).split()

        item = next(item for item in items if "boolean isValid" in item["code"])
        self.assertTrue(item["context_enrichment_applied"])
        self.assertIn("SAFE_HOST_RE", item["enriched_context_symbols"])
        self.assertIn("static final Pattern SAFE_HOST_RE", item["code"])

    def test_process_single_file_records_rejected_snippet(self):
        original_loader = scan_module._load_function_splitter
        original_llm = scan_module.call_llm_with_retry
        original_generated = scan_module.is_generated_or_minified

        class FakeSplitter:
            def __init__(self, file_path):
                self.file_path = file_path

            def split(self):
                return [
                    {
                        "type": "function",
                        "start_line": 1,
                        "end_line": 2,
                        "code": "def get_backup_file_path(name):\n    return name",
                    }
                ]

        class DummyResponse:
            def __init__(self, content):
                self.content = content

        scan_module._load_function_splitter = lambda: FakeSplitter
        scan_module.call_llm_with_retry = lambda code: (DummyResponse("IsSanitizer: False"), None)
        scan_module.is_generated_or_minified = lambda file_path: False
        try:
            results, debug_records = scan_module.process_single_file("/tmp/sample.py", scan_module._ScanRunDeduper())
        finally:
            scan_module._load_function_splitter = original_loader
            scan_module.call_llm_with_retry = original_llm
            scan_module.is_generated_or_minified = original_generated

        self.assertEqual(results, [])
        self.assertEqual(len(debug_records), 1)
        self.assertEqual(debug_records[0]["status"], "candidate_rejected")
        self.assertIn("IsSanitizer: False", debug_records[0]["llm_response"])
        self.assertFalse(debug_records[0]["context_enrichment_applied"])

    def test_main_writes_debug_jsonl_for_scan_decisions(self):
        original_process_single_file = scan_module.process_single_file

        def fake_process_single_file(file_path, deduper):
            return (
                [],
                [
                    {
                        "file_path": file_path,
                        "status": "candidate_rejected",
                        "message": "llm_negative_match",
                        "code": "def sample():\n    return False",
                        "context_enrichment_applied": True,
                        "enriched_context_symbols": ["SAFE_HOST_RE"],
                        "enriched_definition_count": 1,
                        "enriched_language_tier": "tier1",
                    }
                ],
            )

        scan_module.process_single_file = fake_process_single_file
        try:
            with TemporaryDirectory() as tmp_dir:
                repo_dir = Path(tmp_dir) / "repo"
                repo_dir.mkdir()
                (repo_dir / "sample.py").write_text("def sample():\n    return False\n", encoding="utf-8")
                save_path = Path(tmp_dir) / "scan_candidates.json"
                results = scan_module.main(str(repo_dir), str(save_path))
                self.assertEqual(results, [])
                debug_path = scan_module.derive_debug_save_path(save_path)
                self.assertTrue(debug_path.exists())
                records = [json.loads(line) for line in debug_path.read_text(encoding="utf-8").splitlines() if line]
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["status"], "candidate_rejected")
                self.assertEqual(records[0]["enriched_context_symbols"], ["SAFE_HOST_RE"])
        finally:
            scan_module.process_single_file = original_process_single_file

    def test_main_resets_duplicate_tracking_between_runs(self):
        original_loader = scan_module._load_function_splitter
        original_llm = scan_module.call_llm_with_retry
        original_generated = scan_module.is_generated_or_minified

        class FakeSplitter:
            def __init__(self, file_path):
                self.file_path = file_path

            def split(self):
                return [
                    {
                        "type": "function",
                        "start_line": 1,
                        "end_line": 4,
                        "code": "def is_safe_url(url):\n    return url.startswith('https://')",
                    }
                ]

        class DummyResponse:
            def __init__(self, content):
                self.content = content

        scan_module._load_function_splitter = lambda: FakeSplitter
        scan_module.call_llm_with_retry = lambda code: (DummyResponse("IsSanitizer: True"), None)
        scan_module.is_generated_or_minified = lambda file_path: False
        try:
            with TemporaryDirectory() as tmp_dir:
                repo_dir = Path(tmp_dir) / "repo"
                repo_dir.mkdir()
                (repo_dir / "sample.py").write_text("def sample():\n    return True\n", encoding="utf-8")

                first_save_path = Path(tmp_dir) / "scan_candidates_first.json"
                first_results = scan_module.main(str(repo_dir), str(first_save_path))
                first_debug_path = scan_module.derive_debug_save_path(first_save_path)
                first_records = [json.loads(line) for line in first_debug_path.read_text(encoding="utf-8").splitlines() if line]

                second_save_path = Path(tmp_dir) / "scan_candidates_second.json"
                second_results = scan_module.main(str(repo_dir), str(second_save_path))
                second_debug_path = scan_module.derive_debug_save_path(second_save_path)
                second_records = [json.loads(line) for line in second_debug_path.read_text(encoding="utf-8").splitlines() if line]

                self.assertEqual(len(first_results), 1)
                self.assertEqual(len(second_results), 1)
                self.assertEqual(first_records[0]["status"], "candidate_selected")
                self.assertEqual(second_records[0]["status"], "candidate_selected")
        finally:
            scan_module._load_function_splitter = original_loader
            scan_module.call_llm_with_retry = original_llm
            scan_module.is_generated_or_minified = original_generated

    def test_main_keeps_duplicate_tracking_within_single_run(self):
        original_loader = scan_module._load_function_splitter
        original_llm = scan_module.call_llm_with_retry
        original_generated = scan_module.is_generated_or_minified

        class FakeSplitter:
            def __init__(self, file_path):
                self.file_path = file_path

            def split(self):
                return [
                    {
                        "type": "function",
                        "start_line": 1,
                        "end_line": 2,
                        "code": "def sanitize(value):\n    return value.strip()",
                    }
                ]

        class DummyResponse:
            def __init__(self, content):
                self.content = content

        scan_module._load_function_splitter = lambda: FakeSplitter
        scan_module.call_llm_with_retry = lambda code: (DummyResponse("IsSanitizer: True"), None)
        scan_module.is_generated_or_minified = lambda file_path: False
        try:
            with TemporaryDirectory() as tmp_dir:
                repo_dir = Path(tmp_dir) / "repo"
                repo_dir.mkdir()
                (repo_dir / "a.py").write_text("def sample_a():\n    return True\n", encoding="utf-8")
                (repo_dir / "b.py").write_text("def sample_b():\n    return True\n", encoding="utf-8")
                save_path = Path(tmp_dir) / "scan_candidates.json"

                results = scan_module.main(str(repo_dir), str(save_path))
                debug_path = scan_module.derive_debug_save_path(save_path)
                records = [json.loads(line) for line in debug_path.read_text(encoding="utf-8").splitlines() if line]
                statuses = sorted(record["status"] for record in records)

                self.assertEqual(len(results), 1)
                self.assertEqual(statuses, ["candidate_selected", "snippet_skipped"])
                self.assertEqual(sum(record["message"] == "duplicate_code_hash" for record in records), 1)
        finally:
            scan_module._load_function_splitter = original_loader
            scan_module.call_llm_with_retry = original_llm
            scan_module.is_generated_or_minified = original_generated


if __name__ == "__main__":
    unittest.main()
