import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from json_recovery import JsonRecoveryError, extract_json_candidates, parse_or_repair_json


class SimplePayload(BaseModel):
    ok: bool
    reason: str


class JsonRecoveryTests(unittest.IsolatedAsyncioTestCase):
    def test_extract_json_candidates_prefers_structured_blocks(self):
        candidates = extract_json_candidates(
            "prefix\n```json\n{\"ok\": true, \"reason\": \"x\"}\n```\nsuffix"
        )
        self.assertIn('{"ok": true, "reason": "x"}', candidates)

    async def test_parse_or_repair_json_handles_fenced_json(self):
        result = await parse_or_repair_json(
            "```json\n{\"ok\": true, \"reason\": \"works\"}\n```",
            schema_model=SimplePayload,
            stage_name="simple",
        )

        self.assertTrue(result.value.ok)
        self.assertEqual(result.value.reason, "works")

    async def test_parse_or_repair_json_uses_json_repair(self):
        result = await parse_or_repair_json(
            "{'ok': true, 'reason': 'fixed',}",
            schema_model=SimplePayload,
            stage_name="simple",
        )

        self.assertTrue(result.value.ok)
        self.assertEqual(result.value.reason, "fixed")

    async def test_parse_or_repair_json_uses_llm_retry(self):
        async def fake_repair_llm(prompt: str) -> str:
            self.assertIn("Original Output", prompt)
            return '{"ok": false, "reason": "repaired by llm"}'

        with TemporaryDirectory() as tmp_dir:
            result = await parse_or_repair_json(
                "not json at all",
                schema_model=SimplePayload,
                stage_name="simple",
                audit_dir=tmp_dir,
                repair_llm=fake_repair_llm,
            )

            self.assertFalse(result.value.ok)
            self.assertEqual(result.repair_method, "llm_repair")
            self.assertTrue((Path(tmp_dir) / "simple_json_repair_retry_response.txt").exists())

    async def test_parse_or_repair_json_raises_error_when_unrecoverable(self):
        async def fake_repair_llm(prompt: str) -> str:
            return "still not json"

        with TemporaryDirectory() as tmp_dir:
            with self.assertRaises(JsonRecoveryError) as ctx:
                await parse_or_repair_json(
                    "broken",
                    schema_model=SimplePayload,
                    stage_name="simple",
                    audit_dir=tmp_dir,
                    repair_llm=fake_repair_llm,
                )

            self.assertEqual(ctx.exception.stage_name, "simple")
            self.assertTrue((Path(tmp_dir) / "simple_json_parse_error.json").exists())


if __name__ == "__main__":
    unittest.main()
