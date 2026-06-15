import json
import os
import subprocess
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

from base_opencode import agent
from base_opencode.script import OpenCodeAgent
from llm_factory.llm_factory import DEFAULT_DASHSCOPE_CHAT_MODEL
from rag import config as rag_config
from rag import rag_search


class DummyResp:
    def __init__(self, content: str):
        self.content = content


class SequenceLLM:
    def __init__(self, responses):
        self._responses = list(responses)

    async def ainvoke(self, prompt: str):
        if not self._responses:
            raise AssertionError(f"Unexpected prompt: {prompt}")
        return DummyResp(self._responses.pop(0))


class SequenceOpenCodeAgent:
    responses: list[str] = []
    instances: list["SequenceOpenCodeAgent"] = []

    def __init__(self, project_path: str, model: str = None):
        self.project_path = project_path
        self.model = model
        self.__class__.instances.append(self)

    def chat(self, prompt: str) -> str:
        self.last_prompt = prompt
        if not self.__class__.responses:
            raise AssertionError(f"Unexpected OpenCode prompt: {prompt}")
        return self.__class__.responses.pop(0)


class FailingOpenCodeAgent:
    def __init__(self, project_path: str, model: str = None):
        self.project_path = project_path
        self.model = model

    def chat(self, prompt: str) -> str:
        raise make_opencode_error("boom", self.project_path)


def make_opencode_error(message: str, project_path: str) -> RuntimeError:
    error = RuntimeError(message)
    error.opencode_debug = {
        "project_path": project_path,
        "command": ["opencode", "run", "--dir", project_path, "<prompt length=12>"],
        "command_text": f"opencode run --dir {project_path} <prompt length=12>",
        "stdout_preview": '{"type":"tool_use"}',
        "stderr_preview": "debug stderr",
        "event_count": 1,
        "event_types": ["tool_use"],
        "last_events": [{"type": "tool_use", "tool": "task"}],
    }
    return error


class BaseOpenCodeAgentTests(unittest.IsolatedAsyncioTestCase):
    async def test_analyze_sanitizer_logic_uses_sanitizer_code(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "derived from sanitizer code",
                        "details": ["check allowlist"],
                        "actions": ["validate input"],
                        "logic_with_nlp": "Validate input against an allowlist.",
                    }
                )
            ]
        )
        original_default_llm = agent._default_llm
        agent._default_llm = lambda: llm
        try:
            result = await agent.analyze_sanitizer_logic_node({"sanitizer_code": "if input in allowed: pass"})
        finally:
            agent._default_llm = original_default_llm

        self.assertEqual(result["sanitizer_logic"].logic_with_nlp, "Validate input against an allowlist.")
        self.assertIn("Validate input against an allowlist.", result["sanitizer_logic_str"])
        self.assertIn("validate input", result["sanitizer_logic_str"])

    def test_prompt_resolution_and_rag_formatting(self):
        self.assertTrue(agent.PROMPT_DIR.joinpath("full_analysis.txt").exists())
        self.assertTrue(agent.PROMPT_DIR.joinpath("extract_sanitizer_from_candidate_prompt.txt").exists())
        self.assertTrue(agent.PROMPT_DIR.joinpath("opencode_analysis_standard.txt").exists())
        self.assertTrue(agent.PROMPT_DIR.joinpath("opencode_analysis_enhanced_search.txt").exists())
        prompt = agent._prompt_text("full_analysis.txt")
        self.assertIn("目标防御代码", prompt)

        formatted = agent.format_rag_results_for_llm(
            [
                {
                    "distance": 0.1,
                    "raw_distance": 0.1,
                    "rank": 0,
                    "entity": {
                        "CVE_ID": "CVE-2024-0001",
                        "unsafe_sanitizer_logic": "Blacklist replacement misses newlines",
                        "vulnerable_code_snippet": "value = value.replace('<script>', '')",
                        "cwe_id": ["CWE-79"],
                        "bypass_poc": "Use newline-separated payload",
                        "unsafe_sanitizer_info": {"缺陷原因": "Blacklist coverage is incomplete"},
                    },
                }
            ]
        )

        self.assertIn("CVE-2024-0001", formatted)
        self.assertIn("Blacklist replacement misses newlines", formatted)
        self.assertIn("Use newline-separated payload", formatted)

    def test_dashscope_defaults(self):
        original_env = {
            "RAG_EMBED_MODEL": os.environ.get("RAG_EMBED_MODEL"),
            "RAG_RERANK_MODEL": os.environ.get("RAG_RERANK_MODEL"),
        }
        try:
            os.environ.pop("RAG_EMBED_MODEL", None)
            os.environ.pop("RAG_RERANK_MODEL", None)
            self.assertEqual(DEFAULT_DASHSCOPE_CHAT_MODEL, "qwen3.7-plus")
            self.assertEqual(rag_config.default_embedding_model(), "text-embedding-v4")
            self.assertEqual(rag_config.default_rerank_model(), "qwen3-rerank")
        finally:
            for key, value in original_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    async def test_run_analysis_smoke_uses_opencode_backend(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The code validates input before use.",
                        "details": ["check allowlist"],
                        "actions": ["validate input"],
                        "logic_with_nlp": "Validate input against an allowlist before use.",
                    }
                )
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        SequenceOpenCodeAgent.responses = [
            json.dumps({"code": "if user_input in ALLOWLIST:\n    return user_input"}),
            json.dumps(
                {
                    "reasoning": "The allowlist logic differs from the retrieved blacklist-only failures and looks safer.",
                    "is_vuln": False,
                    "confidence": "medium",
                    "evidence_summary": "The sanitizer validates against an allowlist before use.",
                    "external_evidence_used": False,
                    "external_evidence_sources": [],
                    "external_evidence_reason": "standard 模式不会主动检索公开资料。",
                }
            ),
        ]
        SequenceOpenCodeAgent.instances = []

        async def fake_search(**kwargs):
            self.assertTrue(kwargs["logic_text"])
            self.assertTrue(kwargs["code_text"])
            return [
                {
                    "distance": 0.2,
                    "raw_distance": 0.2,
                    "rank": 0,
                    "entity": {
                        "CVE_ID": "CVE-2020-0001",
                        "unsafe_sanitizer_logic": "Blacklist sanitization only",
                        "vulnerable_code_snippet": "x = x.replace('<script>', '')",
                        "cwe_id": ["CWE-79"],
                        "bypass_poc": "Mixed-case payload",
                        "unsafe_sanitizer_info": {"缺陷原因": "Blacklist bypass"},
                    },
                },
                {
                    "distance": 0.4,
                    "raw_distance": 0.4,
                    "rank": 1,
                    "entity": {
                        "CVE_ID": "CVE-2020-0002",
                        "unsafe_sanitizer_logic": "Case-sensitive blacklist replacement",
                        "vulnerable_code_snippet": "value = value.replace('<script>', '')",
                        "cwe_id": ["CWE-79"],
                        "bypass_poc": "Case-smuggling payload",
                        "unsafe_sanitizer_info": {"缺陷原因": "Case normalization missing"},
                    },
                },
            ]

        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                patch_path = Path(tmp_dir) / "fix.patch"
                patch_path.write_text("diff --git a/a.py b/a.py\n+sanitize(user_input)\n", encoding="utf-8")
                result = await agent.run_analysis(str(repo_path), str(patch_path))
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

        self.assertTrue(result["sanitizer_code"].startswith("if user_input"))
        self.assertEqual(SequenceOpenCodeAgent.instances[0].model, "alibaba-cn/qwen3.7-plus")
        self.assertTrue(result["sanitizer_logic_str"])
        self.assertEqual(result["rag_relevance"].label, "medium")
        self.assertFalse(result["result"].is_vuln)
        self.assertEqual(result["result"].final_verdict_source, "opencode_analysis")
        self.assertEqual(result["result"].analysis_backend, "opencode")
        self.assertEqual(result["result"].analysis_profile, "standard")

    async def test_run_analysis_with_audit_writes_stage_files(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The code validates input before use.",
                        "details": ["check allowlist"],
                        "actions": ["validate input"],
                        "logic_with_nlp": "Validate input against an allowlist before use.",
                    }
                )
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        SequenceOpenCodeAgent.responses = [
            json.dumps({"code": "if user_input in ALLOWLIST:\n    return user_input"}),
            json.dumps(
                {
                    "reasoning": "The allowlist logic appears safe.",
                    "is_vuln": False,
                    "confidence": "medium",
                    "evidence_summary": "No blacklist-only failure pattern was found in the target sanitizer.",
                    "external_evidence_used": False,
                    "external_evidence_sources": [],
                    "external_evidence_reason": "standard 模式不会主动检索公开资料。",
                }
            ),
        ]
        SequenceOpenCodeAgent.instances = []

        async def fake_search(**kwargs):
            return [
                {
                    "distance": 0.2,
                    "raw_distance": 0.2,
                    "rank": 0,
                    "entity": {
                        "CVE_ID": "CVE-2020-0001",
                        "unsafe_sanitizer_logic": "Blacklist sanitization only",
                        "vulnerable_code_snippet": "x = x.replace('<script>', '')",
                        "cwe_id": ["CWE-79"],
                        "bypass_poc": "Mixed-case payload",
                        "unsafe_sanitizer_info": {"缺陷原因": "Blacklist bypass"},
                    },
                },
                {
                    "distance": 0.35,
                    "raw_distance": 0.35,
                    "rank": 1,
                    "entity": {
                        "CVE_ID": "CVE-2020-0002",
                        "unsafe_sanitizer_logic": "Regex misses alternate separators",
                        "vulnerable_code_snippet": "re.sub('<script>', '', value)",
                        "cwe_id": ["CWE-79"],
                        "bypass_poc": "Separator-smuggling payload",
                        "unsafe_sanitizer_info": {"缺陷原因": "Regex coverage incomplete"},
                    },
                },
            ]

        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                patch_path = Path(tmp_dir) / "fix.patch"
                patch_path.write_text("diff --git a/a.py b/a.py\n+sanitize(user_input)\n", encoding="utf-8")
                audit_dir = Path(tmp_dir) / "audit"
                result = await agent.run_analysis_with_audit(str(repo_path), str(patch_path), audit_dir=audit_dir)

                expected = [
                    "01_sanitizer_extraction.json",
                    "02_sanitizer_logic.json",
                    "03_rag_search.json",
                    "04_opencode_analysis.json",
                    "05_final_result.json",
                    "audit_summary.json",
                ]
                for name in expected:
                    self.assertTrue((audit_dir / name).exists(), name)

                summary = json.loads((audit_dir / "audit_summary.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["status"], "success")
                self.assertEqual(summary["analysis_backend"], "opencode")
                self.assertFalse(summary["deep_analysis_triggered"])
                self.assertEqual(summary["rag_hits_count"], 2)
                self.assertEqual(summary["input_mode"], "patch")
                self.assertFalse(result["result"].is_vuln)
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

    async def test_run_analysis_with_audit_repairs_opencode_json_with_llm_retry(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The code validates input before use.",
                        "details": ["check allowlist"],
                        "actions": ["validate input"],
                        "logic_with_nlp": "Validate input against an allowlist before use.",
                    }
                ),
                json.dumps(
                    {
                        "reasoning": "The allowlist logic appears safe after JSON repair.",
                        "is_vuln": False,
                        "confidence": "medium",
                        "evidence_summary": "Recovered structured output preserves the original verdict.",
                        "external_evidence_used": False,
                        "external_evidence_sources": [],
                        "external_evidence_reason": "standard 模式不会主动检索公开资料。",
                    }
                ),
                json.dumps(
                    {
                        "reasoning": "Review agrees the recovered allowlist result is safe.",
                        "is_real_vuln": False,
                        "confidence": "medium",
                    }
                ),
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        SequenceOpenCodeAgent.responses = [
            json.dumps({"code": "if user_input in ALLOWLIST:\n    return user_input"}),
            "analysis says it looks safe but not in json",
        ]
        SequenceOpenCodeAgent.instances = []

        async def fake_search(**kwargs):
            return []

        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                patch_path = Path(tmp_dir) / "fix.patch"
                patch_path.write_text("diff --git a/a.py b/a.py\n+sanitize(user_input)\n", encoding="utf-8")
                audit_dir = Path(tmp_dir) / "audit"
                result = await agent.run_analysis_with_audit(str(repo_path), str(patch_path), audit_dir=audit_dir)

                summary = json.loads((audit_dir / "audit_summary.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["analysis_backend"], "opencode")
                self.assertTrue(summary["json_repair_events"])
                self.assertEqual(summary["json_repair_events"][0]["stage"], "opencode_analysis")
                self.assertEqual(summary["json_repair_events"][0]["repair_method"], "llm_repair")
                self.assertFalse(result["result"].is_vuln)
                self.assertTrue((audit_dir / "opencode_analysis_json_repair_retry_response.txt").exists())
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

    async def test_run_analysis_with_audit_triggers_deep_context_analysis(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The code validates input before use.",
                        "details": ["check allowlist"],
                        "actions": ["validate input"],
                        "logic_with_nlp": "Validate input against an allowlist before use.",
                    }
                )
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search

        class DeepOpenCodeAgent:
            call_count = 0

            def __init__(self, project_path: str, model: str = None):
                self.project_path = project_path
                self.model = model

            def chat(self, prompt: str) -> str:
                self.__class__.call_count += 1
                if self.__class__.call_count == 1:
                    return json.dumps({"code": "dangerous_filter(user_input)"})
                if self.__class__.call_count == 2:
                    return json.dumps(
                        {
                            "reasoning": "The filter still looks brittle once we compare it with known sanitizer failure patterns.",
                            "is_vuln": True,
                            "confidence": "high",
                            "evidence_summary": "The sanitizer still behaves like a brittle blacklist and warrants repo-aware confirmation.",
                            "external_evidence_used": False,
                            "external_evidence_sources": [],
                            "external_evidence_reason": "standard 模式不会主动检索公开资料。",
                        }
                    )
                return json.dumps(
                    {
                        "vulnerable_path": "POST dayFilter -> __parse_query.php::$dayFilter -> __build_query.php::$query -> rawQuery($query)",
                        "bypass_reasoning": "The value is concatenated into a numeric SQL context where escaping quotes is insufficient.",
                        "poc": "POST /location_history/controllers/global.php\\n\\ndayFilter[]=1) OR 1=1 -- ",
                        "is_vuln": True,
                        "verdict": "confirmed",
                    }
                )

        async def fake_search(**kwargs):
            return []

        agent.OpenCodeAgent = DeepOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                patch_path = Path(tmp_dir) / "fix.patch"
                patch_path.write_text("diff --git a/a.py b/a.py\n+dangerous_filter(user_input)\n", encoding="utf-8")
                audit_dir = Path(tmp_dir) / "audit"
                result = await agent.run_analysis_with_audit(str(repo_path), str(patch_path), audit_dir=audit_dir)

                self.assertTrue((audit_dir / "05_deep_context_analysis.json").exists())
                self.assertTrue((audit_dir / "06_final_result.json").exists())
                summary = json.loads((audit_dir / "audit_summary.json").read_text(encoding="utf-8"))
                self.assertTrue(summary["deep_analysis_triggered"])
                self.assertEqual(summary["final_verdict_source"], "deep_context_analysis")
                self.assertTrue(result["result"].is_vuln)
                self.assertIn("dayFilter[]", result["result"].poc_text)
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

    async def test_run_analysis_with_audit_repairs_fenced_deep_context_json(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The code validates input before use.",
                        "details": ["check allowlist"],
                        "actions": ["validate input"],
                        "logic_with_nlp": "Validate input against an allowlist before use.",
                    }
                )
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        SequenceOpenCodeAgent.responses = [
            json.dumps(
                {
                    "reasoning": "The sanitizer still looks brittle once we compare it with known failure patterns.",
                    "is_vuln": True,
                    "confidence": "high",
                    "evidence_summary": "The sanitizer still behaves like a brittle blacklist and warrants repo-aware confirmation.",
                    "external_evidence_used": False,
                    "external_evidence_sources": [],
                    "external_evidence_reason": "standard 模式不会主动检索公开资料。",
                }
            ),
            "```json\n"
            "{\n"
            '  "vulnerable_path": "POST dayFilter -> rawQuery($query)",\n'
            '  "bypass_reasoning": "The value is concatenated into a numeric SQL context where escaping quotes is insufficient.",\n'
            '  "poc": "POST /location_history/controllers/global.php\\n\\ndayFilter[]=1) OR 1=1 -- ",\n'
            '  "is_vuln": true,\n'
            '  "verdict": "confirmed"\n'
            "}\n"
            "```",
        ]
        SequenceOpenCodeAgent.instances = []

        async def fake_search(**kwargs):
            return []

        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                audit_dir = Path(tmp_dir) / "audit"
                result = await agent.run_analysis_with_audit(
                    repo_path=str(repo_path),
                    sanitizer_code="dangerous_filter(user_input)",
                    audit_dir=audit_dir,
                )

                self.assertTrue((audit_dir / "05_deep_context_analysis.json").exists())
                summary = json.loads((audit_dir / "audit_summary.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["status"], "success")
                self.assertTrue(summary["deep_analysis_triggered"])
                self.assertEqual(summary["final_verdict_source"], "deep_context_analysis")
                self.assertEqual(result["deep_analysis"].verdict, "confirmed")
                self.assertIn("dayFilter[]", result["result"].poc_text)
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

    async def test_run_analysis_with_audit_preserves_fallback_result_when_deep_context_fails(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The sanitizer still looks like a brittle blacklist.",
                        "details": ["replaces a narrow token set"],
                        "actions": ["replace token", "return original data"],
                        "logic_with_nlp": "Replace a narrow token set and then return the original attacker-controlled value.",
                    }
                ),
                json.dumps(
                    {
                        "reasoning": "The fallback analysis finds the blacklist incomplete.",
                        "is_vuln": True,
                        "confidence": "medium",
                    }
                ),
                json.dumps(
                    {
                        "reasoning": "Review confirms the sanitizer is still bypassable.",
                        "is_real_vuln": True,
                        "confidence": "high",
                    }
                ),
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search

        class FallbackThenDeepFailAgent:
            call_count = 0

            def __init__(self, project_path: str, model: str = None):
                self.project_path = project_path
                self.model = model

            def chat(self, prompt: str) -> str:
                self.__class__.call_count += 1
                raise make_opencode_error(
                    f"opencode failure #{self.__class__.call_count}",
                    self.project_path,
                )

        async def fake_search(**kwargs):
            return []

        agent.OpenCodeAgent = FallbackThenDeepFailAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                audit_dir = Path(tmp_dir) / "audit"
                result = await agent.run_analysis_with_audit(
                    repo_path=str(repo_path),
                    sanitizer_code="dangerous_filter(user_input)",
                    audit_dir=audit_dir,
                )

                self.assertTrue((audit_dir / "07_deep_context_analysis.json").exists())
                self.assertTrue((audit_dir / "08_final_result.json").exists())
                summary = json.loads((audit_dir / "audit_summary.json").read_text(encoding="utf-8"))
                deep_stage = json.loads(
                    (audit_dir / "07_deep_context_analysis.json").read_text(encoding="utf-8")
                )

                self.assertEqual(summary["status"], "success")
                self.assertEqual(summary["final_verdict_source"], "review_result")
                self.assertTrue(summary["deep_analysis_attempted"])
                self.assertTrue(summary["deep_analysis_skipped"])
                self.assertEqual(summary["deep_analysis_error"]["node"], "deep_context_analysis")
                self.assertEqual(len(summary["recoverable_errors"]), 2)
                self.assertTrue(result["result"].is_vuln)
                self.assertEqual(result["result"].final_verdict_source_detail, "llm_fallback_review")
                self.assertIn("源码上下文深挖执行失败", result["result"].reasoning)
                self.assertEqual(
                    deep_stage["node_output"]["error"]["opencode_debug"]["project_path"],
                    str(repo_path),
                )
                self.assertTrue(deep_stage["state"]["deep_analysis_skipped"])
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

    async def test_run_analysis_with_audit_preserves_fallback_result_when_deep_context_returns_text(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The sanitizer still looks like a brittle blacklist.",
                        "details": ["replaces a narrow token set"],
                        "actions": ["replace token", "return original data"],
                        "logic_with_nlp": "Replace a narrow token set and then return the original attacker-controlled value.",
                    }
                ),
                json.dumps(
                    {
                        "reasoning": "The fallback analysis finds the blacklist incomplete.",
                        "is_vuln": True,
                        "confidence": "medium",
                    }
                ),
                json.dumps(
                    {
                        "reasoning": "Review confirms the sanitizer is still bypassable.",
                        "is_real_vuln": True,
                        "confidence": "high",
                    }
                ),
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search

        class FallbackThenDeepTextAgent:
            call_count = 0

            def __init__(self, project_path: str, model: str = None):
                self.project_path = project_path
                self.model = model

            def chat(self, prompt: str) -> str:
                self.__class__.call_count += 1
                if self.__class__.call_count == 1:
                    raise make_opencode_error("boom", self.project_path)
                return (
                    "Now let me read the complete source file to understand the full context:\n\n"
                    "Now I have all the context needed. Let me verify the exploit logic with a quick Python test:"
                )

        async def fake_search(**kwargs):
            return []

        agent.OpenCodeAgent = FallbackThenDeepTextAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                audit_dir = Path(tmp_dir) / "audit"
                result = await agent.run_analysis_with_audit(
                    repo_path=str(repo_path),
                    sanitizer_code="dangerous_filter(user_input)",
                    audit_dir=audit_dir,
                )

                self.assertTrue((audit_dir / "07_deep_context_analysis.json").exists())
                summary = json.loads((audit_dir / "audit_summary.json").read_text(encoding="utf-8"))
                deep_stage = json.loads(
                    (audit_dir / "07_deep_context_analysis.json").read_text(encoding="utf-8")
                )

                self.assertEqual(summary["status"], "success")
                self.assertEqual(summary["final_verdict_source"], "review_result")
                self.assertEqual(summary["final_verdict_source_detail"], "llm_fallback_review")
                self.assertTrue(summary["deep_analysis_attempted"])
                self.assertTrue(summary["deep_analysis_skipped"])
                self.assertEqual(summary["deep_analysis_error"]["node"], "deep_context_analysis")
                self.assertEqual(len(summary["recoverable_errors"]), 2)
                self.assertTrue(deep_stage["node_output"]["fallback_triggered"])
                self.assertIn(
                    deep_stage["node_output"]["error"]["type"],
                    {"OutputParserException", "JsonRecoveryError"},
                )
                self.assertIn("源码上下文深挖执行失败", result["result"].reasoning)
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

    async def test_run_analysis_with_audit_falls_back_when_opencode_json_repair_still_fails(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The sanitizer still looks like a brittle blacklist.",
                        "details": ["replaces a narrow token set"],
                        "actions": ["replace token", "return original data"],
                        "logic_with_nlp": "Replace a narrow token set and then return the original attacker-controlled value.",
                    }
                ),
                "still not json",
                json.dumps(
                    {
                        "reasoning": "The fallback analysis finds the blacklist incomplete.",
                        "is_vuln": True,
                        "confidence": "medium",
                    }
                ),
                json.dumps(
                    {
                        "reasoning": "Review confirms the sanitizer is still bypassable.",
                        "is_real_vuln": True,
                        "confidence": "high",
                    }
                ),
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        SequenceOpenCodeAgent.responses = ["not json at all"]

        async def fake_search(**kwargs):
            return []

        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                audit_dir = Path(tmp_dir) / "audit"
                result = await agent.run_analysis_with_audit(
                    repo_path=str(repo_path),
                    sanitizer_code="dangerous_filter(user_input)",
                    audit_dir=audit_dir,
                )

                summary = json.loads((audit_dir / "audit_summary.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["analysis_backend"], "llm_fallback")
                self.assertEqual(summary["recoverable_errors"][0]["node"], "opencode_analysis")
                self.assertTrue((audit_dir / "opencode_analysis_json_parse_error.json").exists())
                self.assertTrue(result["result"].is_vuln)
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

    async def test_run_analysis_with_audit_writes_error_file(self):
        original_open_code_agent = agent.OpenCodeAgent
        agent.OpenCodeAgent = FailingOpenCodeAgent
        try:
            with TemporaryDirectory() as tmp_dir:
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                patch_path = Path(tmp_dir) / "fix.patch"
                patch_path.write_text("diff --git a/a.py b/a.py\n+sanitize(user_input)\n", encoding="utf-8")
                audit_dir = Path(tmp_dir) / "audit"
                with self.assertRaises(RuntimeError):
                    await agent.run_analysis_with_audit(str(repo_path), str(patch_path), audit_dir=audit_dir)

                self.assertTrue((audit_dir / "error.json").exists())
                self.assertTrue((audit_dir / "audit_summary.json").exists())
                error_payload = json.loads((audit_dir / "error.json").read_text(encoding="utf-8"))
                summary = json.loads((audit_dir / "audit_summary.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["status"], "failed")
                self.assertEqual(summary["completed_nodes"], [])
                self.assertEqual(error_payload["opencode_debug"]["project_path"], str(repo_path))
        finally:
            agent.OpenCodeAgent = original_open_code_agent

    async def test_full_analysis_returns_conservative_result_when_no_sanitizer_code(self):
        result = await agent.full_analysis({"sanitizer_code": ""})
        self.assertFalse(result["full_analysis_decision"].is_vuln)
        self.assertEqual(result["full_analysis_decision"].confidence, "low")
        self.assertIn("证据不足", result["full_analysis_decision"].reasoning)

    async def test_run_analysis_with_direct_sanitizer_code_skips_extraction(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The code validates input before use.",
                        "details": ["check allowlist"],
                        "actions": ["validate input"],
                        "logic_with_nlp": "Validate input against an allowlist before use.",
                    }
                )
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        SequenceOpenCodeAgent.responses = [
            json.dumps(
                {
                    "reasoning": "The provided allowlist sanitizer appears safe.",
                    "is_vuln": False,
                    "confidence": "medium",
                    "evidence_summary": "The analysis is based directly on the provided sanitizer snippet.",
                    "external_evidence_used": False,
                    "external_evidence_sources": [],
                    "external_evidence_reason": "standard 模式不会主动检索公开资料。",
                }
            )
        ]
        SequenceOpenCodeAgent.instances = []

        async def fake_search(**kwargs):
            return []

        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                audit_dir = Path(tmp_dir) / "audit"
                result = await agent.run_analysis_with_audit(
                    repo_path=None,
                    patch_path=None,
                    sanitizer_code="if user_input in ALLOWLIST:\n    return user_input",
                    audit_dir=audit_dir,
                )

                stage_one = json.loads((audit_dir / "01_sanitizer_extraction.json").read_text(encoding="utf-8"))
                self.assertTrue(stage_one["node_output"]["skipped"])
                summary = json.loads((audit_dir / "audit_summary.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["input_mode"], "sanitizer_code")
                self.assertEqual(summary["sanitizer_extraction_source"], "provided")
                self.assertTrue(summary["sanitizer_extraction_skipped"])
                self.assertEqual(summary["analysis_backend"], "opencode")
                self.assertEqual(result["sanitizer_code"], "if user_input in ALLOWLIST:\n    return user_input")
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

    async def test_run_analysis_with_direct_sanitizer_code_takes_precedence_over_patch_and_candidate(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "derived from provided sanitizer code",
                        "details": ["check allowlist"],
                        "actions": ["validate input"],
                        "logic_with_nlp": "Validate input against an allowlist before use.",
                    }
                )
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        SequenceOpenCodeAgent.responses = [
            json.dumps(
                {
                    "reasoning": "The direct sanitizer code appears safe.",
                    "is_vuln": False,
                    "confidence": "medium",
                    "evidence_summary": "The allowlist behavior is visible in the provided sanitizer snippet.",
                    "external_evidence_used": False,
                    "external_evidence_sources": [],
                    "external_evidence_reason": "standard 模式不会主动检索公开资料。",
                }
            )
        ]
        SequenceOpenCodeAgent.instances = []

        async def fake_search(**kwargs):
            self.assertIn("ALLOWLIST", kwargs["code_text"])
            return []

        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                repo_path = Path(tmp_dir) / "repo"
                repo_path.mkdir()
                patch_path = Path(tmp_dir) / "fix.patch"
                patch_path.write_text("diff --git a/a.py b/a.py\n+dangerous_filter(user_input)\n", encoding="utf-8")
                result = await agent.run_analysis(
                    str(repo_path),
                    str(patch_path),
                    sanitizer_code="if user_input in ALLOWLIST:\n    return user_input",
                    candidate_code=(
                        "def sanitize(user_input):\n"
                        "    audit_log(user_input)\n"
                        "    return html.escape(user_input)\n"
                    ),
                    candidate_path="src/sanitizer.py",
                    candidate_symbol="sanitize",
                )
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

        self.assertEqual(result["input_mode"], "sanitizer_code")
        self.assertEqual(result["input_source"], "sanitizer_code")
        self.assertEqual(result["sanitizer_code"], "if user_input in ALLOWLIST:\n    return user_input")
        self.assertEqual(result["candidate_symbol"], "sanitize")
        self.assertEqual(result["candidate_path"], "src/sanitizer.py")

    async def test_run_analysis_with_scanner_candidate_extracts_minimal_sanitizer_code(self):
        llm = SequenceLLM(
            [
                json.dumps({"code": "return html.escape(user_input)"}),
                json.dumps(
                    {
                        "reasoning": "The candidate extracts a built-in HTML escaping call.",
                        "details": ["call html.escape on user input"],
                        "actions": ["apply HTML escaping"],
                        "logic_with_nlp": "Escape user-controlled input before rendering it into HTML.",
                    }
                ),
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        SequenceOpenCodeAgent.responses = [
            json.dumps(
                {
                    "reasoning": "The extracted sanitizer is a standard escaping call and appears safe.",
                    "is_vuln": False,
                    "confidence": "medium",
                    "evidence_summary": "The candidate uses a standard HTML escaping function on user input.",
                    "external_evidence_used": False,
                    "external_evidence_sources": [],
                    "external_evidence_reason": "standard 模式不会主动检索公开资料。",
                }
            )
        ]
        SequenceOpenCodeAgent.instances = []

        async def fake_search(**kwargs):
            self.assertEqual(kwargs["code_text"], "return html.escape(user_input)")
            self.assertNotIn("def sanitize", kwargs["code_text"])
            self.assertIn("HTML", kwargs["logic_text"])
            return []

        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            result = await agent.run_analysis(
                repo_path=None,
                patch_path=None,
                sanitizer_code=None,
                candidate_code=(
                    "def sanitize(user_input):\n"
                    "    audit_log(user_input)\n"
                    "    return html.escape(user_input)\n"
                ),
                candidate_path="src/sanitizer.py",
                candidate_start_line=10,
                candidate_end_line=12,
                candidate_symbol="sanitize",
                candidate_language="python",
            )
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

        self.assertEqual(result["input_mode"], "scanner_candidate")
        self.assertEqual(result["input_source"], "scanner_candidate_extraction")
        self.assertEqual(result["sanitizer_extraction_source"], "scanner_candidate")
        self.assertEqual(result["sanitizer_code"], "return html.escape(user_input)")
        self.assertFalse(result["result"].is_vuln)

    async def test_run_analysis_with_scanner_candidate_can_fail_conservatively(self):
        llm = SequenceLLM([json.dumps({"code": ""})])
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm

        async def fake_search(**kwargs):
            raise AssertionError("RAG search should be skipped when extraction returns empty sanitizer_code")

        agent.rag_search.search = fake_search
        SequenceOpenCodeAgent.responses = []
        SequenceOpenCodeAgent.instances = []

        try:
            result = await agent.run_analysis(
                repo_path=None,
                patch_path=None,
                sanitizer_code=None,
                candidate_code="return project_sanitizer(user_input)",
                candidate_symbol="sanitize",
            )
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

        self.assertEqual(result["input_mode"], "scanner_candidate")
        self.assertEqual(result["sanitizer_code"], "")
        self.assertFalse(result["full_analysis_decision"].is_vuln)
        self.assertEqual(result["full_analysis_decision"].confidence, "low")
        self.assertFalse(result["review_result"].is_real_vuln)
        self.assertEqual(result["review_result"].confidence, "low")

    async def test_run_analysis_with_audit_scanner_candidate_records_candidate_metadata(self):
        llm = SequenceLLM(
            [
                json.dumps({"code": "return html.escape(user_input)"}),
                json.dumps(
                    {
                        "reasoning": "The code uses a visible escaping call.",
                        "details": ["call html.escape on user input"],
                        "actions": ["apply HTML escaping"],
                        "logic_with_nlp": "Escape user input before rendering.",
                    }
                ),
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        SequenceOpenCodeAgent.responses = [
            json.dumps(
                {
                    "reasoning": "The extracted escaping logic appears safe.",
                    "is_vuln": False,
                    "confidence": "medium",
                    "evidence_summary": "The candidate performs a direct HTML escaping call.",
                    "external_evidence_used": False,
                    "external_evidence_sources": [],
                    "external_evidence_reason": "standard 模式不会主动检索公开资料。",
                }
            )
        ]
        SequenceOpenCodeAgent.instances = []

        async def fake_search(**kwargs):
            return []

        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                audit_dir = Path(tmp_dir) / "audit"
                result = await agent.run_analysis_with_audit(
                    repo_path=None,
                    patch_path=None,
                    sanitizer_code=None,
                    audit_dir=audit_dir,
                    candidate_code=(
                        "def sanitize(user_input):\n"
                        "    audit_log(user_input)\n"
                        "    return html.escape(user_input)\n"
                    ),
                    candidate_path="src/sanitizer.py",
                    candidate_start_line=10,
                    candidate_end_line=12,
                    candidate_symbol="sanitize",
                    candidate_language="python",
                    candidate_metadata={"scanner_rule": "html-escape", "confidence": "high"},
                )

                stage_one = json.loads((audit_dir / "01_sanitizer_extraction.json").read_text(encoding="utf-8"))
                self.assertEqual(stage_one["node"], "extract_sanitizer_from_candidate")
                self.assertEqual(stage_one["input_state"]["candidate_path"], "src/sanitizer.py")
                summary = json.loads((audit_dir / "audit_summary.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["input_mode"], "scanner_candidate")
                self.assertEqual(summary["candidate_path"], "src/sanitizer.py")
                self.assertEqual(summary["candidate_symbol"], "sanitize")
                self.assertEqual(summary["candidate_start_line"], 10)
                self.assertEqual(summary["candidate_end_line"], 12)
                self.assertEqual(summary["candidate_metadata"]["scanner_rule"], "html-escape")
                self.assertFalse(summary["sanitizer_extraction_skipped"])
                self.assertEqual(result["sanitizer_code"], "return html.escape(user_input)")
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

    async def test_run_analysis_requires_patch_or_sanitizer_code(self):
        with self.assertRaisesRegex(ValueError, "至少提供一个"):
            await agent.run_analysis(repo_path=None, patch_path=None, sanitizer_code=None)

    async def test_run_analysis_rejects_blank_sanitizer_code(self):
        with self.assertRaisesRegex(ValueError, "不能为空白"):
            await agent.run_analysis(repo_path=None, patch_path=None, sanitizer_code="   ")

    async def test_run_analysis_with_audit_skips_deep_analysis_when_repo_path_missing(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The sanitizer logic is brittle.",
                        "details": ["blacklist only"],
                        "actions": ["replace script tag"],
                        "logic_with_nlp": "Replace a small blacklist of script patterns.",
                    }
                )
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        SequenceOpenCodeAgent.responses = [
            json.dumps(
                {
                    "reasoning": "The blacklist-only sanitizer still appears brittle.",
                    "is_vuln": True,
                    "confidence": "high",
                    "evidence_summary": "The sanitizer only replaces a narrow script blacklist and lacks stronger normalization.",
                    "external_evidence_used": False,
                    "external_evidence_sources": [],
                    "external_evidence_reason": "standard 模式不会主动检索公开资料。",
                }
            )
        ]
        SequenceOpenCodeAgent.instances = []

        async def fake_search(**kwargs):
            return []

        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            with TemporaryDirectory() as tmp_dir:
                audit_dir = Path(tmp_dir) / "audit"
                result = await agent.run_analysis_with_audit(
                    repo_path=None,
                    patch_path=None,
                    sanitizer_code="value = value.replace('<script>', '')",
                    audit_dir=audit_dir,
                )

                self.assertFalse((audit_dir / "05_deep_context_analysis.json").exists())
                summary = json.loads((audit_dir / "audit_summary.json").read_text(encoding="utf-8"))
                self.assertTrue(summary["deep_analysis_skipped"])
                self.assertIn("repo_path", summary["deep_analysis_skip_reason"])
                self.assertEqual(summary["final_verdict_source"], "opencode_analysis")
                self.assertTrue(result["result"].is_vuln)
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

    async def test_enhanced_search_can_record_public_evidence(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The sanitizer logic only removes a narrow script pattern.",
                        "details": ["blacklist replacement"],
                        "actions": ["replace literal script tag"],
                        "logic_with_nlp": "Replace a literal script token but leave alternate encodings untouched.",
                    }
                )
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search
        SequenceOpenCodeAgent.responses = [
            json.dumps(
                {
                    "reasoning": "The sanitizer still appears weak after supplementing the low-relevance RAG cases with public advisories.",
                    "is_vuln": True,
                    "confidence": "high",
                    "evidence_summary": "A similar sanitizer failure was documented in a public advisory for the same escaping pattern.",
                    "external_evidence_used": True,
                    "external_evidence_sources": [
                        "https://example.test/advisory-1",
                        "https://example.test/patch-1",
                    ],
                    "external_evidence_reason": "RAG relevance was low, so public defensive evidence was used to confirm the failure mode.",
                }
            )
        ]
        SequenceOpenCodeAgent.instances = []

        async def fake_search(**kwargs):
            return [
                {
                    "distance": 0.15,
                    "raw_distance": 0.15,
                    "rank": 0,
                    "entity": {
                        "CVE_ID": "CVE-2025-0001",
                        "unsafe_sanitizer_logic": "Literal tag replacement only",
                        "vulnerable_code_snippet": "value = value.replace('<script>', '')",
                        "cwe_id": ["CWE-79"],
                        "bypass_poc": "mixed encoding",
                        "unsafe_sanitizer_info": {"缺陷原因": "encoding gaps"},
                    },
                }
            ]

        agent.OpenCodeAgent = SequenceOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            result = await agent.run_analysis(
                repo_path=None,
                patch_path=None,
                sanitizer_code="value = value.replace('<script>', '')",
                analysis_profile="enhanced_search",
            )
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

        self.assertTrue(result["result"].external_evidence_used)
        self.assertEqual(result["result"].analysis_profile, "enhanced_search")
        self.assertEqual(result["result"].final_verdict_source, "opencode_analysis_with_public_evidence")
        self.assertEqual(result["rag_relevance"].label, "low")
        self.assertEqual(result["external_evidence_sources"], ["https://example.test/advisory-1", "https://example.test/patch-1"])

    async def test_run_analysis_falls_back_to_llm_when_opencode_analysis_fails(self):
        llm = SequenceLLM(
            [
                json.dumps(
                    {
                        "reasoning": "The sanitizer logic uses a narrow blacklist.",
                        "details": ["blacklist only"],
                        "actions": ["replace literal tag"],
                        "logic_with_nlp": "Replace a literal script tag but miss alternate encodings.",
                    }
                ),
                json.dumps(
                    {
                        "reasoning": "The target logic still appears vulnerable.",
                        "is_vuln": True,
                        "confidence": "medium",
                    }
                ),
                json.dumps(
                    {
                        "reasoning": "The fallback review agrees there is still a vulnerability.",
                        "is_real_vuln": True,
                        "confidence": "medium",
                    }
                ),
            ]
        )
        original_open_code_agent = agent.OpenCodeAgent
        original_default_llm = agent._default_llm
        original_search = agent.rag_search.search

        async def fake_search(**kwargs):
            return []

        agent.OpenCodeAgent = FailingOpenCodeAgent
        agent._default_llm = lambda: llm
        agent.rag_search.search = fake_search

        try:
            result = await agent.run_analysis(
                repo_path=None,
                patch_path=None,
                sanitizer_code="value = value.replace('<script>', '')",
                analysis_profile="enhanced_search",
            )
        finally:
            agent.OpenCodeAgent = original_open_code_agent
            agent._default_llm = original_default_llm
            agent.rag_search.search = original_search

        self.assertTrue(result["result"].is_vuln)
        self.assertEqual(result["result"].analysis_backend, "llm_fallback")
        self.assertEqual(result["result"].final_verdict_source_detail, "llm_fallback_review")
        self.assertIn("未执行公开资料补证", result["result"].external_evidence_reason)

    async def test_get_result_prefers_review_when_it_disagrees(self):
        result = await agent.get_result(
            {
                "full_analysis_decision": agent.AnalysisDecisionStruct(
                    reasoning="initial said safe",
                    is_vuln=False,
                    confidence="high",
                ),
                "review_result": agent.ReviewDecisionStruct(
                    reasoning="review found a real vulnerability",
                    is_real_vuln=True,
                    confidence="medium",
                ),
                "analysis_backend": "llm_fallback",
                "final_verdict_source_detail": "llm_fallback_review",
            }
        )

        self.assertTrue(result["result"].is_vuln)
        self.assertEqual(result["result"].confidence, "medium")
        self.assertIn("最终以复核结论为准", result["result"].reasoning)

    async def test_get_result_prefers_deep_analysis_when_present(self):
        result = await agent.get_result(
            {
                "full_analysis_decision": agent.AnalysisDecisionStruct(
                    reasoning="initial said safe",
                    is_vuln=False,
                    confidence="high",
                ),
                "review_result": agent.ReviewDecisionStruct(
                    reasoning="review found a real vulnerability",
                    is_real_vuln=True,
                    confidence="medium",
                ),
                "deep_analysis": agent.DeepAnalysisStruct(
                    vulnerable_path="input -> sink",
                    bypass_reasoning="numeric SQL context bypasses string escaping",
                    poc="curl ...",
                    is_vuln=True,
                    verdict="confirmed",
                ),
            }
        )

        self.assertTrue(result["result"].is_vuln)
        self.assertEqual(result["result"].final_verdict_source, "deep_context_analysis")
        self.assertIn("源码上下文深挖", result["result"].reasoning)
        self.assertEqual(result["result"].poc_text, "curl ...")

    def test_assess_rag_relevance_uses_low_medium_high_thresholds(self):
        none_result = agent.assess_rag_relevance([])
        self.assertEqual(none_result.label, "none")

        low_result = agent.assess_rag_relevance(
            [
                {"distance": 0.1, "raw_distance": 0.1, "rank": 0, "entity": {"unsafe_sanitizer_logic": "logic"}},
            ]
        )
        self.assertEqual(low_result.label, "low")

        medium_result = agent.assess_rag_relevance(
            [
                {"distance": 0.2, "raw_distance": 0.2, "rank": 0, "entity": {"unsafe_sanitizer_logic": "logic", "vulnerable_code_snippet": "code"}},
                {"distance": 0.35, "raw_distance": 0.35, "rank": 1, "entity": {"unsafe_sanitizer_logic": "logic2", "vulnerable_code_snippet": "code2"}},
            ]
        )
        self.assertEqual(medium_result.label, "medium")

        high_result = agent.assess_rag_relevance(
            [
                {"distance": 0.1, "raw_distance": 0.1, "rank": 0, "entity": {"unsafe_sanitizer_logic": "logic", "vulnerable_code_snippet": "code"}},
                {"distance": 0.2, "raw_distance": 0.2, "rank": 1, "entity": {"unsafe_sanitizer_logic": "logic2", "vulnerable_code_snippet": "code2"}},
                {"distance": 0.25, "raw_distance": 0.25, "rank": 2, "entity": {"unsafe_sanitizer_logic": "logic3", "vulnerable_code_snippet": "code3"}},
            ]
        )
        self.assertEqual(high_result.label, "high")

    def test_rerank_results_uses_dashscope_and_falls_back(self):
        class FakeResponse:
            status_code = 200

            class Output:
                results = [
                    type("Result", (), {"index": 1, "relevance_score": 0.9})(),
                    type("Result", (), {"index": 0, "relevance_score": 0.1})(),
                ]

            output = Output()

        original_create_dashscope_rerank = rag_search.create_dashscope_rerank
        original_rerank_enabled = rag_search.rerank_enabled
        try:
            rag_search.create_dashscope_rerank = lambda **kwargs: FakeResponse()
            rag_search.rerank_enabled = lambda: True
            reranked = rag_search._rerank_results(
                [
                    {"distance": 0.8, "raw_distance": 0.8, "entity": {"CVE_ID": "A"}},
                    {"distance": 0.2, "raw_distance": 0.2, "entity": {"CVE_ID": "B"}},
                ],
                logic_text="logic",
                code_text="code",
                top_k=2,
            )
        finally:
            rag_search.create_dashscope_rerank = original_create_dashscope_rerank
            rag_search.rerank_enabled = original_rerank_enabled

        self.assertEqual([item["entity"]["CVE_ID"] for item in reranked], ["B", "A"])
        self.assertEqual(reranked[0]["rank"], 0)
        self.assertEqual(reranked[0]["raw_distance"], 0.2)
        self.assertEqual(reranked[0]["rerank_score"], 0.9)

        original_create_dashscope_rerank = rag_search.create_dashscope_rerank
        original_rerank_enabled = rag_search.rerank_enabled
        try:
            def failing_rerank(**kwargs):
                raise RuntimeError("boom")

            rag_search.create_dashscope_rerank = failing_rerank
            rag_search.rerank_enabled = lambda: True
            fallback = rag_search._rerank_results(
                [
                    {"distance": 0.8, "raw_distance": 0.8, "entity": {"CVE_ID": "A"}},
                    {"distance": 0.2, "raw_distance": 0.2, "entity": {"CVE_ID": "B"}},
                ],
                logic_text="logic",
                code_text="code",
                top_k=1,
            )
        finally:
            rag_search.create_dashscope_rerank = original_create_dashscope_rerank
            rag_search.rerank_enabled = original_rerank_enabled

        self.assertEqual(len(fallback), 1)
        self.assertEqual(fallback[0]["entity"]["CVE_ID"], "A")
        self.assertEqual(fallback[0]["rank"], 0)

    def test_opencode_legacy_model_name_is_mapped_to_provider_model(self):
        agent_instance = OpenCodeAgent.__new__(OpenCodeAgent)
        agent_instance.project_path = "/tmp"
        agent_instance.model = "qwen3.7-plus"
        agent_instance.session_id = None
        agent_instance._refresh_session_id = lambda: None

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return type("Completed", (), {"stdout": '{"type":"text","part":{"text":"OK"}}', "stderr": "", "returncode": 0})()

        original_run = subprocess.run
        subprocess.run = fake_run
        try:
            result = OpenCodeAgent.chat(agent_instance, "hello")
        finally:
            subprocess.run = original_run

        self.assertEqual(result, "OK")
        self.assertEqual(len(calls), 1)
        self.assertIn("--dir", calls[0])
        self.assertIn("/tmp", calls[0])
        model_index = calls[0].index("--model")
        self.assertEqual(calls[0][model_index + 1], "alibaba-cn/qwen3.7-plus")
        self.assertEqual(calls[0][-1], "hello")


if __name__ == "__main__":
    unittest.main()
