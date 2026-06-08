import io
import os
import sys
import asyncio
from contextlib import redirect_stdout
from http import HTTPStatus
from importlib import import_module
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
for candidate in (ROOT, SRC_DIR):
    candidate_str = str(candidate)
    if candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

from rag import config as rag_config
from rag import rag as rag_module
from rag import rag_search


class FakeMilvusSearchClient:
    def __init__(self, load_states, collection_exists=True):
        self.load_states = list(load_states)
        self.collection_exists = collection_exists
        self.calls = []

    def has_collection(self, *, collection_name):
        self.calls.append(("has_collection", collection_name))
        return self.collection_exists

    def get_load_state(self, *, collection_name):
        self.calls.append(("get_load_state", collection_name))
        if self.load_states:
            return self.load_states.pop(0)
        return {"state": "Loaded"}

    def load_collection(self, *, collection_name, timeout=None):
        self.calls.append(("load_collection", collection_name, timeout))

    def query(self, *, collection_name, filter, output_fields, limit):
        self.calls.append(("query", collection_name, filter, tuple(output_fields), limit))
        return [
            {
                "CVE_ID": "CVE-TEST",
                "unsafe_sanitizer_logic": "logic",
                "vulnerable_code_snippet": "code",
            }
        ]

    def hybrid_search(self, *, collection_name, reqs, ranker, limit, output_fields):
        self.calls.append(
            ("hybrid_search", collection_name, len(reqs), limit, tuple(output_fields))
        )
        hit = type(
            "Hit",
            (),
            {
                "entity": {
                    "CVE_ID": "CVE-HYBRID",
                    "unsafe_sanitizer_logic": "logic",
                    "vulnerable_code_snippet": "code",
                },
                "distance": 0.25,
            },
        )()
        return [[hit]]

    def close(self):
        self.calls.append(("close",))


class FakeEmbeddingModel:
    def embed_query(self, text):
        return [0.0] * 1024


class RagModuleTests(unittest.TestCase):
    def test_rag_module_imports(self):
        module = import_module("rag.rag")
        self.assertTrue(hasattr(module, "create_collection"))
        self.assertTrue(hasattr(module, "main"))

    def test_cross_encoder_model_is_cached_and_uses_dashscope_scores(self):
        original_create_dashscope_rerank = rag_config.create_dashscope_rerank
        original_model = os.environ.get("RAG_RERANK_MODEL")
        calls = []

        class FakeResponse:
            def __init__(self, results):
                self.status_code = HTTPStatus.OK
                self.output = type("Output", (), {"results": results})()

        responses = [
            FakeResponse(
                [
                    type("Result", (), {"index": 1, "relevance_score": 0.3})(),
                    type("Result", (), {"index": 0, "relevance_score": 0.8})(),
                ]
            ),
            FakeResponse(
                [
                    type("Result", (), {"index": 0, "relevance_score": 0.5})(),
                ]
            ),
        ]

        def fake_create_dashscope_rerank(*, query: str, documents: list[str], top_k: int):
            calls.append((query, documents, top_k))
            return responses.pop(0)

        try:
            os.environ["RAG_RERANK_MODEL"] = "qwen3-rerank"
            rag_config.get_cross_encoder_model.cache_clear()
            rag_config.create_dashscope_rerank = fake_create_dashscope_rerank

            model = rag_config.get_cross_encoder_model()
            same_model = rag_config.get_cross_encoder_model()
            scores = model.score(
                [
                    ("logic query", "doc-a"),
                    ("logic query", "doc-b"),
                    ("code query", "doc-c"),
                ]
            )
        finally:
            rag_config.create_dashscope_rerank = original_create_dashscope_rerank
            rag_config.get_cross_encoder_model.cache_clear()
            if original_model is None:
                os.environ.pop("RAG_RERANK_MODEL", None)
            else:
                os.environ["RAG_RERANK_MODEL"] = original_model

        self.assertIs(model, same_model)
        self.assertEqual(model.model_name, "qwen3-rerank")
        self.assertEqual(
            calls,
            [
                ("logic query", ["doc-a", "doc-b"], 2),
                ("code query", ["doc-c"], 1),
            ],
        )
        self.assertEqual(scores, [0.8, 0.3, 0.5])

    def test_cli_dispatches_collection_commands(self):
        original_create_collection = rag_module.create_collection
        original_drop_collection = rag_module.drop_collection
        original_describe_collection = rag_module.describe_collection
        invoked = []

        try:
            rag_module.create_collection = lambda collection_name=None: invoked.append(
                ("create", collection_name)
            )
            rag_module.drop_collection = lambda collection_name: invoked.append(
                ("drop", collection_name)
            )
            rag_module.describe_collection = lambda collection_name=None: {
                "collection_name": collection_name
            }

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                create_exit_code = rag_module.main(
                    ["create-collection", "--collection-name", "demo"]
                )
                drop_exit_code = rag_module.main(
                    ["drop-collection", "--collection-name", "demo"]
                )
                describe_exit_code = rag_module.main(
                    ["describe-collection", "--collection-name", "demo"]
                )
        finally:
            rag_module.create_collection = original_create_collection
            rag_module.drop_collection = original_drop_collection
            rag_module.describe_collection = original_describe_collection

        self.assertEqual(create_exit_code, 0)
        self.assertEqual(drop_exit_code, 0)
        self.assertEqual(describe_exit_code, 0)
        self.assertEqual(invoked, [("create", "demo"), ("drop", "demo")])
        self.assertIn("collection_name", stdout.getvalue())

    def test_rag_search_loads_collection_before_query(self):
        original_create_client = rag_search._create_client
        client = FakeMilvusSearchClient(
            load_states=[{"state": "NotLoad"}, {"state": "Loaded"}]
        )

        try:
            rag_search._create_client = lambda: client
            results = asyncio.run(
                rag_search.search(
                    expr="CVE_ID == 'CVE-TEST'",
                    top_k=1,
                    collection_name="demo",
                )
            )
        finally:
            rag_search._create_client = original_create_client

        self.assertEqual(results[0]["entity"]["CVE_ID"], "CVE-TEST")
        self.assertEqual(results[0]["rank"], 0)
        self.assertEqual(results[0]["raw_distance"], 0.0)
        self.assertEqual(
            client.calls[:5],
            [
                ("has_collection", "demo"),
                ("get_load_state", "demo"),
                ("load_collection", "demo", 60.0),
                ("get_load_state", "demo"),
                ("query", "demo", "CVE_ID == 'CVE-TEST'", tuple(rag_search.OUTPUT_FIELDS), 1),
            ],
        )
        self.assertEqual(client.calls[-1], ("close",))

    def test_rag_search_skips_load_when_collection_is_loaded(self):
        original_create_client = rag_search._create_client
        client = FakeMilvusSearchClient(load_states=[{"state": "Loaded"}])

        try:
            rag_search._create_client = lambda: client
            asyncio.run(
                rag_search.search(
                    expr="CVE_ID == 'CVE-TEST'",
                    top_k=1,
                    collection_name="demo",
                )
            )
        finally:
            rag_search._create_client = original_create_client

        self.assertNotIn(
            ("load_collection", "demo", rag_search.MILVUS_LOAD_TIMEOUT_SECONDS),
            client.calls,
        )
        self.assertIn(("query", "demo", "CVE_ID == 'CVE-TEST'", tuple(rag_search.OUTPUT_FIELDS), 1), client.calls)

    def test_rag_search_raises_when_collection_is_missing(self):
        original_create_client = rag_search._create_client
        client = FakeMilvusSearchClient(load_states=[], collection_exists=False)

        try:
            rag_search._create_client = lambda: client
            with self.assertRaisesRegex(RuntimeError, "Milvus collection does not exist: demo"):
                asyncio.run(
                    rag_search.search(
                        expr="CVE_ID == 'CVE-TEST'",
                        top_k=1,
                        collection_name="demo",
                    )
                )
        finally:
            rag_search._create_client = original_create_client

        self.assertEqual(client.calls, [("has_collection", "demo"), ("close",)])

    def test_rag_search_loads_collection_before_hybrid_search(self):
        original_create_client = rag_search._create_client
        original_get_embedding_model = rag_search.get_embedding_model
        original_rerank_enabled = rag_search.rerank_enabled
        client = FakeMilvusSearchClient(
            load_states=[{"state": "NotLoad"}, {"state": "Loaded"}]
        )

        try:
            rag_search._create_client = lambda: client
            rag_search.get_embedding_model = lambda: FakeEmbeddingModel()
            rag_search.rerank_enabled = lambda: False
            results = asyncio.run(
                rag_search.search(
                    code_text="vulnerable code",
                    top_k=1,
                    collection_name="demo",
                )
            )
        finally:
            rag_search._create_client = original_create_client
            rag_search.get_embedding_model = original_get_embedding_model
            rag_search.rerank_enabled = original_rerank_enabled

        self.assertEqual(results[0]["entity"]["CVE_ID"], "CVE-HYBRID")
        self.assertEqual(results[0]["rank"], 0)
        self.assertEqual(results[0]["raw_distance"], 0.25)
        self.assertEqual(
            client.calls[:5],
            [
                ("has_collection", "demo"),
                ("get_load_state", "demo"),
                ("load_collection", "demo", 60.0),
                ("get_load_state", "demo"),
                ("hybrid_search", "demo", 2, 2, tuple(rag_search.OUTPUT_FIELDS)),
            ],
        )
