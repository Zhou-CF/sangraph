from __future__ import annotations

import os
from http import HTTPStatus
from functools import lru_cache

from dashscope import TextReRank
from dotenv import load_dotenv
from langchain_classic.retrievers.document_compressors.cross_encoder import BaseCrossEncoder

from llm_factory.llm_factory import (
    DEFAULT_DASHSCOPE_EMBED_MODEL,
    embed_factory,
)

load_dotenv(override=True)

DEFAULT_RERANK_MODEL = "qwen3-rerank"


def _response_field(item, field_name: str, default=None):
    if isinstance(item, dict):
        return item.get(field_name, default)
    return getattr(item, field_name, default)


class DashScopeCrossEncoder(BaseCrossEncoder):
    """Adapter for legacy CrossEncoderReranker call sites in rag.py."""

    def __init__(self, model_name: str):
        self.model_name = model_name

    def score(self, text_pairs: list[tuple[str, str]]) -> list[float]:
        if not text_pairs:
            return []

        grouped_pairs: dict[str, list[tuple[int, str]]] = {}
        for pair_index, (query, document) in enumerate(text_pairs):
            grouped_pairs.setdefault(query, []).append((pair_index, document))

        scores = [0.0] * len(text_pairs)
        for query, indexed_documents in grouped_pairs.items():
            response = create_dashscope_rerank(
                query=query,
                documents=[document for _, document in indexed_documents],
                top_k=len(indexed_documents),
            )
            if response.status_code != HTTPStatus.OK:
                raise RuntimeError(f"{response.code}: {response.message}")

            for result in response.output.results:
                result_index = int(_response_field(result, "index", -1))
                if result_index < 0 or result_index >= len(indexed_documents):
                    continue
                score = float(_response_field(result, "relevance_score", 0.0))
                pair_index = indexed_documents[result_index][0]
                scores[pair_index] = score
        return scores


def milvus_uri() -> str:
    return os.getenv("MILVUS_URI", "http://127.0.0.1:19530")


def milvus_token() -> str:
    return os.getenv("MILVUS_TOKEN", "root:Milvus")


def default_collection_name() -> str:
    return os.getenv("MILVUS_COLLECTION_NAME", "sanitizer_logic")


def rerank_enabled() -> bool:
    return os.getenv("RAG_ENABLE_RERANK", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def milvus_connection_args() -> dict[str, str]:
    return {
        "uri": milvus_uri(),
        "token": milvus_token(),
    }


def dashscope_api_key() -> str:
    value = os.getenv("DASHSCOPE_API_KEY")
    if value:
        return value
    raise ValueError("缺少必要环境变量: DASHSCOPE_API_KEY")


def default_embedding_model() -> str:
    return os.getenv("RAG_EMBED_MODEL", DEFAULT_DASHSCOPE_EMBED_MODEL)


def default_rerank_model() -> str:
    return os.getenv("RAG_RERANK_MODEL", DEFAULT_RERANK_MODEL)


@lru_cache(maxsize=1)
def get_embedding_model():
    return embed_factory(
        embed_type="dashscope",
        embed_model=default_embedding_model(),
    )


@lru_cache(maxsize=1)
def get_cross_encoder_model() -> BaseCrossEncoder:
    return DashScopeCrossEncoder(model_name=default_rerank_model())


def create_dashscope_rerank(
    query: str,
    documents: list[str],
    top_k: int,
):
    return TextReRank.call(
        model=default_rerank_model(),
        query=query,
        documents=documents,
        top_n=top_k,
        return_documents=False,
        api_key=dashscope_api_key(),
    )
