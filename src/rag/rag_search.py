from __future__ import annotations

from http import HTTPStatus
from typing import Any

from pymilvus import AnnSearchRequest, MilvusClient, RRFRanker
from sangraph_logging import get_logger

from rag.config import (
    create_dashscope_rerank,
    default_collection_name,
    get_embedding_model,
    milvus_connection_args,
    rerank_enabled,
)

OUTPUT_FIELDS = [
    "CVE_ID",
    "unsafe_sanitizer_logic",
    "vulnerable_code_snippet",
    "cwe_id",
    "bypass_poc",
    "unsafe_sanitizer_info",
]
MILVUS_LOAD_TIMEOUT_SECONDS = 60.0
logger = get_logger(__name__)


def _create_client() -> MilvusClient:
    return MilvusClient(**milvus_connection_args())


def _load_state_value(load_state: Any) -> Any:
    if isinstance(load_state, dict):
        return load_state.get("state")
    return load_state


def _is_collection_loaded(load_state: Any) -> bool:
    state = _load_state_value(load_state)
    state_name = getattr(state, "name", None)
    if state_name is not None:
        return state_name == "Loaded"

    if state == 3:
        return True

    normalized = "".join(ch for ch in str(state).lower() if ch.isalnum())
    return normalized in {"loaded", "loadstateloaded"}


def _ensure_collection_loaded(client: MilvusClient, collection_name: str) -> None:
    if not client.has_collection(collection_name=collection_name):
        raise RuntimeError(f"Milvus collection does not exist: {collection_name}")

    load_state = client.get_load_state(collection_name=collection_name)
    if _is_collection_loaded(load_state):
        logger.debug("Milvus collection already loaded collection=%s", collection_name)
        return

    logger.info(
        "Loading Milvus collection collection=%s current_state=%s",
        collection_name,
        load_state,
    )
    client.load_collection(
        collection_name=collection_name,
        timeout=MILVUS_LOAD_TIMEOUT_SECONDS,
    )

    load_state = client.get_load_state(collection_name=collection_name)
    if not _is_collection_loaded(load_state):
        logger.warning(
            "Milvus collection load requested but state is not loaded collection=%s state=%s",
            collection_name,
            load_state,
        )


def _normalize_entity(entity: dict[str, Any]) -> dict[str, Any]:
    return {
        "CVE_ID": entity.get("CVE_ID"),
        "unsafe_sanitizer_logic": entity.get("unsafe_sanitizer_logic", ""),
        "vulnerable_code_snippet": entity.get("vulnerable_code_snippet", ""),
        "cwe_id": entity.get("cwe_id", []),
        "bypass_poc": entity.get("bypass_poc", ""),
        "unsafe_sanitizer_info": entity.get("unsafe_sanitizer_info", {}),
    }


def _normalize_hit(
    entity: dict[str, Any],
    distance: float,
    *,
    raw_distance: float | None = None,
    rank: int | None = None,
    rerank_score: float | None = None,
) -> dict[str, Any]:
    resolved_distance = float(raw_distance if raw_distance is not None else distance)
    return {
        "distance": resolved_distance,
        "raw_distance": resolved_distance,
        "rank": rank,
        "rerank_score": rerank_score,
        "entity": _normalize_entity(entity),
    }


def _normalize_query_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_normalize_hit(item, 0.0, rank=index) for index, item in enumerate(results)]


def _normalize_hybrid_results(results: list[Any]) -> list[dict[str, Any]]:
    normalized = []
    for index, hit in enumerate(results):
        if hasattr(hit, "entity") and hasattr(hit, "distance"):
            normalized.append(_normalize_hit(hit.entity, hit.distance, rank=index))
    return normalized


def _assign_ranks(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for index, result in enumerate(results):
        ranked.append(
            {
                **result,
                "rank": index,
            }
        )
    return ranked


def _build_requests(
    logic_text: str,
    code_text: str,
    expr: str,
    top_k: int,
) -> list[AnnSearchRequest]:
    embedding_model = get_embedding_model()
    recall_limit = top_k * 5
    requests: list[AnnSearchRequest] = []

    if logic_text:
        logic_vector = embedding_model.embed_query(logic_text)
        requests.append(
            AnnSearchRequest(
                data=[logic_vector],
                anns_field="unsafe_sanitizer_dense_vector",
                param={"metric_type": "COSINE", "params": {"nprobe": 10}},
                expr=expr,
                limit=recall_limit,
            )
        )
        requests.append(
            AnnSearchRequest(
                data=[logic_text],
                anns_field="unsafe_sanitizer_sparse_vector",
                param={"metric_type": "BM25"},
                expr=expr,
                limit=recall_limit,
            )
        )

    if code_text:
        code_vector = embedding_model.embed_query(code_text)
        requests.append(
            AnnSearchRequest(
                data=[code_vector],
                anns_field="vulnerable_code_vector",
                param={"metric_type": "COSINE", "params": {"nprobe": 10}},
                expr=expr,
                limit=recall_limit,
            )
        )
        requests.append(
            AnnSearchRequest(
                data=[code_text],
                anns_field="vulnerable_code_sparse_vector",
                param={"metric_type": "BM25"},
                expr=expr,
                limit=recall_limit,
            )
        )

    return requests


def _build_rerank_query(logic_text: str, code_text: str) -> str:
    return f"Logic: {logic_text}\nCode: {code_text}".strip()


def _build_rerank_documents(results: list[dict[str, Any]]) -> list[str]:
    documents = []
    for result in results:
        entity = result["entity"]
        documents.append(
            (
                f"Logic: {entity.get('unsafe_sanitizer_logic', '')}\n"
                f"Code: {entity.get('vulnerable_code_snippet', '')}"
            ).strip()
        )
    return documents


def _rerank_results(
    results: list[dict[str, Any]],
    logic_text: str,
    code_text: str,
    top_k: int,
) -> list[dict[str, Any]]:
    if not results:
        return []
    if not rerank_enabled():
        logger.debug("RAG rerank disabled; returning hybrid results directly")
        return _assign_ranks(results[:top_k])

    query_text = _build_rerank_query(logic_text, code_text)
    documents = _build_rerank_documents(results)
    try:
        response = create_dashscope_rerank(
            query=query_text,
            documents=documents,
            top_k=top_k,
        )
        if response.status_code != HTTPStatus.OK:
            raise RuntimeError(f"{response.code}: {response.message}")
    except Exception as exc:
        logger.warning("RAG rerank failed; falling back to hybrid results: %s", exc)
        return _assign_ranks(results[:top_k])

    reranked = []
    for rank, item in enumerate(response.output.results):
        original = results[item.index]
        reranked.append(
            _normalize_hit(
                original["entity"],
                original.get("raw_distance", original.get("distance", 0.0)),
                raw_distance=original.get("raw_distance", original.get("distance", 0.0)),
                rank=rank,
                rerank_score=getattr(item, "relevance_score", None),
            )
        )
    return reranked


async def search(
    logic_text: str = "",
    code_text: str = "",
    expr: str = "",
    top_k: int = 10,
    collection_name: str | None = None,
) -> list[dict[str, Any]]:
    resolved_collection = collection_name or default_collection_name()
    if not logic_text and not code_text and not expr:
        return []

    logger.debug(
        "Starting RAG search collection=%s logic_text_present=%s code_text_present=%s expr_present=%s top_k=%s",
        resolved_collection,
        bool(logic_text),
        bool(code_text),
        bool(expr),
        top_k,
    )
    client = _create_client()
    try:
        _ensure_collection_loaded(client, resolved_collection)

        if not logic_text and not code_text and expr:
            query_results = client.query(
                collection_name=resolved_collection,
                filter=expr,
                output_fields=OUTPUT_FIELDS,
                limit=top_k,
            )
            logger.debug("RAG query-only search returned %s hits", len(query_results))
            return _normalize_query_results(query_results)

        requests = _build_requests(logic_text=logic_text, code_text=code_text, expr=expr, top_k=top_k)
        if not requests:
            return []

        hybrid_results = client.hybrid_search(
            collection_name=resolved_collection,
            reqs=requests,
            ranker=RRFRanker(k=60),
            limit=top_k * 2,
            output_fields=OUTPUT_FIELDS,
        )
        normalized = _normalize_hybrid_results(hybrid_results[0] if hybrid_results else [])
        logger.debug("RAG hybrid search returned %s raw hits", len(normalized))
        return _rerank_results(normalized, logic_text=logic_text, code_text=code_text, top_k=top_k)
    finally:
        client.close()


async def only_code_search(
    code_text: str,
    top_k: int = 10,
    collection_name: str | None = None,
) -> list[dict[str, Any]]:
    return await search(code_text=code_text, top_k=top_k, collection_name=collection_name)
