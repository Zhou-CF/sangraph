# RAG / Milvus Handoff

## Goal
This handoff covers the next implementation task: finish the `rag/` subsystem first, using a local Dockerized Milvus deployment with authentication enabled, then refactor the RAG code so the analysis system can consume it directly.

The desired end state is:
- Milvus runs locally through Docker Compose
- `rag/` connects to the local Milvus instance via environment variables
- hybrid retrieval keeps the current dense + sparse + BM25 direction
- the RAG query layer returns one stable result structure that upper layers can consume without special cases
- Docker image pull failures can be retried through the proxy `192.168.124.173:7890`

## Current Repo State
The repository has already moved to `~/SanGraph`, and the key files currently involved are:
- `rag/rag.py`
- `rag/rag_search.py`
- `llm_factory/llm_factory.py`
- `base_opencode/agent.py` (consumer of RAG output)

There are several concrete problems in the current implementation:

### 1. Hardcoded Milvus connection
`rag/rag_search.py` currently creates a module-level client with:
- `uri="http://192.168.20.138:19530"`
- `token="root:Milvus"`

This must be replaced with environment-driven local configuration.

### 2. Proxy behavior conflicts with deployment needs
`rag/rag_search.py` removes `http_proxy`, `https_proxy`, `HTTP_PROXY`, `HTTPS_PROXY`, `all_proxy`, and `ALL_PROXY` at import time.

That conflicts with the deployment requirement that Docker image pulls may need to go through:
- `HTTP_PROXY=http://192.168.124.173:7890`
- `HTTPS_PROXY=http://192.168.124.173:7890`
- `ALL_PROXY=http://192.168.124.173:7890`

The RAG module must not globally delete proxy variables.

### 3. Reranker path is hardcoded to one machine
`rag/rag_search.py` hardcodes the cross-encoder model to a local Hugging Face cache path under `/home/sanitizer/...`.

That path is not portable. Replace it with a model-name-based configuration, with a default such as:
- `BAAI/bge-reranker-v2-m3`

### 4. RAG return structure does not match the analysis consumer
`base_opencode/agent.py` formats RAG results by reading:
- `item["entity"]`
- `item["distance"]`

But `rag/rag_search.py` currently returns flattened dictionaries in the final reranked path. That mismatch will break the analysis pipeline.

The RAG layer must return one normalized structure everywhere:
```python
{
    "distance": float,
    "entity": {
        "CVE_ID": ...,
        "unsafe_sanitizer_logic": ...,
        "vulnerable_code_snippet": ...,
        "cwe_id": ...,
        "bypass_poc": ...,
        "unsafe_sanitizer_info": ...,
    },
}
```

### 5. Connection/configuration logic is duplicated
`rag/rag.py` and `rag/rag_search.py` each construct Milvus clients and embed/rerank models separately.

This should be centralized.

### 6. Collection and management helpers are incomplete for local ops
`rag/rag.py` has useful schema/index helpers, but it lacks a clean operator-facing CLI for common actions such as:
- create collection
- drop collection
- describe collection

That makes local setup harder than necessary.

## Target Runtime Configuration
The next implementer should standardize on these runtime variables:

- `MILVUS_URI=http://127.0.0.1:19530`
- `MILVUS_TOKEN=root:Milvus`
- `MILVUS_COLLECTION_NAME=sanitizer_logic`
- `RAG_EMBED_PROVIDER=dashscope`
- `RAG_EMBED_MODEL=text-embedding-v4`
- `RAG_RERANK_MODEL=BAAI/bge-reranker-v2-m3`
- `RAG_ENABLE_RERANK=true`

Notes:
- Keep `MILVUS_TOKEN=root:Milvus` because the Dockerized Milvus instance should enable authorization.
- Keep the collection name default as `sanitizer_logic` to match current code assumptions.

## Milvus Docker Deployment Plan
Use Milvus Standalone with Docker Compose, not Milvus Lite.

Recommended deployment directory:
- `deploy/milvus/`

Recommended files:
- `deploy/milvus/docker-compose.yml`
- `deploy/milvus/milvus.yaml`
- `deploy/milvus/.gitignore`

### Compose layout
Use three services:
- `etcd`
- `minio`
- `standalone`

### Required Milvus settings
In `milvus.yaml`, enable authentication with:
```yaml
common:
  security:
    authorizationEnabled: true
    superUsers:
      - root
```

### Required port exposure
Expose at least:
- `19530:19530` for Milvus client access
- `9091:9091` for Milvus internal/http health if needed

### Volumes
Persist data for:
- etcd
- minio
- milvus

Recommended approach: keep a `volumes/` directory under `deploy/milvus/` and ignore it with `.gitignore`.

### Proxy fallback for image pulls
If `docker compose up -d` fails during image pull, retry with:
```bash
HTTP_PROXY=http://192.168.124.173:7890 \
HTTPS_PROXY=http://192.168.124.173:7890 \
ALL_PROXY=http://192.168.124.173:7890 \
docker compose -f deploy/milvus/docker-compose.yml up -d
```

If the environment also needs `NO_PROXY`, keep local endpoints direct as appropriate.

## Code Refactor Plan

### A. Add a shared RAG config module
Add a new module, recommended path:
- `rag/config.py`

This module should centralize:
- Milvus URI/token/collection name
- embedding provider/model
- reranker model name
- rerank enable/disable flag
- helper constructors such as:
  - `milvus_connection_args()`
  - `get_embedding_model()`
  - `get_cross_encoder_model()`

Implementation notes:
- use `load_dotenv(override=True)` once here
- use lazy initialization or `lru_cache` for embedding and reranker model constructors
- do not create a global Milvus client at import time

### B. Refactor `rag/rag.py`
This file should remain the Milvus schema/index/ops module.

Tasks:
- replace direct `os.getenv(...)` access with the shared config helpers
- keep the current schema direction intact:
  - `unsafe_sanitizer_dense_vector`
  - `unsafe_sanitizer_sparse_vector`
  - `vulnerable_code_vector`
  - `vulnerable_code_sparse_vector`
  - BM25 function definitions for logic and code
- make `create_collection()` idempotent:
  - if the collection already exists, return cleanly instead of failing
- keep index creation as a separate helper, but ensure local operator flow is smooth
- add a small CLI entrypoint so operators can run commands like:
  - `python -m rag.rag create-collection`
  - `python -m rag.rag drop-collection`
  - `python -m rag.rag describe-collection`

CLI only needs to cover common setup/inspection operations.

### C. Refactor `rag/rag_search.py`
This file should become the query/runtime layer.

Tasks:
- remove the module-level `MilvusClient(...)`
- create the client inside helper functions and close it after each operation
- remove the proxy-clearing logic entirely
- use the shared config module for embeddings, reranker, connection args, and collection name
- keep the current four-way retrieval behavior:
  - logic dense
  - logic sparse / BM25
  - code dense
  - code sparse / BM25
- keep `RRFRanker(k=60)` unless a concrete compatibility issue is found
- rerank with `CrossEncoderReranker` only if enabled; if rerank initialization or execution fails, fall back to the unre-ranked top results
- normalize **all** return paths to one result schema:
  - hybrid search results
  - pure `expr` filter results
  - empty results

Recommended output fields remain:
- `CVE_ID`
- `unsafe_sanitizer_logic`
- `vulnerable_code_snippet`
- `cwe_id`
- `bypass_poc`
- `unsafe_sanitizer_info`

### D. Add `rag/__init__.py`
Add a minimal package marker and short module docstring so `rag` can be imported cleanly as a package.

## Required Interface Contract
The public async query function should stay compatible with current usage:
```python
async def search(
    logic_text: str = "",
    code_text: str = "",
    expr: str = "",
    top_k: int = 10,
    collection_name: str | None = None,
):
    ...
```

But its return value must be normalized as:
```python
list[dict]
```
where each item is:
```python
{
    "distance": float,
    "entity": {
        "CVE_ID": str | None,
        "unsafe_sanitizer_logic": str,
        "vulnerable_code_snippet": str,
        "cwe_id": list[str] | tuple[str, ...],
        "bypass_poc": str,
        "unsafe_sanitizer_info": dict | str,
    },
}
```

This is important because `base_opencode/agent.py` already expects `entity` + `distance` when formatting results for the LLM.

## Suggested Implementation Order
1. Add Milvus Docker deployment files under `deploy/milvus/`
2. Start Milvus locally through Docker Compose
3. Add `rag/config.py`
4. Refactor `rag/rag.py` to use shared config and add CLI
5. Refactor `rag/rag_search.py` to use shared config and normalize results
6. Add `rag/__init__.py`
7. Run static checks and a minimal connection/query smoke test

## Validation Checklist

### Docker / Milvus validation
- `docker compose -f deploy/milvus/docker-compose.yml up -d` succeeds
- if pull fails, retry via the proxy endpoint and document whether proxy was required
- Milvus is reachable on `127.0.0.1:19530`
- auth is enabled and token-based connection works

### Code validation
- no hardcoded remote Milvus IP remains in `rag/`
- no hardcoded local reranker cache path remains in `rag/`
- no proxy environment variables are deleted in `rag/`
- shared config is used consistently by both `rag/rag.py` and `rag/rag_search.py`

### Behavioral validation
- collection creation works through the CLI helper
- empty query branches return `[]` rather than crashing
- pure `expr` filter queries return normalized `distance + entity` records
- hybrid search returns normalized `distance + entity` records
- rerank failures degrade gracefully instead of breaking retrieval

### Consumer compatibility
- `base_opencode/agent.py` should be able to consume the new RAG results without requiring further RAG output shape changes

## Known Constraints / Risks
- BM25/sparse support depends on using standard Milvus service mode; do not replace this with Lite for this task
- embedding still depends on `llm_factory.embed_factory(...)`, which likely requires valid embedding credentials such as DashScope configuration
- reranker model download may require network access; if not available, use `RAG_ENABLE_RERANK=false` as a temporary fallback
- this handoff only covers the RAG/Milvus portion, not the rest of the analysis pipeline

## Done Definition
This task is done when all of the following are true:
- local authenticated Milvus is running under Docker Compose
- `rag/` no longer depends on hardcoded remote Milvus settings
- `rag_search.search()` returns one stable normalized schema across all branches
- collection management has a practical local CLI path
- the next stage of the analysis system can consume the RAG layer without another retrieval-shape refactor
