#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
FRONTEND_DIR="$REPO_ROOT/frontend"
MILVUS_COMPOSE_DIR="$REPO_ROOT/other/deploy/milvus"
RUN_DIR="$REPO_ROOT/other/artifacts/run"
BACKEND_LOG="$RUN_DIR/backend.log"
ENV_FILE="$REPO_ROOT/.env"
RAG_JSONL="$REPO_ROOT/other/data/verified_sanitizer_dataset.to_rag.jsonl"
RAG_SOURCE_JSONL="$REPO_ROOT/other/data/verified_sanitizer_dataset.jsonl"
RAG_ERROR_JSONL="$REPO_ROOT/other/data/verified_sanitizer_dataset.to_rag.errors.jsonl"

HOST="${SANGRAPH_HOST:-127.0.0.1}"
API_PORT="${SANGRAPH_API_PORT:-8010}"
WEB_PORT="${SANGRAPH_WEB_PORT:-5173}"
COLLECTION_NAME="${MILVUS_COLLECTION_NAME:-}"
DEFAULT_DASHSCOPE_API_KEY="${SANGRAPH_DEFAULT_DASHSCOPE_API_KEY:-sk-326bf87f51154797a7a379fe7d960396}"
DEFAULT_OPENCODE_MODEL="${SANGRAPH_DEFAULT_OPENCODE_MODEL:-alibaba-cn/qwen3.7-plus}"

SKIP_INSTALL=0
SKIP_RAG_SEED=0
REBUILD_RAG_DATA=0
INSTALL_OPENCODE=1
BACKEND_RELOAD=1

BACKEND_PID=""

log() {
  printf '[sangraph] %s\n' "$*"
}

fail() {
  printf '[sangraph] ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<EOF
Usage: ./scripts/start_full_stack.sh [options]

Start the SanGraph full local stack:
  - .env bootstrap
  - uv sync
  - frontend npm install
  - opencode check/install
  - Milvus docker compose
  - collection create
  - optional RAG data seed
  - backend FastAPI
  - frontend Vite

Ubuntu/Debian prerequisites:
  - uv
  - Node.js 18 LTS or 20+ with npm
  - Docker Engine with the compose plugin
  - curl

Options:
  --skip-install         Skip uv sync and npm install.
  --skip-rag-seed        Skip automatic RAG collection seeding.
  --rebuild-rag-data     Rebuild other/data/verified_sanitizer_dataset.to_rag.jsonl before seeding.
  --skip-opencode-install
                         Do not auto-install @opencode/cli when missing.
  --no-reload            Start backend without --reload.
  --host HOST            Bind host for backend and frontend. Default: $HOST
  --api-port PORT        Backend port. Default: $API_PORT
  --web-port PORT        Frontend port. Default: $WEB_PORT
  --collection-name NAME Milvus collection name. Default: MILVUS_COLLECTION_NAME from env/.env, else sanitizer_logic
  -h, --help             Show this help message.
EOF
}

print_prereq_help() {
  local cmd="$1"

  case "$cmd" in
    uv)
      cat >&2 <<'EOF'
[sangraph] Ubuntu/Debian setup hint for uv:
  curl -LsSf https://astral.sh/uv/install.sh | sh
  exec "$SHELL" -l
  uv --version

[sangraph] uv sync will read pyproject.toml and create the Python 3.13 .venv.
EOF
      ;;
    node|npm)
      cat >&2 <<'EOF'
[sangraph] Ubuntu/Debian setup hint for Node.js/npm:
  Install Node.js 18 LTS or 20+ with npm, then verify:
  node --version
  npm --version
EOF
      ;;
    docker)
      cat >&2 <<'EOF'
[sangraph] Ubuntu/Debian setup hint for Docker:
  Install Docker Engine and the Docker Compose plugin, then verify:
  docker --version
  docker compose version
  docker info
EOF
      ;;
    curl)
      cat >&2 <<'EOF'
[sangraph] Ubuntu/Debian setup hint for curl:
  sudo apt update
  sudo apt install -y curl
EOF
      ;;
  esac
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf '[sangraph] ERROR: Missing required command: %s\n' "$cmd" >&2
    print_prereq_help "$cmd"
    exit 1
  fi
}

env_has_nonempty_key() {
  local key="$1"
  awk -v key="$key" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      sub(/^export[[:space:]]+/, "", line)
      split(line, parts, "=")
      env_key = parts[1]
      gsub(/[[:space:]]+$/, "", env_key)
      if (env_key == key) {
        value = substr(line, index(line, "=") + 1)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        if (value != "") {
          found = 1
        }
      }
    }
    END { exit found ? 0 : 1 }
  ' "$ENV_FILE"
}

ensure_env_file() {
  local dashscope_api_key="${DASHSCOPE_API_KEY:-$DEFAULT_DASHSCOPE_API_KEY}"

  if [[ ! -f "$ENV_FILE" ]]; then
    log "Creating default .env"
    (
      umask 077
      cat >"$ENV_FILE" <<EOF
DASHSCOPE_API_KEY=$dashscope_api_key
OPENCODE_MODEL=${OPENCODE_MODEL:-$DEFAULT_OPENCODE_MODEL}
MILVUS_URI=${MILVUS_URI:-http://127.0.0.1:19530}
MILVUS_TOKEN=${MILVUS_TOKEN:-root:Milvus}
MILVUS_COLLECTION_NAME=${MILVUS_COLLECTION_NAME:-sanitizer_logic}
EOF
    )
    return
  fi

  if ! env_has_nonempty_key "DASHSCOPE_API_KEY"; then
    log "Adding missing DASHSCOPE_API_KEY to .env"
    {
      printf '\n'
      printf 'DASHSCOPE_API_KEY=%s\n' "$dashscope_api_key"
    } >>"$ENV_FILE"
    chmod go-rwx "$ENV_FILE" 2>/dev/null || true
  fi

  if ! env_has_nonempty_key "OPENCODE_MODEL"; then
    log "Adding missing OPENCODE_MODEL to .env"
    {
      printf '\n'
      printf 'OPENCODE_MODEL=%s\n' "${OPENCODE_MODEL:-$DEFAULT_OPENCODE_MODEL}"
    } >>"$ENV_FILE"
    chmod go-rwx "$ENV_FILE" 2>/dev/null || true
  fi
}

check_node_version() {
  local major
  major=$(node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null || true)
  if [[ ! "$major" =~ ^[0-9]+$ ]] || (( major < 18 || major == 19 )); then
    printf '[sangraph] ERROR: Node.js 18 LTS or 20+ is required; found: %s\n' "$(node --version 2>/dev/null || printf 'unknown')" >&2
    print_prereq_help node
    exit 1
  fi
}

check_docker() {
  if ! docker compose version >/dev/null 2>&1; then
    cat >&2 <<'EOF'
[sangraph] ERROR: Docker Compose plugin is not available.
[sangraph] Install Docker Engine with the compose plugin, then verify:
  docker compose version
EOF
    exit 1
  fi

  if ! docker info >/dev/null 2>&1; then
    cat >&2 <<'EOF'
[sangraph] ERROR: Docker daemon is not reachable by the current user.
[sangraph] On Ubuntu/Debian, common fixes are:
  sudo systemctl start docker
  sudo usermod -aG docker "$USER"
[sangraph] If you change groups, log out and back in before rerunning this script.
EOF
    exit 1
  fi
}

wait_for_http() {
  local url="$1"
  local name="$2"
  local attempts="${3:-60}"
  local sleep_seconds="${4:-2}"

  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      log "$name is ready: $url"
      return 0
    fi
    sleep "$sleep_seconds"
  done

  fail "$name did not become ready in time: $url"
}

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM

  if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" >/dev/null 2>&1; then
    log "Stopping backend process $BACKEND_PID"
    kill "$BACKEND_PID" >/dev/null 2>&1 || true
    wait "$BACKEND_PID" 2>/dev/null || true
  fi

  exit "$exit_code"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-install)
      SKIP_INSTALL=1
      ;;
    --skip-rag-seed)
      SKIP_RAG_SEED=1
      ;;
    --rebuild-rag-data)
      REBUILD_RAG_DATA=1
      ;;
    --skip-opencode-install)
      INSTALL_OPENCODE=0
      ;;
    --no-reload)
      BACKEND_RELOAD=0
      ;;
    --host)
      [[ $# -ge 2 ]] || fail "--host requires a value"
      HOST="$2"
      shift
      ;;
    --api-port)
      [[ $# -ge 2 ]] || fail "--api-port requires a value"
      API_PORT="$2"
      shift
      ;;
    --web-port)
      [[ $# -ge 2 ]] || fail "--web-port requires a value"
      WEB_PORT="$2"
      shift
      ;;
    --collection-name)
      [[ $# -ge 2 ]] || fail "--collection-name requires a value"
      COLLECTION_NAME="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
  shift
done

trap cleanup EXIT INT TERM

ensure_env_file

mkdir -p "$RUN_DIR" "$REPO_ROOT/.cache/uv" "$REPO_ROOT/.cache/npm"
export UV_CACHE_DIR="${UV_CACHE_DIR:-$REPO_ROOT/.cache/uv}"
export NPM_CONFIG_CACHE="${NPM_CONFIG_CACHE:-$REPO_ROOT/.cache/npm}"

if [[ "$SKIP_INSTALL" -eq 0 ]]; then
  require_cmd uv
fi
require_cmd node
require_cmd npm
require_cmd docker
require_cmd curl
check_node_version
check_docker

if [[ "$SKIP_INSTALL" -eq 0 ]]; then
  log "Syncing Python dependencies with uv"
  (
    cd "$REPO_ROOT"
    uv sync
  )

  log "Installing frontend dependencies"
  (
    cd "$FRONTEND_DIR"
    npm install
  )
else
  log "Skipping dependency installation"
fi

PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
[[ -x "$PYTHON_BIN" ]] || fail "Python environment not found: $PYTHON_BIN"

if [[ -z "$COLLECTION_NAME" ]]; then
  COLLECTION_NAME=$(
    cd "$REPO_ROOT"
    PYTHONPATH=src "$PYTHON_BIN" - <<'PY'
from rag.config import default_collection_name

print(default_collection_name())
PY
  )
fi
COLLECTION_NAME="${COLLECTION_NAME:-sanitizer_logic}"

if command -v opencode >/dev/null 2>&1; then
  log "opencode CLI found on PATH"
elif [[ "$INSTALL_OPENCODE" -eq 1 ]]; then
  log "Installing @opencode/cli"
  if ! npm install -g opencode-ai; then
    cat >&2 <<'EOF'
[sangraph] ERROR: Failed to install opencode-ai with npm.
[sangraph] You can install it manually, fix npm global permissions, or rerun with --skip-opencode-install.
EOF
    exit 1
  fi
  command -v opencode >/dev/null 2>&1 || fail "opencode is still not on PATH after installation"
else
  log "opencode CLI not found; continuing without auto-install"
fi

[[ -f "$MILVUS_COMPOSE_DIR/docker-compose.yml" ]] || fail "Milvus compose file not found: $MILVUS_COMPOSE_DIR/docker-compose.yml"

log "Starting Milvus with docker compose"
(
  cd "$MILVUS_COMPOSE_DIR"
  docker compose up -d
)

wait_for_http "http://127.0.0.1:9091/healthz" "Milvus"

log "Ensuring Milvus collection exists: $COLLECTION_NAME"
(
  cd "$REPO_ROOT"
  PYTHONPATH=src MILVUS_COLLECTION_NAME="$COLLECTION_NAME" \
    "$PYTHON_BIN" -m rag.rag create-collection --collection-name "$COLLECTION_NAME"
)

collection_row_count() {
  (
    cd "$REPO_ROOT"
    PYTHONPATH=src MILVUS_COLLECTION_NAME="$COLLECTION_NAME" \
      "$PYTHON_BIN" - <<'PY'
from pymilvus import MilvusClient
from rag.config import milvus_connection_args
import os

collection_name = os.environ["MILVUS_COLLECTION_NAME"]
client = MilvusClient(**milvus_connection_args())
try:
    if not client.has_collection(collection_name=collection_name):
        print(-1)
    else:
        stats = client.get_collection_stats(collection_name=collection_name)
        print(int(stats.get("row_count", 0)))
finally:
    client.close()
PY
  )
}

if [[ "$REBUILD_RAG_DATA" -eq 1 ]]; then
  [[ -f "$RAG_SOURCE_JSONL" ]] || fail "RAG source dataset not found: $RAG_SOURCE_JSONL"
  log "Rebuilding RAG dataset JSONL"
  (
    cd "$REPO_ROOT"
    PYTHONPATH=src "$PYTHON_BIN" -m rag.build_rag_dataset \
      --input-path other/data/verified_sanitizer_dataset.jsonl \
      --output-path other/data/verified_sanitizer_dataset.to_rag.jsonl \
      --error-path other/data/verified_sanitizer_dataset.to_rag.errors.jsonl
  )
fi

if [[ "$SKIP_RAG_SEED" -eq 1 ]]; then
  log "Skipping RAG data seed"
else
  [[ -f "$RAG_JSONL" ]] || fail "RAG dataset not found: $RAG_JSONL"

  row_count=$(collection_row_count | tail -n 1 | tr -d '\r')
  if [[ "$row_count" =~ ^[0-9]+$ ]] && (( row_count > 0 )); then
    log "Collection already contains $row_count rows; skipping seed"
  else
    log "Seeding RAG data into Milvus; this may take a while on first run"
    (
      cd "$REPO_ROOT"
      PYTHONPATH=src MILVUS_COLLECTION_NAME="$COLLECTION_NAME" \
        "$PYTHON_BIN" - <<'PY'
import os
from rag.test_milvus import upload_from_to_rag_jsonl

upload_from_to_rag_jsonl(
    jsonl_path="other/data/verified_sanitizer_dataset.to_rag.jsonl",
    collection_name=os.environ["MILVUS_COLLECTION_NAME"],
    limit=0,
)
PY
    )
    row_count=$(collection_row_count | tail -n 1 | tr -d '\r')
    log "RAG seed completed; current row count: $row_count"
  fi
fi

: >"$BACKEND_LOG"

log "Starting backend API on http://$HOST:$API_PORT"
(
  cd "$REPO_ROOT"
  if [[ "$BACKEND_RELOAD" -eq 1 ]]; then
    PYTHONPATH=src "$PYTHON_BIN" -m scripts.run_webapp --host "$HOST" --port "$API_PORT" --reload
  else
    PYTHONPATH=src "$PYTHON_BIN" -m scripts.run_webapp --host "$HOST" --port "$API_PORT"
  fi
) >>"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!

wait_for_http "http://$HOST:$API_PORT/api/health" "Backend API"

log "Backend log: $BACKEND_LOG"
log "Frontend will start on http://$HOST:$WEB_PORT"
log "Frontend API proxy target: ${VITE_API_TARGET:-http://$HOST:$API_PORT}"
log "Press Ctrl-C to stop the frontend and the backend."

(
  cd "$FRONTEND_DIR"
  VITE_API_TARGET="${VITE_API_TARGET:-http://$HOST:$API_PORT}" npm run dev -- --host "$HOST" --port "$WEB_PORT"
)
