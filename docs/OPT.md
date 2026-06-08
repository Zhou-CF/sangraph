# SanGraph 安装命令

`SanGraph` 当前没有单独的业务数据库；这里说的“建库”主要是启动 `Milvus`，创建 collection，并导入 RAG 数据。

## 1. 准备 `.env`

一键启动脚本会自动创建 `.env`，并在缺少 `DASHSCOPE_API_KEY` 或 `OPENCODE_MODEL` 时写入默认值；手动启动时可以按下面格式准备。

```dotenv
# 分析、embedding、RAG 都会用到
DASHSCOPE_API_KEY=your_key

# OpenCode 默认使用 alibaba-cn provider
OPENCODE_MODEL=alibaba-cn/qwen3.7-plus

# Milvus 连接配置
MILVUS_URI=http://127.0.0.1:19530
MILVUS_TOKEN=root:Milvus
MILVUS_COLLECTION_NAME=sanitizer_logic

# 只有重建 to_rag 数据集时才需要
DEEPSEEK_API_KEY=your_key
```

## 2. 手动安装和启动顺序

```bash
cd /home/codex/SanGraph

uv sync  # 安装 Python 依赖，并生成 .venv

cd frontend
npm install  # 安装前端依赖
cd ..

npm install -g opencode-ai  # 安装 opencode CLI
command -v opencode         # 确认 opencode 已进 PATH

cd other/deploy/milvus
docker compose up -d                # 启动 Milvus
docker compose ps                   # 查看容器状态
curl http://127.0.0.1:9091/healthz  # 检查 Milvus 健康
cd /home/codex/SanGraph

PYTHONPATH=src ./.venv/bin/python -m rag.rag create-collection --collection-name sanitizer_logic
# 创建默认 Milvus collection；如果你改了 MILVUS_COLLECTION_NAME，这里也改成同一个名字
```

```bash
PYTHONPATH=src ./.venv/bin/python - <<'PY'
import os
from rag.test_milvus import upload_from_to_rag_jsonl

upload_from_to_rag_jsonl(
    jsonl_path="other/data/verified_sanitizer_dataset.to_rag.jsonl",  # 仓库自带 RAG 数据
    collection_name=os.getenv("MILVUS_COLLECTION_NAME", "sanitizer_logic"),  # 沿用 .env 里的 collection 名
    limit=0,  # 导入全部数据
)
PY
```

```bash
PYTHONPATH=src ./.venv/bin/python -m scripts.run_webapp --host 127.0.0.1 --port 8010 --reload
# 启动后端；这个终端会持续占用
```

```bash
curl http://127.0.0.1:8010/api/health
# 检查后端健康；重点看 checks.opencode / checks.dashscope_api_key / checks.milvus

cd /home/codex/SanGraph/frontend
npm run dev -- --host 127.0.0.1 --port 5173  # 启动前端
```

## 一键启动

```bash
cd /home/codex/SanGraph
./scripts/start_full_stack.sh  # 自动安装依赖、检查 opencode、启动 Milvus、建 collection、导入 RAG、启动前后端
```

## 常用快速重启

```bash
./scripts/start_full_stack.sh --skip-install           # 跳过 uv sync 和 npm install
./scripts/start_full_stack.sh --skip-install --skip-rag-seed  # 已确认 Milvus 里有数据时，跳过 RAG 导入
```

## 命令行使用功能


### 扫描目标仓库，输出 sanitizer / validator 候选
```bash
./.venv/bin/python -m scripts.run_scan \
  --project-path /path/to/target-repo \
  --save-path other/data/scan_candidates.json
```


### 在命令行里直接分析你自己的 patch
```bash
PYTHONPATH=src ./.venv/bin/python - <<'PY'
import asyncio
import json
from base_opencode import run_analysis_with_audit

async def main():
    result = await run_analysis_with_audit(
        repo_path="/path/to/checked-out/repo",                # 可选；给了 repo_path 才能做更深上下文分析
        patch_path="/path/to/fix.patch",                      # 分析一个 patch
        audit_dir="other/artifacts/audit/my-patch-run",      # 分析产物输出目录
    )
    print(json.dumps(result["result"].model_dump(mode="json"), ensure_ascii=False, indent=2))

asyncio.run(main())
PY
```

### 在命令行里直接分析一段 sanitizer 代码
```bash
PYTHONPATH=src ./.venv/bin/python - <<'PY'
import asyncio
import json
from base_opencode import run_analysis_with_audit

SANITIZER_CODE = r'''
<?php
$out = strip_tags($_GET["x"]);
echo $out;
'''

async def main():
    result = await run_analysis_with_audit(
        sanitizer_code=SANITIZER_CODE,                       # 直接分析一段 sanitizer 代码
        audit_dir="other/artifacts/audit/my-sanitizer-run",  # 分析产物输出目录
    )
    print(json.dumps(result["result"].model_dump(mode="json"), ensure_ascii=False, indent=2))

asyncio.run(main())
PY
```

### 验证一份已有漏洞报告；依赖 opencode
```bash
./.venv/bin/python -m scripts.run_validation_report \
  --report-path /path/to/report.json \
  --repo-path /path/to/checked-out/repo
```
