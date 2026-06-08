# SanGraph 完整启动指南

这份文档面向“第一次把项目完整跑起来”的场景。

如果你只想了解项目整体情况，请先看根目录 `README.md`。
如果你要接手维护，请再结合 `docs/handover.md` 一起看。

## 1. 这份文档解决什么问题

这里默认你希望把下面这些部分一起启动起来：

- Milvus
- RAG collection
- 后端 FastAPI API
- 前端 Vite 开发服务器
- `opencode` CLI 依赖链路

也就是说，这不是“只把页面点亮”的最小启动，而是“尽量把主链路依赖也带上”的完整本地开发启动。

## 2. 前置条件

建议先确认这些依赖已经可用：

- `uv`（会在 `uv sync` 时按项目约束准备 Python `3.13.x` 环境）
- Node.js / `npm`
- Docker + `docker compose`
- `curl`

仓库对 Python 版本是强约束：

- `pyproject.toml` 中写的是 `requires-python = "==3.13.*"`
- 不需要系统预装 Python `3.13.x`；只要 `uv` 可以下载/选择对应版本即可

## 3. 环境变量

一键启动脚本会在 `.env` 不存在时自动创建默认文件；如果 `.env` 已存在但缺少 `DASHSCOPE_API_KEY` 或 `OPENCODE_MODEL`，脚本会追加默认值。已有值不会被覆盖。

至少建议准备这些变量：

```dotenv
DASHSCOPE_API_KEY=your_key
OPENCODE_MODEL=alibaba-cn/qwen3.7-plus
DEEPSEEK_API_KEY=your_key
MILVUS_URI=http://127.0.0.1:19530
MILVUS_TOKEN=root:Milvus
MILVUS_COLLECTION_NAME=sanitizer_logic
```

说明：

- `DASHSCOPE_API_KEY`：分析链路、embedding、RAG 检索都可能用到
- `OPENCODE_MODEL`：OpenCode CLI 使用的模型，默认 `alibaba-cn/qwen3.7-plus`
- `DEEPSEEK_API_KEY`：只有在你要重建 `to_rag` 数据集时才必须
- `MILVUS_*`：不写也有默认值，但建议显式写清楚

OpenCode 默认使用 `alibaba-cn` provider，token 复用 `DASHSCOPE_API_KEY`，脚本会通过临时 `opencode.json` 注入配置。

注意：

- `.env` 最好统一写成 `KEY=value`，不要写成 `KEY = value`
- Python 侧很多模块会自己调用 `load_dotenv`，所以后端和脚本都能读取 `.env`

## 4. 一键启动

仓库里提供了一个一键启动脚本：

```bash
./scripts/start_full_stack.sh
```

它会按顺序做这些事情：

1. 用 `uv sync` 同步 Python 依赖
2. 用 `npm install` 安装前端依赖
3. 检查 `opencode`；缺失时尝试 `npm install -g opencode-ai`
4. 用 Docker Compose 启动 Milvus
5. 创建 `sanitizer_logic` collection
6. 当 collection 为空时，自动导入 `other/data/verified_sanitizer_dataset.to_rag.jsonl`
7. 启动后端 `http://127.0.0.1:8010`
8. 启动前端 `http://127.0.0.1:5173`

### 4.1 首次启动会更慢

首次启动时，如果 Milvus collection 为空，脚本会自动导入 RAG 数据。

这里要注意：

- 仓库里的 `other/data/verified_sanitizer_dataset.to_rag.jsonl` 只是结构化数据
- 真正导入 Milvus 时，脚本还会调用 embedding 生成向量
- 所以第一次导入会明显慢一些，也会消耗 DashScope 配额

为了避免你每次重启都重复导入，脚本会先检查 collection 的 `row_count`：

- 如果 collection 里已经有数据，就跳过导入
- 只有在 collection 为空时才做自动播种

### 4.2 常用参数

只在第一次完整初始化后，想更快重新启动时：

```bash
./scripts/start_full_stack.sh --skip-install
```

如果你只想起服务，不想自动导入 RAG 数据：

```bash
./scripts/start_full_stack.sh --skip-rag-seed
```

如果你想先重建 `to_rag` 数据集，再导入 Milvus：

```bash
./scripts/start_full_stack.sh --rebuild-rag-data
```

如果你想临时换后端端口，前端代理会跟随：

```bash
./scripts/start_full_stack.sh --api-port 8020
SANGRAPH_API_PORT=8020 ./scripts/start_full_stack.sh
```

查看全部参数：

```bash
./scripts/start_full_stack.sh --help
```

### 4.3 停止方式

- 前端和后端由脚本一起托管
- 在脚本所在终端按 `Ctrl-C`，脚本会停止后端进程
- Milvus 容器不会自动删除；如果你要停掉 Milvus：

```bash
cd other/deploy/milvus
docker compose down
```

## 5. 手动完整启动命令

如果你不想用脚本，也可以手动按下面的顺序启动。

### 5.1 进入仓库

```bash
cd /home/codex/SanGraph
```

### 5.2 安装后端依赖

```bash
uv sync
```

### 5.3 安装前端依赖

```bash
cd frontend
npm install
cd ..
```

### 5.4 安装 OpenCode CLI

```bash
npm install -g opencode-ai
```

### 5.5 启动 Milvus

```bash
cd other/deploy/milvus
docker compose up -d
docker compose ps
curl http://127.0.0.1:9091/healthz
cd /home/codex/SanGraph
```

### 5.6 创建 collection

```bash
PYTHONPATH=src ./.venv/bin/python -m rag.rag create-collection --collection-name sanitizer_logic
```

可选查看 collection 描述：

```bash
PYTHONPATH=src ./.venv/bin/python -m rag.rag describe-collection --collection-name sanitizer_logic
```

### 5.7 导入仓库自带的 RAG 数据

```bash
PYTHONPATH=src ./.venv/bin/python - <<'PY'
from rag.test_milvus import upload_from_to_rag_jsonl

upload_from_to_rag_jsonl(
    jsonl_path="other/data/verified_sanitizer_dataset.to_rag.jsonl",
    collection_name="sanitizer_logic",
    limit=0,
)
PY
```

### 5.8 如果你要重建 RAG 数据集

```bash
PYTHONPATH=src ./.venv/bin/python -m rag.build_rag_dataset \
  --input-path other/data/verified_sanitizer_dataset.jsonl \
  --output-path other/data/verified_sanitizer_dataset.to_rag.jsonl \
  --error-path other/data/verified_sanitizer_dataset.to_rag.errors.jsonl
```

跑完后，再执行上一节的导入命令。

### 5.9 启动后端

```bash
PYTHONPATH=src ./.venv/bin/python -m scripts.run_webapp --host 127.0.0.1 --port 8010 --reload
```

### 5.10 检查后端健康状态

```bash
curl http://127.0.0.1:8010/api/health
```

重点看返回里的：

- `status`
- `checks.opencode`
- `checks.dashscope_api_key`
- `checks.milvus`
- `artifact_root`

### 5.11 启动前端

```bash
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

打开：

- `http://127.0.0.1:5173`

## 6. 推荐的冒烟验证

### 6.1 检查后端健康

```bash
curl http://127.0.0.1:8010/api/health
```

### 6.2 最小分析验证

```bash
./.venv/bin/python -m scripts.run_manual_sanitizer_analysis
```

成功后，一般会在这里看到分析产物：

- `other/artifacts/audit/manual-roundcube-svg`

### 6.3 Web API 最小验证

```bash
curl -X POST http://127.0.0.1:8010/api/tasks/analysis \
  -H 'Content-Type: application/json' \
  -d '{"sanitizer_code":"<?php echo strip_tags($_GET[\"x\"]); ?>"}'
```

记下返回的 `task_id` 后，再查状态：

```bash
curl http://127.0.0.1:8010/api/tasks/<task_id>
```

查最终结果：

```bash
curl http://127.0.0.1:8010/api/tasks/<task_id>/result
```

## 7. 常见问题

### 7.1 后端能起，但健康检查是 `degraded`

常见原因：

- `opencode` 不在 `PATH`
- `DASHSCOPE_API_KEY` 缺失
- Milvus 没起来，或 `MILVUS_URI` 配置错了

这时服务未必完全起不来，但主链路会退化。

### 7.2 每次启动都很慢

优先确认是不是每次都在重新导入 RAG 数据。

脚本默认会在 collection 已有数据时跳过导入；如果你手动清空了 Milvus volume 或 drop 了 collection，就会再次触发首轮播种。

### 7.3 我只想快点重启本地服务

推荐：

```bash
./scripts/start_full_stack.sh --skip-install
```

如果你已经确认 Milvus 里有数据，还可以配合：

```bash
./scripts/start_full_stack.sh --skip-install --skip-rag-seed
```
