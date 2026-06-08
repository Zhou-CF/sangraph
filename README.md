# SanGraph

> 接手维护、风险排查、运行核对，请优先阅读 [`docs/handover.md`](docs/handover.md)。
> 那份文档是严格的交接手册，重点写当前状态、依赖、已知问题、标准操作和维护入口；本文保留为项目总览。
> 如果你只是想把整套本地服务从 0 跑起来，请直接看 [`docs/startup.md`](docs/startup.md)。

SanGraph 是一个围绕 sanitizer / validator 防御逻辑构建的安全分析工作台。它关注的核心问题很窄，但很重要：

给定一段防御代码、一个安全补丁，或者一个疑似 sanitizer 候选，这个防御到底是否有效，还是依然可以被绕过？

当前仓库的主业务线由三个模块组成：

1. 扫描模块：在仓库里发现疑似 sanitizer / validator
2. 分析模块：判断这段防御逻辑是否仍然存在漏洞
3. 验证模块：把分析结论当作 claim，在真实仓库里做执行级验证

这三个模块既可以串成端到端流程，也可以独立使用。

## 系统定位

SanGraph 不是一个通用 SAST 扫描器，也不是一个全自动漏洞挖掘平台。

它更适合解决下面这类问题：

- 安全补丁里的 sanitizer 是否修得不彻底
- 历史漏洞的变体分析
- sanitizer 相关误报的收敛
- 针对既有漏洞报告做“是否真能复现”的证据化验证

典型问题包括：

- “这个 patch 新增了防御逻辑，但它是不是仍然能被绕过？”
- “这段代码看起来像校验逻辑，但它真的在防御攻击吗？”
- “这份报告说 sanitizer 不完整，能不能用真实执行来验证？”

## 三个主模块

### 1. 扫描模块

位置：

- `src/scanner/scan.py`

作用：

- 遍历目标仓库
- 把源码切成函数级片段
- 让 LLM 判断一段代码是否具有“安全防御意图”
- 输出疑似 sanitizer / validator 候选列表

它回答的是：

- “仓库里哪些地方值得当作防御逻辑重点看？”

需要注意：

- 这个模块目前还是偏原型化的入口
- 仓库现在内置了 `scanner.func_split` 函数切分器
- 它的输出是候选，不是最终漏洞结论

CLI 包装脚本：

- `scripts/run_scan.py`

### 2. 分析模块

位置：

- `src/base_opencode/agent.py`

作用：

- 接收 patch、直接提供的 sanitizer 代码，或扫描候选
- 提取核心防御代码
- 把防御逻辑结构化为可比较的自然语言描述
- 检索历史相似漏洞案例
- 对比当前逻辑与历史不安全模式
- 必要时结合源码上下文做更深入分析
- 产出结构化结论

它回答的是：

- “这段 sanitizer 看起来是否仍然存在真实漏洞？”

当前支持三种输入模式：

- `patch`：以安全补丁为输入
- `sanitizer_code`：直接给一段防御代码
- `scanner_candidate`：给扫描器找到的候选代码片段

它既可以：

- 独立作为分析模块使用
- 也可以作为“扫描 -> 分析 -> 验证”链路中的中间阶段

### 3. 验证模块

位置：

- `src/validation_opencode/agent.py`

作用：

- 把一份漏洞报告当作“待检验 claim”
- 检查真实仓库
- 选择合适的验证策略
- 生成 notebook、验证脚本、运行脚本
- 执行验证
- 返回基于执行证据的 verdict

它回答的是：

- “这个结论在真实仓库里到底能不能复现？”

当前 verdict 只有三类：

- `confirmed`
- `not_reproduced`
- `inconclusive`

CLI 包装脚本：

- `scripts/run_validation_report.py`

## 支撑层

这几部分不是主业务模块，但决定了整个系统能否工作。

### RAG 知识库

位置：

- `src/rag/rag_search.py`
- `src/rag/rag.py`
- `src/rag/build_rag_dataset.py`

作用：

- 把历史 sanitizer 失败案例存进 Milvus
- 按“防御逻辑文本 + 漏洞代码片段”检索相似案例
- 给分析模块提供 CVE / CWE / bypass PoC / 缺陷原因等上下文

当前检索机制包括：

- dense 向量检索
- BM25 sparse 检索
- hybrid 融合
- 可选 rerank

### LLM 工厂

位置：

- `src/llm_factory/llm_factory.py`

作用：

- 统一创建聊天模型和 embedding 模型
- 支持 DashScope、OpenAI 兼容接口、DeepSeek、Anthropic、Ollama 等

### OpenCode 集成

位置：

- `src/base_opencode/script.py`

作用：

- 通过 `opencode` CLI 做代码感知的仓库理解
- 支持 patch 提取、深度源码分析、验证阶段执行编排

## 端到端流程

推荐的完整流程是：

1. 先扫描仓库，找出疑似 sanitizer 候选
2. 选一个候选或 patch，交给分析模块判断
3. 把分析结果作为报告，再交给验证模块做执行级确认

但现实里这三个模块的耦合度并不完全一样：

- 扫描 -> 分析：逻辑上连得上，但目前还是松耦合
- 分析 -> 验证：衔接更自然
- 验证模块也可以独立验证来自系统外部的报告

## 分析模块内部流程

分析模块当前的执行逻辑大致是：

1. 先识别输入模式
   - patch
   - 直接 sanitizer 代码
   - 扫描候选
2. 如果需要，就先提取最小化核心防御代码
3. 把防御逻辑结构化成字段
   - `actions`
   - `details`
   - `logic_with_nlp`
4. 用结构化逻辑和代码去 RAG 知识库检索相似历史案例
5. 做第一轮漏洞判断
6. 再做一轮 review 复核
7. 如果复核仍认为可能是真漏洞，并且提供了 `repo_path`，就继续做更深的源码上下文分析
8. 汇总所有阶段结果，形成最终结论

所以它并不是“单次 LLM 判断”，而是一个多阶段管线：

- 提取
- 结构化
- 检索
- 差异分析
- 复核
- 可选的源码级深挖

## 验证模块内部流程

验证模块把报告当作假设，而不是事实。

大致步骤如下：

1. 读取报告内容
2. 把报告和内置验证 skill 组装成 prompt
3. 让 OpenCode 去：
   - 理解 claim
   - 检查仓库结构
   - 选择验证策略
   - 生成验证工件
   - 执行验证
4. 解析结构化 JSON 结果
5. 保存验证产物和 summary

当前支持的验证策略标签：

- `full_env`
- `native_test`
- `minimal_harness`

## 仓库结构

主线源码集中在 `src/`，非主线内容统一归档在 `other/`。

- `src/base_opencode`：分析主链路、prompt、OpenCode 封装
- `src/validation_opencode`：验证主链路和内置 skill
- `src/rag`：RAG 数据构建、Milvus schema、检索逻辑
- `src/llm_factory`：模型和 embedding 工厂
- `src/scanner`：扫描器
- `scripts`：轻量 CLI 入口
- `tests`：测试
- `other/artifacts`：分析和验证产物
- `other/data`：数据集、patch 语料、中间数据
- `other/plan`：设计文档和历史方案
- `other/milvus`：归档的外部 Milvus 目录
- `other/no`：当前不在主流程中的旁支工具
- `other/deploy`：部署相关遗留内容

## 运行依赖

最低要求通常包括：

- `uv`（执行 `uv sync` 后会按 `requires-python = "==3.13.*"` 准备 Python 环境）
- `pyproject.toml` 里的依赖已经安装到 `.venv`
- `opencode` CLI 已安装并且可在 `PATH` 中找到
- 可访问配置好的模型服务

常见的可选依赖：

- Milvus：如果要使用 RAG 检索
- DeepSeek API：如果要构建 RAG 数据集
- `tree_sitter_language_pack`：扫描模块切分函数时依赖

## 安装

如果使用 `uv`：

```bash
uv sync
```

如果直接使用仓库里的虚拟环境：

```bash
./.venv/bin/python -V
```

如果你需要 patch 提取、源码深挖、验证执行，建议安装 OpenCode：

```bash
npm install -g opencode-ai
```

## 环境变量

默认方案下，系统主要依赖 DashScope 提供聊天模型、embedding 和 rerank。

一键启动脚本会自动创建 `.env`，并在缺少 `DASHSCOPE_API_KEY` 或 `OPENCODE_MODEL` 时写入默认值；已有值不会被覆盖。

### 通用

- `DASHSCOPE_API_KEY`：默认分析链路和 RAG 检索所需
- `DASHSCOPE_CHAT_MODEL`：可选，覆盖分析模块聊天模型
- `OPENCODE_MODEL`：可选，覆盖 OpenCode 使用的模型；默认 `alibaba-cn/qwen3.7-plus`
- `SANGRAPH_LOG_LEVEL`：日志级别，默认 `INFO`
- `SANGRAPH_LOG_DIR`：日志目录，默认 `other/artifacts/logs`
- `SANGRAPH_LOG_TO_CONSOLE`：是否输出到控制台，默认 `true`
- `SANGRAPH_LOG_TO_FILE`：是否写入轮转日志文件，默认 `true`

OpenCode 默认使用 `alibaba-cn` provider，并通过临时 `opencode.json` 注入 DashScope OpenAI-compatible endpoint；token 默认复用 `DASHSCOPE_API_KEY`，无需手动执行 `opencode /connect`。

### RAG / Milvus

- `MILVUS_URI`：默认 `http://127.0.0.1:19530`
- `MILVUS_TOKEN`：默认 `root:Milvus`
- `MILVUS_COLLECTION_NAME`：默认 `sanitizer_logic`
- `RAG_ENABLE_RERANK`：默认 `true`
- `RAG_EMBED_MODEL`：可选，默认 `text-embedding-v4`
- `RAG_RERANK_MODEL`：可选，默认 `qwen3-rerank`

### RAG 数据构建

- `DEEPSEEK_API_KEY`：`rag.build_rag_dataset` 必需
- `DEEPSEEK_MODEL`：可选，默认 `deepseek-chat`
- `DEEPSEEK_BASE_URL`：可选，默认 `https://api.deepseek.com`

### 其它模型后端

`llm_factory` 还支持以下可选凭据：

- `OPENAI_API_KEY`, `OPENAI_API_BASE`
- `NEW_OPENAI_API_KEY`, `NEW_OPENAI_API_BASE`
- `MOONSHOT_API_KEY`
- `ANTHROPIC_API_KEY`
- `LOCAL_MODEL_NAME`, `LOCAL_MODEL_BASE_URL`, `LOCAL_MODEL_API_KEY`
- `R1_MODEL_NAME`, `R1_MODEL_BASE_URL`, `R1_MODEL_API_KEY`

## 快速开始

### 1. 扫描一个仓库

如果你想先拿到 sanitizer / validator 候选：

```bash
./.venv/bin/python -m scripts.run_scan \
  --project-path /path/to/target-repo \
  --save-path other/data/scan_candidates.json
```

输出：

- 一个 JSON 候选列表，包含代码片段和位置信息
- 一个同目录的调试文件 `scan_candidates.debug.jsonl`，记录入选、未入选和跳过原因

注意：

- 扫描器内置了函数切分代码，但首次使用 `tree_sitter_language_pack` 时可能需要下载 parser 资源
- 扫描结果通常还需要再筛选，或者稍作整理后再交给分析模块

### 2. 分析一段已知 sanitizer 代码

仓库里带了一个最简单的示例脚本：

```bash
./.venv/bin/python -m scripts.run_manual_sanitizer_analysis
```

这个示例会把分析产物写到：

- `other/artifacts/audit/manual-roundcube-svg`

### 3. 通过 Python API 调分析模块

目前还没有一个通用的“分析 CLI”，分析模块的主要入口是 Python API。

示例：

```python
import asyncio

from base_opencode import run_analysis_with_audit


async def main():
    result = await run_analysis_with_audit(
        repo_path="/path/to/checked-out/repo",
        patch_path="/path/to/fix.patch",
    )
    print(result["result"].model_dump(mode="json"))


asyncio.run(main())
```

运行方式：

```bash
PYTHONPATH=src ./.venv/bin/python your_script.py
```

除了 `patch_path`，你也可以直接传：

- `sanitizer_code=...`
- `candidate_code=...` 以及对应候选元数据

### 4. 验证一份报告

如果你已经有一份漏洞报告，想做执行级验证：

```bash
./.venv/bin/python -m scripts.run_validation_report \
  --report-path /path/to/report.json \
  --repo-path /path/to/checked-out/repo
```

输出：

- stdout 上的 JSON 摘要
- 默认写入 `other/artifacts/validation/...` 的验证产物

### 5. 创建 Milvus Collection

Milvus collection helper 代码目前主要在：

- `src/rag/rag.py`

但交接时需要注意：

- `src/rag/rag.py` 的导入漂移问题已经修复
- 它现在可以继续作为 Milvus collection helper / CLI 使用
- 但它仍更偏 helper 路径；如果你准备继续维护这条路径，建议先阅读 `docs/handover.md` 里的 RAG 章节，再补一轮自测后再正式使用

### 6. 构建 RAG 数据集

把原始 sanitizer 数据集转成适合入库的 RAG 结构：

```bash
PYTHONPATH=src ./.venv/bin/python -m rag.build_rag_dataset \
  --input-path other/data/verified_sanitizer_dataset.jsonl \
  --output-path other/data/verified_sanitizer_dataset.to_rag.jsonl \
  --error-path other/data/verified_sanitizer_dataset.to_rag.errors.jsonl
```

这一步需要：

- `DEEPSEEK_API_KEY`

### 7. 运行前后端分离工作台

Web 工作台由一个 FastAPI 后端和一个 React/Vite 前端组成：

- 后端代码：`src/webapp`
- 后端启动脚本：`scripts/run_webapp.py`
- 前端代码：`frontend/`

后端提供 3 类任务接口：

- `POST /api/tasks/e2e`
  - 扫描仓库
  - 将得到的 sanitizer 候选逐个送入分析
  - 只有分析结果判定 `is_vuln=true` 的 candidate，才继续进入验证
- `POST /api/tasks/analysis`
  - 仅支持两种输入：
    - `patch_path` + 可选 `repo_path`
    - `sanitizer_code` + 可选 `repo_path`
  - 若提供了 `repo_path` 且分析结果判定 `is_vuln=true`，会自动进入验证
  - 若未提供 `repo_path`，只做分析，结果中会标记 `validation_skipped=true`
  - 若分析结果判定安全，则同样会跳过验证，并标记 `skip_reason=analysis_negative`
- `POST /api/tasks/validation`
  - 对已有报告做单独验证

任务结果里的验证门控字段统一约定如下：

- `validation_attempted=true`
  - 代表已经实际进入验证阶段
- `validation_skipped=true` 且 `skip_reason=repo_path_not_provided`
  - 代表未提供 `repo_path`，因此无法验证
- `validation_skipped=true` 且 `skip_reason=analysis_negative`
  - 代表最终分析结果为安全，因此按策略跳过验证

启动后端：

```bash
PYTHONPATH=src ./.venv/bin/python -m scripts.run_webapp --host 127.0.0.1 --port 8010
```

安装并启动前端：

```bash
cd frontend
npm install
npm run dev
```

默认情况下，Vite 会把 `/api` 代理到 `http://127.0.0.1:8010`；如果启动脚本使用 `--api-port`，会通过 `VITE_API_TARGET` 自动同步代理目标。

## 主要 API

主线 API 包括：

- 分析模块
  - `base_opencode.run_analysis`
  - `base_opencode.run_analysis_with_audit`
- 验证模块
  - `validation_opencode.run_validation`
  - `validation_opencode.run_validation_with_audit`
- 检索模块
  - `rag.rag_search.search`

## 产物与输出

### 日志

默认日志会写到：

- `other/artifacts/logs/sangraph.log`

日志同时支持：

- 控制台输出
- 按大小轮转的文件输出

### 分析模块产物

默认写入：

- `other/artifacts/audit/...`

常见文件包括：

- `01_sanitizer_extraction.json`
- `02_sanitizer_logic.json`
- `03_rag_search.json`
- `04_full_analysis.json`
- `05_review_result.json`
- `06_final_result.json`
- `07_final_result.json`（只有执行了深度上下文分析才会出现）
- `audit_summary.json`

### 验证模块产物

默认写入：

- `other/artifacts/validation/...`

常见文件包括：

- `01_report_input.json`
- `02_validation_prompt.txt`
- `03_opencode_response.txt`
- `validation_summary.json`
- `workspace/`（验证脚本、notebook、run.sh 等）

## 三个模块之间的关系

这套系统最准确的理解方式是：

- 扫描模块负责“发现入口”
- 分析模块负责“给出漏洞判断”
- 验证模块负责“给出执行证据”

它们既可以串起来：

- 扫描 -> 分析 -> 验证

也可以单独使用：

- 只扫描：找候选
- 只分析：判断 patch / sanitizer 是否仍不安全
- 只验证：验证一份已有报告是否成立

这就是当前仓库的主业务架构。

## 当前限制

- 扫描器仍然偏原型化
- 目前还没有一个完整通用的分析 CLI，分析主要通过 Python API 调用
- patch 提取、深度源码分析、验证执行依赖 `opencode`
- 分析质量依赖外部 LLM / embedding 服务
- 检索效果依赖 Milvus 中历史案例语料的质量
- 验证结果高度依赖目标仓库是否可运行、可构建、可触达

## 测试

运行当前测试集：

```bash
./.venv/bin/python -m unittest discover -s tests
```

测试大致覆盖：

- 分析模块的 prompt / 路径处理
- 结构化结果解析
- RAG 格式化和 rerank fallback
- OpenCode 包装器的 fallback 逻辑
- 验证模块的 prompt 生成、产物写入和 CLI 行为

## 推荐阅读顺序

如果你想尽快理解这个系统，建议按这个顺序看代码：

1. `src/scanner/scan.py`
2. `src/base_opencode/agent.py`
3. `src/validation_opencode/agent.py`
4. `src/rag/rag_search.py`
5. `src/rag/rag.py`
6. `src/llm_factory/llm_factory.py`

如果你想看更偏设计层的说明，可以继续看：

- `other/plan/analysis_system.md`
- `other/plan/reproduction_system.md`

## 一句话理解

对 SanGraph 最短但准确的概括是：

- 扫描模块在问：“防御逻辑在哪里？”
- 分析模块在问：“这个防御是否仍然失效？”
- 验证模块在问：“这个失效能不能用真实执行证据证明？”

这就是整个系统当前的运作逻辑。
