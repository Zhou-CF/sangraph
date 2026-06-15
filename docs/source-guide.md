# SanGraph 源码说明

## 1. 文档概述

本文档说明 SanGraph 仓库的源码组织方式、模块职责以及主要文件的功能定位，供维护、调试和二次开发时参考。

适用读者包括：

- 项目维护者
- 参与后续开发的工程人员
- 需要理解系统结构和调用关系的使用者

相关文档：

- 项目总览：`README.md`
- 维护交接说明：`docs/handover.md`
- 环境启动说明：`docs/startup.md`

本文档的覆盖范围包括：

- 后端核心源码目录：`src`
- 运行入口目录：`scripts`
- 前端源码目录：`frontend/src`
- 测试目录：`tests`
- 支撑性数据与部署目录：`other/data`、`other/deploy`、`other/plan`、`other/no`

本文档不对以下内容进行逐文件源码说明，仅在必要时标注其用途：

- 第三方依赖目录，如 `frontend/node_modules`
- 构建产物目录，如 `frontend/dist`
- 缓存与解释器产物，如 `__pycache__`、`.cache`
- 打包元数据目录，如 `src/sanitizer.egg-info`
- 运行期输出目录，如 `other/artifacts/logs`、`other/artifacts/run`

## 2. 系统总体架构

SanGraph 的核心流程由三个业务阶段构成：

1. 扫描阶段：在目标仓库中识别疑似 sanitizer / validator 候选
2. 分析阶段：对候选代码、防御代码或安全补丁进行漏洞分析
3. 验证阶段：依据分析结论在真实仓库中执行复现验证

与上述流程配套的支撑模块包括：

- `rag`：提供历史案例检索能力，为分析阶段补充相似漏洞上下文
- `llm_factory`：统一创建聊天模型与 embedding 模型
- `webapp`：将扫描、分析和验证封装为 FastAPI 异步任务接口
- `frontend`：提供开发态工作台前端
- `sangraph_logging`：提供统一日志配置与日志访问接口

模块调用关系可概括如下：

```text
scripts/* 或 Web API
        |
        +--> scanner
        +--> base_opencode --> rag
        +--> validation_opencode --> OpenCode CLI
        |
        +--> llm_factory
        +--> sangraph_logging
```

## 3. 仓库目录结构

### 3.1 根目录

- `README.md`
  - 项目总览文档，说明系统定位、核心流程和主要使用方式
- `pyproject.toml`
  - Python 项目配置文件，定义包信息、依赖和 Python 版本约束

### 3.2 `docs/`

`docs/` 目录存放项目说明文档。

- `startup.md`
  - 本地完整启动说明
- `handover.md`
  - 面向维护者的交接说明
- `OPT.md`
  - 手动安装、Milvus 初始化及常用命令说明
- `source-guide.md`
  - 当前源码说明文档

### 3.3 `src/`

`src/` 目录包含后端核心源码和业务实现。

### 3.4 `scripts/`

`scripts/` 目录包含命令行入口和本地运行辅助脚本。

### 3.5 `frontend/`

`frontend/` 目录包含前端工程、前端源码和前端构建产物。

### 3.6 `tests/`

`tests/` 目录包含后端模块、脚本入口和 Web 层的测试代码。

### 3.7 `other/`

`other/` 目录包含运行产物、数据资产、部署配置、交接材料和附属工具。

## 4. 核心源码目录说明

### 4.1 `src/base_opencode`

`base_opencode` 为分析模块实现目录，负责对补丁、候选代码或直接提供的防御代码执行多阶段漏洞分析。

关键入口：

- `base_opencode.run_analysis`
- `base_opencode.run_analysis_with_audit`

文件说明：

- `__init__.py`
  - 对外暴露分析模块的公共调用接口
- `agent.py`
  - 实现分析主流程，包括输入归一化、状态流转、RAG 检索、复核、深度分析和审计输出
- `script.py`
  - 提供 OpenCode CLI 的 Python 封装，用于提交提示词、解析事件流并获取结构化响应
- `llm_struct.py`
  - 定义分析阶段使用的结构化模型，包括 sanitizer 逻辑、分析结论、复核结果、深度分析结果和最终输出结构

### 4.2 `src/validation_opencode`

`validation_opencode` 为验证模块实现目录，负责根据分析报告在目标仓库中生成验证工件并执行复现验证。

关键入口：

- `validation_opencode.run_validation`
- `validation_opencode.run_validation_with_audit`

文件说明：

- `__init__.py`
  - 对外暴露验证模块的公共调用接口
- `agent.py`
  - 实现验证主流程，包括报告读取、验证提示词构造、OpenCode 调用、结果解析和审计输出
- `llm_struct.py`
  - 定义验证阶段使用的结构化模型，包括验证策略、验证结论、工件路径和执行命令

### 4.3 `src/scanner`

`scanner` 为扫描模块实现目录，负责从目标仓库中发现疑似 sanitizer / validator 候选。

关键入口：

- `scanner.scan.main`

文件说明：

- `__init__.py`
  - 对外暴露扫描入口、默认输出路径和调试输出路径辅助接口
- `scan.py`
  - 实现扫描主流程，包括文件遍历、候选切分、LLM 判定、结果输出和调试记录输出
- `func_split.py`
  - 基于 tree-sitter 实现函数 / 方法级代码切分，并为候选片段补充部分上下文定义
- `parsers.py`
  - 维护文件扩展名与 tree-sitter 语言标识之间的映射关系

### 4.4 `src/rag`

`rag` 为历史案例检索支撑目录，负责 Milvus 检索、集合辅助能力和数据构建逻辑。

关键入口：

- `rag.rag_search`

文件说明：

- `__init__.py`
  - 包初始化文件
- `build_rag_dataset.py`
  - 提供 RAG 数据集构建逻辑
- `config.py`
  - 提供 RAG 相关配置，包括 Milvus 连接参数、embedding 模型和 rerank 模型
- `rag.py`
  - 提供 Milvus collection、schema、索引和数据导入等辅助能力
- `rag_search.py`
  - 提供分析阶段实际使用的检索入口，实现 dense、BM25 sparse、hybrid 和可选 rerank
- `test_milvus.py`
  - 提供 Milvus 连接、导入和试验性验证脚本

说明：

- `rag_search.py` 和 `config.py` 构成当前分析主流程中的主要检索调用面
- `rag.py` 主要提供集合与导入辅助能力，不属于每次分析的必经路径

### 4.5 `src/llm_factory`

`llm_factory` 为模型创建与模型接入目录，负责统一构造聊天模型和 embedding 模型。

文件说明：

- `__init__.py`
  - 对外暴露模型工厂与 embedding 工厂接口
- `llm_factory.py`
  - 提供当前主流程使用的模型工厂实现，支持 DashScope、OpenAI 兼容接口、DeepSeek、Anthropic、Ollama 等模型接入
- `client.py`
  - 提供一组基于 LangChain Agent 的客户端封装
- `agent_factory.py`
  - 提供基于 MCP 的 agent 组装逻辑
- `llm_script.py`
  - 提供附属的 LLM 脚本逻辑
- `llm_struct.py`
  - 定义与上述附属逻辑配套的结构化输出模型

说明：

- `llm_factory.py` 构成当前业务主流程的模型创建入口
- `client.py`、`agent_factory.py`、`llm_script.py` 和 `llm_struct.py` 依赖当前仓库中未提供的 `utils.*` 模块，未出现在现有主流程调用链中
- 如需维护或清理上述文件，应先确认其是否仍有外部使用方或历史兼容需求

### 4.6 `src/webapp`

`webapp` 为后端 Web 层实现目录，负责将扫描、分析和验证封装为异步任务接口。

关键入口：

- `webapp.app:create_app`
- `webapp.service.WebTaskService`

文件说明：

- `__init__.py`
  - 包初始化文件
- `app.py`
  - 提供 FastAPI 应用和 HTTP 路由定义，包括健康检查、任务创建、状态查询、结果查询和日志包下载接口
- `models.py`
  - 定义 Web API 的请求 / 响应模型、任务状态模型和健康检查模型
- `service.py`
  - 实现任务编排、状态维护、扫描 / 分析 / 验证调用以及日志包生成逻辑

### 4.7 `src/sangraph_logging`

`sangraph_logging` 为统一日志目录，负责日志初始化、日志路径管理和 logger 获取。

文件说明：

- `__init__.py`
  - 对外暴露日志目录、日志文件名、日志配置和 logger 获取接口
- `config.py`
  - 实现日志配置逻辑，包括控制台日志、滚动文件日志、环境变量读取和 `uvicorn` 日志接管

### 4.8 `src/sanitizer.egg-info`

`sanitizer.egg-info` 为打包生成的元数据目录，不属于人工维护的业务源码。

典型文件包括：

- `PKG-INFO`
- `SOURCES.txt`
- `requires.txt`
- `top_level.txt`

上述文件用于记录包元数据、依赖信息和打包文件清单。

## 5. 运行入口说明

### 5.1 `scripts/`

`scripts/` 目录提供本地运行和调试主流程所需的命令行入口。

文件说明：

- `__init__.py`
  - 包初始化文件
- `run_manual_sanitizer_analysis.py`
  - 提供分析模块的手工示例脚本，通过内置 sanitizer 代码调用 `base_opencode.run_analysis_with_audit`
- `run_scan.py`
  - 提供扫描命令行入口，解析目标仓库路径、结果输出路径和调试输出路径
- `run_validation_report.py`
  - 提供验证命令行入口，解析报告路径、目标仓库路径和验证审计目录
- `run_webapp.py`
  - 提供后端 FastAPI 服务启动入口
- `start_full_stack.sh`
  - 提供本地全链路启动脚本，负责依赖安装、OpenCode 检查、Milvus 启动、RAG 数据播种和前后端联启

常用入口包括：

- `python -m scripts.run_scan`
- `python -m scripts.run_validation_report`
- `python -m scripts.run_webapp`

## 6. 前端源码说明

### 6.1 `frontend/`

`frontend/` 目录包含开发态工作台前端工程。

顶层文件和目录说明：

- `package.json`
  - 定义前端依赖和运行脚本
- `src/`
  - 包含人工维护的前端源码
- `dist/`
  - 包含前端构建产物
- `node_modules/`
  - 包含第三方依赖

### 6.2 `frontend/src/`

文件说明：

- `main.jsx`
  - 提供 React 应用挂载入口
- `App.jsx`
  - 实现前端主界面逻辑，包括任务提交、状态轮询、结果展示和日志包下载
- `styles.css`
  - 定义页面样式

## 7. 测试结构说明

`tests/` 目录按模块划分测试文件，主要用于验证后端主流程、脚本入口和 Web 接口行为。

文件说明：

- `test_base_opencode_agent.py`
  - 验证分析模块主流程行为
- `test_validation_opencode_agent.py`
  - 验证验证模块主流程和验证 CLI 行为
- `test_scanner_func_split.py`
  - 验证扫描切分逻辑和扫描输出行为
- `test_rag_module.py`
  - 验证 RAG 相关模块行为
- `test_opencode_script.py`
  - 验证 OpenCode Python 包装器行为
- `test_sangraph_logging.py`
  - 验证日志配置和日志输出行为
- `test_run_webapp.py`
  - 验证 Web 启动脚本参数解析与 `uvicorn` 调用行为
- `test_webapp_app.py`
  - 验证 FastAPI 路由层行为
- `test_webapp_service.py`
  - 验证 Web 任务编排与任务状态流转行为

测试目录可用于建立以下映射关系：

- 分析模块对应 `test_base_opencode_agent.py`
- 验证模块对应 `test_validation_opencode_agent.py`
- 扫描模块对应 `test_scanner_func_split.py`
- Web 接口对应 `test_webapp_app.py` 与 `test_webapp_service.py`

## 8. 支撑资产目录说明

### 8.1 `other/artifacts`

`other/artifacts` 为运行期产物目录，不属于主线源码目录。

典型子目录包括：

- `audit/`
  - 分析阶段审计输出目录
- `validation/`
  - 验证阶段审计输出目录
- `web/`
  - Web 任务输出目录
- `logs/`
  - 统一日志输出目录
- `run/`
  - 运行期输出目录

该目录中的具体文件通常为历史运行产物，不作为业务源码维护对象。

### 8.2 `other/data`

`other/data` 为数据资产目录，包含历史补丁样本、结构化样本数据和 RAG 数据输入。

典型内容包括：

- `patch/`
  - 历史漏洞补丁样本
- `verified_sanitizer_dataset.jsonl`
  - 已整理的 sanitizer 样本数据
- `verified_sanitizer_dataset.regex_strict.jsonl`
  - 更严格筛选后的样本版本
- `verified_sanitizer_dataset.regex_strict.summary.json`
  - 严格筛选版本的汇总统计
- `verified_sanitizer_dataset.to_rag.jsonl`
  - 可直接用于 RAG 导入的结构化数据
- `finetune_data.jsonl`
  - 训练或微调相关数据
- `test.json`
  - 示例输出或调试数据

### 8.3 `other/deploy`

`other/deploy` 为外部依赖部署示例目录。

#### `other/deploy/milvus`

- `docker-compose.yml`
  - 提供本地 Milvus 服务启动编排
- `milvus.yaml`
  - 提供 Milvus 配置文件
- `.gitignore`
  - 提供部署目录的忽略规则

### 8.4 `other/plan`

`other/plan` 为交接与背景材料目录，不属于业务代码目录。

典型文件包括：

- `analysis_system.md`
  - 分析系统说明材料
- `rag_milvus_handoff.md`
  - RAG / Milvus 交接材料
- `reproduction_system.md`
  - 验证或复现系统说明材料

### 8.5 `other/no`

`other/no` 为附属的非向量 sanitizer 案例检索工具目录，与 Milvus 主检索链路并列存在，但未集成到当前主分析流程。

文件说明：

- `__init__.py`
  - 对外暴露索引构建与搜索接口
- `__main__.py`
  - 提供 `python -m other.no` 模块入口
- `cli.py`
  - 提供命令行入口，包括 `build` 和 `search` 子命令
- `builder.py`
  - 提供 SQLite FTS5 索引构建逻辑
- `search.py`
  - 提供基于 SQLite FTS5 的检索与结果重排逻辑
- `models.py`
  - 定义工具使用的数据模型
- `constants.py`
  - 定义词表、模式、标签与 schema 版本常量

## 9. 主要调用入口

当前对外可见的主要调用入口如下：

- 分析接口
  - `base_opencode.run_analysis`
  - `base_opencode.run_analysis_with_audit`
- 验证接口
  - `validation_opencode.run_validation`
  - `validation_opencode.run_validation_with_audit`
- 扫描入口
  - `scanner.scan.main`
- Web 入口
  - `webapp.app:create_app`
- 脚本入口
  - `scripts.run_scan`
  - `scripts.run_analysis`
  - `scripts.run_validation_report`
  - `scripts.run_webapp`

### 9.1 命令行运行命令

以下命令用于直接调用当前主流程入口。

说明：

- 当前仓库提供独立的扫描、分析和验证 CLI。
- `scripts.run_manual_sanitizer_analysis` 保留为分析模块示例脚本，不作为通用分析入口。

扫描目标仓库：

```bash
uv run python -m scripts.run_scan \
  --project-path /path/to/target-repo \
  --save-path other/data/scan_candidates.json
```

如需同时输出扫描调试记录：

```bash
uv run python -m scripts.run_scan \
  --project-path /path/to/target-repo \
  --save-path other/data/scan_candidates.json \
  --debug-save-path other/data/scan_candidates.debug.jsonl
```

执行手工分析示例：

```bash
uv run python -m scripts.run_manual_sanitizer_analysis
```

分析补丁：

```bash
uv run python -m scripts.run_analysis \
  --patch-path /path/to/fix.patch \
  --repo-path /path/to/target-repo
```

分析直接提供的防御代码：

```bash
uv run python -m scripts.run_analysis \
  --sanitizer-code "value = value.replace('<script>', '')"
```

分析防御代码文件：

```bash
uv run python -m scripts.run_analysis \
  --sanitizer-code-file /path/to/sanitizer.txt \
  --analysis-profile enhanced_search
```

验证漏洞报告：

```bash
uv run python -m scripts.run_validation_report \
  --report-path /path/to/report.json \
  --repo-path /path/to/target-repo
```

如需指定验证审计输出目录：

```bash
uv run python -m scripts.run_validation_report \
  --report-path /path/to/report.json \
  --repo-path /path/to/target-repo \
  --audit-dir other/artifacts/validation/custom-run
```

启动后端 Web 服务：

```bash
uv run python -m scripts.run_webapp --host 127.0.0.1 --port 8010
```

开发模式启动后端 Web 服务：

```bash
uv run python -m scripts.run_webapp --host 127.0.0.1 --port 8010 --reload
```

启动前端开发服务器：

```bash
cd frontend
npm run dev
```

执行本地全链路启动脚本：

```bash
./scripts/start_full_stack.sh
```

### 9.2 Python 调用示例

以下示例用于直接调用 Python API，而不经过命令行脚本。

调用分析接口：

```python
import asyncio
from base_opencode import run_analysis_with_audit

async def main():
    result = await run_analysis_with_audit(
        repo_path="/path/to/target-repo",
        patch_path="/path/to/fix.patch",
        audit_dir="other/artifacts/audit/custom-run",
    )
    print(result["result"].model_dump(mode="json"))

asyncio.run(main())
```

调用验证接口：

```python
import asyncio
from validation_opencode import run_validation_with_audit

async def main():
    result = await run_validation_with_audit(
        report_path="/path/to/report.json",
        repo_path="/path/to/target-repo",
        audit_dir="other/artifacts/validation/custom-run",
    )
    print(result["result"].model_dump(mode="json"))

asyncio.run(main())
```

### 9.3 Web 接口访问入口

启动后端服务后，可通过以下 HTTP 接口访问 Web 层入口：

- `GET /api/health`
  - 返回依赖检查结果和服务状态
- `POST /api/tasks/e2e`
  - 提交端到端任务
- `POST /api/tasks/analysis`
  - 提交分析任务
- `POST /api/tasks/validation`
  - 提交验证任务
- `GET /api/tasks/{task_id}`
  - 查询任务状态
- `GET /api/tasks/{task_id}/result`
  - 查询任务结果
- `GET /api/tasks/{task_id}/log-bundle`
  - 下载任务日志包

## 10. 维护边界

从维护视角出发，可将仓库内容划分为以下三类：

### 10.1 主线实现目录

以下目录构成当前主要业务实现路径：

- `src/base_opencode`
- `src/validation_opencode`
- `src/scanner`
- `src/rag`
- `src/webapp`
- `src/sangraph_logging`
- `scripts`

### 10.2 支撑性目录

以下目录提供数据、部署、交接材料或附属工具支持：

- `frontend/src`
- `tests`
- `other/data`
- `other/deploy`
- `other/plan`
- `other/no`

### 10.3 非源码维护对象

以下目录或文件通常不作为人工维护的源码对象：

- `frontend/node_modules`
- `frontend/dist`
- `src/sanitizer.egg-info`
- `__pycache__`
- `.cache`
- `other/artifacts/*`

## 11. 阅读建议

如需理解系统主流程，建议优先阅读以下路径：

1. `README.md`
2. `docs/handover.md`
3. `scripts/run_webapp.py`
4. `src/webapp/app.py`
5. `src/webapp/service.py`
6. `src/base_opencode/agent.py`
7. `src/validation_opencode/agent.py`
8. `src/scanner/scan.py`
9. `src/rag/rag_search.py`

如需排查分析质量相关问题，建议重点关注以下文件：

- `src/base_opencode/agent.py`
- `src/base_opencode/llm_struct.py`
- `src/rag/rag_search.py`
- `src/rag/config.py`
- `src/llm_factory/llm_factory.py`
