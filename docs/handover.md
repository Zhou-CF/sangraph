# SanGraph 接手维护手册

这不是项目介绍，也不是产品说明。

这份文档只服务一个目的：把当前仓库交给下一位维护者，让对方在最短时间内知道：

- 这个仓库现在能做什么
- 哪些路径能跑，哪些路径不要默认能跑
- 第一天接手应该先验证什么
- 出问题先看哪里
- 如果要改功能，应该改哪里

如果你只是想看项目概览，请看根目录 `README.md`。
如果你只是想把本地完整服务跑起来，请看 `docs/startup.md`。
如果你要接手维护，请先读完这份文档，再开始运行或改代码。

## 1. 先给结论

### 1.1 这个仓库当前是什么

SanGraph 是一个围绕 sanitizer / validator 防御逻辑做安全分析的仓库。

当前主线能力分成三段：

1. 扫描：在目标仓库里找疑似 sanitizer / validator 候选
2. 分析：判断这段防御是否仍可能存在漏洞
3. 验证：把分析结果当作 claim，在真实仓库里生成并执行验证工件

### 1.2 当前维护判断

从仓库代码和测试来看，当前系统更接近“可运行的原型工作台”，不是“稳定上线产品”。

不要默认它已经具备下面这些能力：

- 持久化任务系统
- 一键生产部署
- 完整 RAG 运维链路
- 对所有外部依赖失效都有优雅降级

### 1.3 当前可用路径判断

建议按下面的成熟度理解仓库：

#### A. 当前最适合先验证的路径

- `scripts.run_manual_sanitizer_analysis`
- `scripts.run_scan`
- `scripts.run_validation_report`
- `scripts.run_webapp`
- `frontend/` 开发态前端

这些路径在仓库里有明确入口，且测试覆盖相对集中。

#### B. 条件可用路径

- patch 提取
- 深度源码上下文分析
- 自动验证链路

这些路径依赖 `opencode` CLI 和外部模型服务，环境不完整时会直接失效。

#### C. 不要默认稳定的路径

- `src/rag/rag.py` 中的 collection helper / CLI 路径
- 任何“可直接拿去生产部署”的假设
- Web 任务重启后恢复

这些路径在当前仓库里不是不能看，而是不能直接当成“已验证稳定能力”交给下一位。

## 2. 第一天接手必须做的事情

接手后的第一目标不是“理解所有原理”，而是确认仓库当前是否还能跑主路径。

### 2.1 第一轮检查清单

按顺序做：

1. 确认 `uv sync` 能按项目约束准备 Python `3.13.x` 环境
2. 确认依赖能通过 `uv sync` 安装
3. 确认 `DASHSCOPE_API_KEY` 已配置
4. 确认 `opencode` 是否在 `PATH` 中
5. 跑最小分析脚本
6. 起 Web 后端并打 `/api/health`
7. 如需前端，再起 `frontend` 的 Vite 开发服务器

### 2.2 成功标准

交接验收至少满足以下条件：

- `uv sync` 不报致命依赖错误
- `uv run python -m scripts.run_manual_sanitizer_analysis` 能产出结果
- `uv run python -m scripts.run_webapp` 能启动
- `GET /api/health` 返回 JSON，且依赖检查结果可读
- 前端 `npm run dev` 能启动并访问页面

### 2.3 不要第一天就做的事

不要一上来就做下面这些动作：

- 先修 RAG CLI
- 先做部署改造
- 先改 prompt
- 先排查所有 `other/` 目录归档内容

优先确认“现有主路径还能跑”，再决定修哪里。

## 3. 系统当前边界

这一节只写“职责边界”，不写长篇原理。

### 3.1 扫描模块负责什么

位置：

- `src/scanner`

负责：

- 遍历目标仓库
- 切函数 / 方法级片段
- 调 LLM 判断哪些片段有安全防御意图
- 输出候选列表和 debug 决策日志

不负责：

- 判定漏洞是否真实存在
- 给出最终安全结论
- 生成验证工件

直接入口：

- `scripts/run_scan.py`

### 3.2 分析模块负责什么

位置：

- `src/base_opencode`

负责：

- 接收 patch、直接 sanitizer 代码、或扫描候选
- 提取核心防御代码
- 结构化防御逻辑
- 调用 RAG 检索相似案例
- 产出最终分析结论

不负责：

- 完整持久化任务调度
- 真实执行级复现

直接入口：

- Python API：`base_opencode.run_analysis`
- Python API：`base_opencode.run_analysis_with_audit`
- 示例脚本：`scripts/run_manual_sanitizer_analysis.py`

### 3.3 验证模块负责什么

位置：

- `src/validation_opencode`

负责：

- 把报告当作待验证 claim
- 构造验证 prompt
- 调用 OpenCode 生成并执行验证工件
- 返回 `confirmed / not_reproduced / inconclusive`

不负责：

- 漏洞初判
- 历史案例检索

直接入口：

- Python API：`validation_opencode.run_validation`
- Python API：`validation_opencode.run_validation_with_audit`
- CLI：`scripts/run_validation_report.py`

### 3.4 Web 层负责什么

位置：

- `src/webapp`
- `frontend`

负责：

- 把扫描 / 分析 / 验证封装成异步任务接口
- 提供一个开发态工作台前端

不负责：

- 持久化任务存储
- 多实例任务一致性
- 生产环境部署编排

## 4. 当前主线事实

这一节列的是“现在代码里可以直接看出来的事实”。

### 4.1 分析输入模式

分析模块支持 3 种输入：

- `patch_path`
- `sanitizer_code`
- `candidate_code`

其中 Web API 的 `analysis` 任务只开放了两种输入：

- `patch_path`
- `sanitizer_code`

### 4.2 验证门控规则

在 Web 模式下，验证不会无条件发生。

当前逻辑是：

1. 没有 `repo_path`，则跳过验证
2. 有 `repo_path`，但分析结论 `is_vuln=false`，则跳过验证
3. 只有 `repo_path` 存在且分析结论 `is_vuln=true`，才进入验证

对应的结果字段：

- `validation_attempted`
- `validation_skipped`
- `skip_reason`

### 4.3 Web 任务状态保存方式

当前 Web 任务状态只在内存里保存。

这意味着：

- 服务重启后，旧任务不能通过 API 继续查询
- 产物目录仍会保留
- 想追旧任务只能看磁盘产物，不能依赖 API 恢复

### 4.4 运行时主要外部依赖

主路径依赖：

- DashScope 模型服务
- `opencode` CLI
- 可选 Milvus

RAG 数据构建额外依赖：

- DeepSeek API

## 5. 仓库依赖矩阵

这一节给维护者判断“缺了什么会坏哪条路径”。

### 5.1 必需依赖

#### Python 3.13

`pyproject.toml` 中写的是：

- `requires-python = "==3.13.*"`

不要把它当作“建议版本”，这是强约束；新机器上优先让 `uv sync` 下载/选择对应 Python 版本。

#### `uv`

推荐使用 `uv sync`，因为仓库已经提交：

- `pyproject.toml`
- `uv.lock`

#### `DASHSCOPE_API_KEY`

这是当前默认分析链路的核心依赖。

OpenCode 默认也复用它作为 `alibaba-cn` provider token；一键启动脚本会在 `.env` 缺失时补默认值。

缺失后，分析、OpenCode 和部分检索路径会直接失败。

### 5.2 强依赖但不属于 Python 包管理的组件

#### `opencode`

需要它的路径：

- patch 提取
- 深度上下文分析
- 验证模块
- Web 自动验证链路

如果 `opencode` 不可用，Health 检查会显示异常，验证链路基本不可用。

默认模型是 `alibaba-cn/qwen3.7-plus`，运行时通过临时 `opencode.json` 注入 provider 配置，一般不需要手动执行 `opencode /connect`。

### 5.3 可选依赖

#### Milvus

不是所有路径都必须有 Milvus。

没有 Milvus 时：

- 扫描路径仍可能工作
- 基础分析路径也可能运行
- RAG 上下文会退化

#### `DEEPSEEK_API_KEY`

只在 `src/rag/build_rag_dataset.py` 这条数据构建路径上必需。

### 5.4 当前仓库出现过的环境变量

从代码和 `.env` 看，至少涉及：

- `DASHSCOPE_API_KEY`
- `DASHSCOPE_CHAT_MODEL`
- `OPENCODE_MODEL`
- `MILVUS_URI`
- `MILVUS_TOKEN`
- `MILVUS_COLLECTION_NAME`
- `RAG_ENABLE_RERANK`
- `RAG_EMBED_MODEL`
- `RAG_RERANK_MODEL`
- `DEEPSEEK_API_KEY`
- `DEEPSEEK_MODEL`
- `DEEPSEEK_BASE_URL`
- `SANGRAPH_LOG_LEVEL`
- `SANGRAPH_LOG_DIR`
- `SANGRAPH_LOG_TO_CONSOLE`
- `SANGRAPH_LOG_TO_FILE`

## 6. 标准启动方式

这一节只列“建议交接时交给别人的标准命令”。

如果你想直接一条命令把完整本地栈拉起来，也可以优先使用：

```bash
./scripts/start_full_stack.sh
```

更完整的说明见：

- `docs/startup.md`

### 6.1 安装后端依赖

```bash
uv sync
```

### 6.2 安装前端依赖

```bash
cd frontend
npm install
```

### 6.3 安装 OpenCode CLI

```bash
npm install -g opencode-ai
```

### 6.4 最小分析验证

推荐第一条命令：

```bash
uv run python -m scripts.run_manual_sanitizer_analysis
```

这条命令的作用不是验证全系统，而是先确认：

- Python 环境能跑
- 基本分析链路能跑
- artifact 会落盘

### 6.5 扫描一个仓库

```bash
uv run python -m scripts.run_scan \
  --project-path /path/to/target-repo \
  --save-path other/data/scan_candidates.json
```

输出：

- 候选 JSON
- 对应 debug JSONL

### 6.6 验证一份报告

```bash
uv run python -m scripts.run_validation_report \
  --report-path /path/to/report.json \
  --repo-path /path/to/checked-out/repo
```

这条命令依赖 `opencode`。

### 6.7 启动 Web 后端

```bash
uv run python -m scripts.run_webapp --host 127.0.0.1 --port 8010
```

开发态自动重载：

```bash
uv run python -m scripts.run_webapp --host 127.0.0.1 --port 8010 --reload
```

### 6.8 检查后端健康状态

```bash
curl http://127.0.0.1:8010/api/health
```

重点看返回里的：

- `status`
- `checks`
- `artifact_root`

### 6.9 启动前端

```bash
cd frontend
npm run dev
```

默认前端开发地址：

- `http://127.0.0.1:5173`

当前 Vite 配置会把 `/api` 代理到：

- `http://127.0.0.1:8010`

## 7. 当前可对外说明的接口

这一节不是 API 教程，只列接手人必须知道的对外入口。

### 7.1 CLI 入口

- `scripts.run_manual_sanitizer_analysis`
- `scripts.run_scan`
- `scripts.run_validation_report`
- `scripts.run_webapp`

### 7.2 Web API

- `GET /api/health`
- `POST /api/tasks/e2e`
- `POST /api/tasks/analysis`
- `POST /api/tasks/validation`
- `GET /api/tasks/{task_id}`
- `GET /api/tasks/{task_id}/result`

### 7.3 Web 输入约束

#### `POST /api/tasks/analysis`

当前只接受两种输入模式之一：

- `patch_path`
- `sanitizer_code`

二者必须二选一。

#### `POST /api/tasks/validation`

必须提供：

- `report_path`
- `repo_path`

#### `POST /api/tasks/e2e`

必须提供：

- `repo_path`

## 8. 产物位置和排查入口

接手时最常见的问题不是“没有输出”，而是“输出写在哪了”。

### 8.1 日志

默认日志目录：

- `other/artifacts/logs`

默认日志文件：

- `other/artifacts/logs/sangraph.log`

日志配置位置：

- `src/sangraph_logging/config.py`

### 8.2 分析产物

默认目录：

- `other/artifacts/audit`

常见文件：

- `01_sanitizer_extraction.json`
- `02_sanitizer_logic.json`
- `03_rag_search.json`
- `04_full_analysis.json`
- `05_review_result.json`
- `06_final_result.json`
- `07_final_result.json`
- `audit_summary.json`

### 8.3 验证产物

默认目录：

- `other/artifacts/validation`

常见文件：

- `01_report_input.json`
- `02_validation_prompt.txt`
- `03_opencode_response.txt`
- `03_opencode_raw_stdout.txt`
- `03_opencode_raw_stderr.txt`
- `validation_summary.json`
- `workspace/`

### 8.4 Web 任务产物

默认目录：

- `other/artifacts/web/<task_id>/`

这部分对排障非常重要，因为：

- API 状态会丢
- 文件产物不会自动丢

### 8.5 出问题先看哪里

#### 分析失败

先看：

- `other/artifacts/audit/.../audit_summary.json`
- `other/artifacts/logs/sangraph.log`

#### 验证失败

先看：

- `other/artifacts/validation/.../validation_summary.json`
- `03_opencode_raw_stdout.txt`
- `03_opencode_raw_stderr.txt`

#### Web 任务异常

先看：

- `/api/health`
- `other/artifacts/web/<task_id>/`
- 后端日志

## 9. 已知问题和技术债

这一节是交接重点。

### 9.1 `opencode` 是单点依赖

当前实现里：

- patch 提取依赖它
- 深度上下文分析依赖它
- 验证依赖它

所以“安装不了 `opencode`”不是小问题，而是主链路阻断。

### 9.2 Web 任务没有持久化

当前实现没有数据库、没有消息队列、没有持久化任务表。

直接后果：

- 后端重启后任务状态丢失
- 不能把当前实现当作长期运行的任务服务

### 9.3 `src/rag/rag.py` 的导入漂移已修复，但它仍是 helper 路径

之前这里出现过一个明确问题：

- `src/rag/rag.py` 引用了 `get_cross_encoder_model`
- `src/rag/config.py` 当时没有这个定义

现在这处导入漂移已经修掉，`python -m rag.rag ...` 可以继续作为 collection helper / CLI 使用。

但交接时仍建议注意：

- `src/rag/rag.py` 更偏 Milvus 运维 helper，不是主业务最稳定入口
- 真正分析链路更依赖 `src/rag/rag_search.py`
- 如果要继续维护 `rag.py` 这条路径，仍建议先补自测再正式使用

### 9.4 `other/` 目录里有大量归档 / 历史内容

不要默认：

- `other/milvus`
- `other/deploy`
- `other/plan`

里的每个文件都还在主流程使用。

当前最安全的做法是：

- 先以 `src/` 与 `scripts/` 为准
- 再把 `other/` 当作参考或归档

### 9.5 结果质量受外部模型影响很大

这是一个工程化 LLM 系统，不是纯 deterministic 工具。

会影响结果的因素包括：

- 模型供应商切换
- Prompt 调整
- Milvus 语料质量
- rerank 开关

交接时要明确告诉下一位：

- 结果波动不一定是代码逻辑错误，也可能是外部模型和数据问题

### 9.6 当前没有仓库内可直接确认的生产部署方案

仓库内能看到前后端开发态运行方式，但不能从代码直接确认：

- 正式部署是否存在
- 线上如何托管前端
- Milvus 线上怎么部署
- 模型调用是否走代理或网关

这些信息需要人工补充，不要靠猜。

## 10. 如果要改功能，先看哪里

这一节用于快速定位代码入口。

### 10.1 改扫描规则

看：

- `src/scanner/scan.py`
- `src/scanner/func_split.py`

通常涉及：

- 文件过滤
- 候选判断 prompt
- 函数切分逻辑
- 上下文增强策略

### 10.2 改分析行为

看：

- `src/base_opencode/agent.py`
- `src/base_opencode/llm_struct.py`
- `src/base_opencode/prompt/`

通常涉及：

- 输入模式
- sanitizer 提取
- 逻辑结构化
- 初判 / review / deep analysis

### 10.3 改验证策略

看：

- `src/validation_opencode/agent.py`
- `src/validation_opencode/skills/vuln-verification/SKILL.md`
- `src/validation_opencode/skills/vuln-verification/references/verification-rules.md`

### 10.4 改模型后端

看：

- `src/llm_factory/llm_factory.py`

### 10.5 改 Web 行为

看：

- `src/webapp/service.py`
- `src/webapp/models.py`
- `src/webapp/app.py`
- `frontend/src/App.jsx`

## 11. 推荐阅读顺序

如果你是维护者，建议这样看：

1. `src/webapp/service.py`
2. `src/base_opencode/agent.py`
3. `src/validation_opencode/agent.py`
4. `src/scanner/scan.py`
5. `src/scanner/func_split.py`
6. `src/rag/rag_search.py`
7. `src/llm_factory/llm_factory.py`

理由很简单：

- 先看系统怎么串
- 再看核心分析
- 再看验证
- 最后补扫描、RAG 和模型层

## 12. 这次交接仍然缺什么信息

下面这些信息无法从当前仓库直接确认，应该由当前维护者人工补充：

### 12.1 外部系统信息

- 当前实际使用的 DashScope 模型名
- 是否使用了代理 / 网关 / OpenAI-compatible 中转
- Milvus 实际部署位置
- 是否存在共享测试仓库或固定验证样例

### 12.2 运维信息

- 是否有线上环境
- 是否有 CI
- 是否有固定发布流程
- 是否有前端构建产物托管方式

### 12.3 责任信息

- 谁维护 Milvus
- 谁维护模型凭据
- 谁维护 `opencode` 使用方式
- 哪个目录是历史归档，哪个目录仍在生产使用

如果这些信息补不上，就不要在交接口径里把它们说成“已知事实”。

## 13. 给下一位维护者的一段直话

这个仓库现在最适合这样接手：

- 先把主路径跑起来
- 再决定修哪条链路
- 不要先做大重构
- 不要默认所有归档代码仍在使用
- 不要默认 Web 层已经具备生产条件
- 不要默认 RAG CLI 已经是稳定入口

先把这些判断立住，再去理解细节，会少走很多弯路。
