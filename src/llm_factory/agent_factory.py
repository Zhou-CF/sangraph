import sys
from contextlib import asynccontextmanager, AsyncExitStack
from typing import AsyncGenerator
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.tools import load_mcp_tools
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import PromptTemplate
import os
import logging
from pathlib import Path


from .client import Agent 
from .llm_factory import llm_factory
from utils.constant import evaluation_path
from utils.file_management import ContextManager

logger = logging.getLogger(__name__)

# 将函数定义为上下文管理器
@asynccontextmanager
async def agent_factory(
    model_name=None,
    llm_type: str = "local_model",
    active_server_names: list = None,
    system_prompt: str = None, 
    debug: bool = False
) -> AsyncGenerator[Agent, None]:
    """
    Agent 工厂：负责建立环境、创建 Agent，并在使用结束后自动清理资源。
    使用方式：
    async with agent_factory(prompt, model) as agent:
        await agent.run(...)
    """
    if model_name:
        llm_model = llm_factory(llm_type, model_name)
    else:
        llm_model = llm_factory(llm_type)
    
    # 0. 默认配置
    if active_server_names is None:
        active_server_names = ["filesystem", "grep", "lsp"]

    # 1. 配置 MCP Servers (配置数据可以提取到外部常量文件)
    server_configs = {
        "filesystem": {
            "command": sys.executable,
            "args": [str(evaluation_path / "servers/read_server.py")],
            "transport": "stdio",
        },
        "grep": {
            "command": sys.executable,
            "args": [str(evaluation_path / "servers/grep_server.py")],
            "transport": "stdio",
        },
        # 预留位置，不用改代码就能扩展
        "edit": {
            "command": sys.executable,
            "args": [str(evaluation_path / "servers/edit_server.py")],
            "transport": "stdio",
        },
        "lsp": {
            "command": sys.executable,
            "args": [str(evaluation_path / "servers/lsp_server.py")],
            "transport": "stdio",
        },
    }

    # 2. 动态筛选配置
    active_servers_config = {
        k: v for k, v in server_configs.items() 
        if k in active_server_names
    }

    # 3. 资源生命周期管理
    client = MultiServerMCPClient(active_servers_config)
    
    # 注意：新版本中，具体的连接生命周期由 client.session() 管理
    # 所以只要下面的 AsyncExitStack 正常退出，连接就会被关闭
    
    try:
        async with AsyncExitStack() as stack:
            sessions = {}
            for name in active_server_names:
                # --- 【保持不变】: 这里符合新版要求 (client.session 是上下文管理器) ---
                session = await stack.enter_async_context(client.session(name))
                sessions[name] = session
            
            # --- 创建 Agent ---
            search_tools = []
            for name, session in sessions.items():
                tools = await load_mcp_tools(session)
                if tools:
                    search_tools.extend(tools)
            
            agent = Agent(llm_model, search_tools, system_prompt=system_prompt, debug=debug)
            
            # --- 关键点：Yield ---
            yield agent
    finally:
        logger.info("🔌 关闭 Agent 连接，清理资源中...")
        # --- 【修改点 2】: 清理工作 ---
        # 如果新版 MultiServerMCPClient 提供了显式的 cleanup/aclose 方法，建议在这里调用
        # 通常情况下，AsyncExitStack 退出时会关闭 session，从而关闭底层 transport
        # 如果 client 有 .aclose() 方法 (取决于具体版本实现)，可以加上：
        # await client.aclose() 
        pass

# --- 如何使用 (复用性极高) ---
async def main():
    repo_path = "/path/to/repo"
    prompt = "分析代码"
    model = ... # 初始化模型
    
    # 外部调用者只需要关心 "我要一个 agent"，不需要关心连接怎么建立、怎么销毁
    async with agent_factory(prompt, model, active_server_names=["filesystem", "grep"]) as agent:
        # 在这个缩进块内，连接都是通的
        result = await agent.async_run(prompt, repo_path)

    # 出缩进块，自动断开连接
