import asyncio
import logging
from langchain.agents import create_agent
from langchain.agents.middleware import SummarizationMiddleware
from typing import Any, override
from langchain_core.messages import RemoveMessage, AIMessage, HumanMessage, ToolMessage
from langchain.agents.middleware import AgentMiddleware, after_model, AgentState
from langchain_core.messages import AIMessage
from langgraph.graph.message import REMOVE_ALL_MESSAGES # 确保引入了这个常量
from utils.format import (
    extract_conversation_summary,
    extract_file_paths_from_edits,
    calculate_total_tokens,
)

logger = logging.getLogger(__name__)

class SummarizationMiddlewareSelf(SummarizationMiddleware):
    """
    SummarizationMiddleware 的自定义版本。
    在触发总结时，强制保留对话历史中的第一条消息（通常是 System Prompt 或用户核心指令），
    防止 LLM 在长对话摘要后丢失原始任务目标。
    """

    @override
    def before_model(self, state: dict, runtime: Any) -> dict[str, Any] | None:
        """同步处理逻辑：保留第一条消息"""
        messages = state["messages"]
        self._ensure_message_ids(messages)

        total_tokens = self.token_counter(messages)
        if not self._should_summarize(messages, total_tokens):
            return None

        cutoff_index = self._determine_cutoff_index(messages)

        # 如果切分点小于等于1，说明没有中间内容可以总结（因为要保留第0条）
        if cutoff_index <= 1:
            return None

        # --- 核心修改逻辑开始 ---
        
        # 1. 提取第一条消息
        first_message = messages[0]
        logger.debug("Preserving first message during summarization: %s", first_message)
        
        # 2. 调整切片：跳过第0条，从第1条开始总结到 cutoff_index
        messages_to_summarize = messages[1:cutoff_index]
        
        # 3. 剩余保留的消息保持不变
        preserved_messages = messages[cutoff_index:]

        # 如果中间没有消息（比如 messages[1:1]），则不处理
        if not messages_to_summarize:
            return None
            
        # --- 核心修改逻辑结束 ---

        # 生成摘要
        summary = self._create_summary(messages_to_summarize)
        new_messages = self._build_new_messages(summary)

        # 返回构建的新消息列表
        return {
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES), # 清除旧历史
                first_message,       # <--- 重新插入未被压缩的第一条消息
                *new_messages,       # 插入摘要信息
                *preserved_messages, # 插入近期保留的消息
            ]
        }

    @override
    async def abefore_model(self, state: dict, runtime: Any) -> dict[str, Any] | None:
        """异步处理逻辑：保留第一条消息"""
        messages = state["messages"]
        self._ensure_message_ids(messages)

        total_tokens = self.token_counter(messages)
        if not self._should_summarize(messages, total_tokens):
            return None

        cutoff_index = self._determine_cutoff_index(messages)

        if cutoff_index <= 1:
            return None

        # --- 核心修改逻辑开始 ---
        first_message = messages[0]
        messages_to_summarize = messages[1:cutoff_index]
        preserved_messages = messages[cutoff_index:]

        if not messages_to_summarize:
            return None
        # --- 核心修改逻辑结束 ---

        # 异步生成摘要
        summary = await self._acreate_summary(messages_to_summarize)
        new_messages = self._build_new_messages(summary)

        return {
            "messages": [
                RemoveMessage(id=REMOVE_ALL_MESSAGES),
                first_message,       # <--- 重新插入未被压缩的第一条消息
                *new_messages,
                *preserved_messages,
            ]
        }

class LogAgentContentMiddleware(AgentMiddleware):
    def after_model(self, state: dict) -> dict | None:
        messages = state.get("messages", [])
        if not messages:
            return None

        last_msg = messages[-1]

        if isinstance(last_msg, AIMessage):
            if last_msg.content:
                logger.debug("Agent response preview: %s", last_msg.content[:200])
        return None
    
    def wrap_tool_call(self, request, handler):
        tool_name = request.tool.name
        tool_args = request.tool_call.get("args", {})

        logger.debug("Invoking tool name=%s args=%s", tool_name, tool_args)

        result = handler(request)  # 真正执行工具

        # ToolMessage / Command 都在这里
        logger.debug("Tool result preview name=%s result=%s", tool_name, str(result)[:100])

        return result 
    
    async def aafter_model(self, state: dict) -> dict | None:
        messages = state.get("messages", [])
        if not messages:
            return None

        last_msg = messages[-1]
        if isinstance(last_msg, AIMessage):
            if last_msg.content:
                logger.debug("Agent response preview: %s", last_msg.content[:200])

        return None
    
    async def awrap_tool_call(self, request, handler):
        tool_name = request.tool.name
        tool_args = request.tool_call.get("args", {})

        logger.debug("Invoking tool name=%s args=%s", tool_name, tool_args)

        result = await handler(request)
        logger.debug("Tool result preview name=%s result=%s", tool_name, str(result)[:100])

        return result


class Agent:
    """Evaluator class for running LLM queries with MCP tools"""

    def __init__(self, llm_model, tools, system_prompt=None, debug=False):
        """
        Initialize the Agent

        Args:
            llm_model: LangChain LLM model instance (required)
            tools: List of tools to use (required)
        """
        self.llm_model = llm_model
        self.tools = tools
        logger.debug("Creating Agent debug=%s tool_count=%s", debug, len(self.tools))
        # self.agent = create_agent(self.llm_model, self.tools, debug=debug)
        self.agent = create_agent(
                        model=self.llm_model,
                        tools=self.tools,  # 替换为你的工具
                        system_prompt=system_prompt,
                        middleware=[
                            SummarizationMiddlewareSelf(
                                model=self.llm_model,          # 用于总结的模型
                                trigger=[("tokens", 30000)],     # 触发条件：达到10000 tokens 时总结
                                keep=("messages", 10),        # 保留最近 20 条消息
                                trim_tokens_to_summarize=40000,  # 总结的 tokens 数量
                            ),
                            LogAgentContentMiddleware(),  # 添加日志中间件
                        ],
                        debug=debug,
                    )

        # Setup event loop for sync usage
        try:
            self.loop = asyncio.get_event_loop()
        except RuntimeError:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

    async def async_run(self, query, codebase_path=None):
        """Internal async method to run the query"""
        response = await self.agent.ainvoke(
            {"messages": [{"role": "user", "content": query}]},
            config={"recursion_limit": 300},
        )

        # Extract data without printing
        conversation_summary, tool_stats, summary_report = extract_conversation_summary(response)
        token_usage = calculate_total_tokens(response)

        if codebase_path:
            file_paths = extract_file_paths_from_edits(response, codebase_path)
        else:
            file_paths = []
        return summary_report, conversation_summary, token_usage, file_paths, tool_stats

    async def async_loop_run(self, messages: list):
        """Internal async method to run the query"""
        response = await self.agent.ainvoke(
            {"messages": messages},
            config={"recursion_limit": 300},
        )
        return response

    def query(self, query: str):
        """
        Run a query synchronously

        Args:
            query (str): The query to execute
            codebase_path (str): Path to the codebase for relative path conversion

        Returns:
            tuple: (response, conversation_summary, token_usage, file_paths)
        """
        response = self.agent.invoke(
            {"messages": [{"role": "user", "content": query}]},
            config={"recursion_limit": 300},
        )
        return response
    def ainvoke(self, messages: list):
        """
        Run a query synchronously

        Args:
            query (str): The query to execute
            codebase_path (str): Path to the codebase for relative path conversion

        Returns:
            tuple: (response, conversation_summary, token_usage, file_paths)
        """
        response = self.agent.ainvoke(
            {"messages": messages},
            config={"recursion_limit": 300},
        )
        return response
        
        
    def run(self, query: str, codebase_path=None):
        """
        Run a query synchronously

        Args:
            query (str): The query to execute
            codebase_path (str): Path to the codebase for relative path conversion

        Returns:
            tuple: (response, conversation_summary, token_usage, file_paths)
        """

        return asyncio.run(self.async_run(query, codebase_path))
