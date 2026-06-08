
import sys
from contextlib import asynccontextmanager, AsyncExitStack
from typing import AsyncGenerator
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.tools import load_mcp_tools

from utils.constant import evaluation_path
from utils.file_management import ContextManager
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import PromptTemplate
import os
import json
import logging
from pathlib import Path
import functools
import inspect
from langchain_core.language_models.chat_models import BaseChatModel
from json import JSONDecodeError



try:
    from .llm_struct import IsApproved
    from .llm_factory import llm_factory
except ImportError:
    from llm_factory import llm_factory
    from llm_struct import IsApproved

async def is_approved(check_report):
    """
    检查漏洞危害等级是否提升
    
    :param check_report: 漏洞检查报告内容
    :return: bool - 是否有提升
    """


    # llm_model = llm_factory("local_model")
    llm_model = llm_factory(llm_model="qwen3-max", llm_type="openai")

    ### 临时增加检查危害等级是否提升的逻辑 ###
    is_up_parser = PydanticOutputParser(pydantic_object=IsApproved)

    is_up_prompt = PromptTemplate(
        template=(
            "{check_report}。"
            "分析这个漏洞报告内容，如果审核通过，则is_approved=True，否则为False"
            "\n\n"
            "请严格按照以下json格式输出：\n"
            "{format_instructions}\n"
        ),
        input_variables=["check_report"],
        partial_variables={"format_instructions": is_up_parser.get_format_instructions()}
    )

    is_up_response = await llm_model.ainvoke(
        is_up_prompt.format(check_report=check_report)
    )
    is_up_output = is_up_parser.parse(is_up_response.content)
    is_approved = is_up_output.is_approved
    return is_approved
        ### ================================= ###
        ### 临时增加检查危害等级是否提升的逻辑结束 ###
