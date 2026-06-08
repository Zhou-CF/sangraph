import os

from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_community.embeddings.dashscope import DashScopeEmbeddings
from langchain_deepseek import ChatDeepSeek
from langchain_ollama import ChatOllama
from langchain_openai import ChatOpenAI

load_dotenv(override=True)

DASHSCOPE_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
DEFAULT_DASHSCOPE_CHAT_MODEL = "qwen3.7-plus"
DEFAULT_DASHSCOPE_EMBED_MODEL = "text-embedding-v4"


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if value:
        return value
    raise ValueError(f"缺少必要环境变量: {name}")


def llm_factory(llm_type: str, llm_model: str = None):
    if llm_model is None and llm_type not in ["local_model", "R1", "dashscope"]:
        raise ValueError("llm_model 参数不能为空，除非 llm_type 是 'local_model'、'R1' 或 'dashscope'。")
    if llm_type == "openai":
        if os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_API_BASE"):
            return ChatOpenAI(
                model=llm_model,
                base_url=os.getenv("OPENAI_API_BASE"),
                api_key=os.getenv("OPENAI_API_KEY"),
            )
        return ChatOpenAI(model=llm_model)
    elif llm_type == "aicopenai":
        if os.getenv("NEW_OPENAI_API_KEY") and os.getenv("NEW_OPENAI_API_BASE"):
            return ChatOpenAI(
                model=llm_model,
                base_url=os.getenv("NEW_OPENAI_API_BASE"),
                api_key=os.getenv("NEW_OPENAI_API_KEY"),
            )
    elif llm_type == "ollama":
        return ChatOllama(model=llm_model)
    elif llm_type == "moonshot":
        return ChatOpenAI(
            model=llm_model,
            base_url="https://api.moonshot.cn/v1",
            api_key=os.getenv("MOONSHOT_API_KEY"),
        )
    elif llm_type == "anthropic":
        return ChatAnthropic(model=llm_model, api_key=os.getenv("ANTHROPIC_API_KEY"))
    elif llm_type == "deepseek":
        return ChatDeepSeek(model=llm_model, api_key=os.getenv("DEEPSEEK_API_KEY"))
    elif llm_type == "dashscope":
        resolved_model = llm_model or DEFAULT_DASHSCOPE_CHAT_MODEL
        if resolved_model == "qwen3-8b-2ae89b5c4e9f":
            extra_body = {
                "enable_thinking": False,  # 关键点：必须设置为 False
            }
        else:
            extra_body = {
                "enable_thinking": True,  # 其他模型可以开启思考链
            }
        return ChatOpenAI(
            model=resolved_model,
            base_url=DASHSCOPE_BASE_URL,
            api_key=_require_env("DASHSCOPE_API_KEY"),
            extra_body=extra_body
        )
    elif llm_type == "local_model":
        return ChatOpenAI(
            model=llm_model if llm_model else os.getenv("LOCAL_MODEL_NAME"),
            base_url=os.getenv("LOCAL_MODEL_BASE_URL"),
            api_key=os.getenv("LOCAL_MODEL_API_KEY"),
        )
    elif llm_type == "R1":
        return ChatOpenAI(
            model=llm_model if llm_model else os.getenv("R1_MODEL_NAME"),
            base_url=os.getenv("R1_MODEL_BASE_URL"),
            api_key=os.getenv("R1_MODEL_API_KEY"),
        )
    else:
        raise ValueError(f"Unsupported LLM type: {llm_type}")


def embed_factory(embed_type: str, embed_model: str | None = None):
    if embed_type == "openai":
        from langchain_openai import OpenAIEmbeddings
        if os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_API_BASE"):
            return OpenAIEmbeddings(
                model=embed_model,
                base_url=os.getenv("OPENAI_API_BASE"),
                api_key=os.getenv("OPENAI_API_KEY"),
            )
        return OpenAIEmbeddings(model=embed_model)
    elif embed_type == "dashscope":
        _require_env("DASHSCOPE_API_KEY")
        return DashScopeEmbeddings(model=embed_model or DEFAULT_DASHSCOPE_EMBED_MODEL)
    else:
        raise ValueError(f"Unsupported embedding type: {embed_type}")
