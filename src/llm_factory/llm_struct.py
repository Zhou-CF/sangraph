from pydantic import BaseModel, ConfigDict, Field
from typing import Literal, Optional, Dict, Any, List, Annotated


class IsApproved(BaseModel):
    reasoning: Optional[str] = Field(description="模型推理过程说明")
    is_approved: bool = Field(description="是否审核通过")

class SanitizerItem(BaseModel):
    language: str = Field(description="代码语言")
    confidence_score: str = Field(description="置信度评分，范围0-1")
    file_path: Optional[str] = Field(description="相关代码文件路径")
    defense_target_class: str = Field(description="防御的漏洞类型")
    implementation_type: str = Field(description="防御实现类型")
    vuln_type: Optional[str] = Field(description="示例攻击代码或输入")
    defense_snippet: Optional[str] = Field(description="防御代码片段，包含行号")
    intended_defense_effect: str = Field(description="简述防御逻辑的预期效果")
    failure_mechanism: str = Field(description="简述防御失败的原因")
    bypass_poc: Optional[str] = Field(description="绕过的示例攻击代码或输入")
    analysis_summary: str = Field(description="简要分析总结")
    is_defense_but_failure: str = Field(description="是否为防御失败的分析")

class AnalyseOutput(BaseModel):
    output: List[SanitizerItem] = Field(description="分析结果列表")

class CheckerOutput(BaseModel):
    reasoning: Optional[str] = Field(description="模型推理过程说明")
    critique: str = Field(description="审核理由说明")
    verdict: Literal["APPROVE", "REJECT"] = Field(description="审核结论")
    confidence_score: str = Field(description="置信度评分，范围0-100")



