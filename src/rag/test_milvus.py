from rag.rag import main, upsert_data
from llm_factory.llm_factory import embed_factory
import json
from pathlib import Path


embeddings_model = embed_factory(embed_type="dashscope", embed_model="text-embedding-v4")
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_JSONL_PATH = REPO_ROOT / "other" / "data" / "verified_sanitizer_dataset.to_rag.jsonl"


def _resolve_repo_path(path: str | Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute() or candidate.exists():
        return candidate
    if candidate.parts and candidate.parts[0] in {"artifacts", "data", "plan"}:
        return REPO_ROOT / "other" / candidate
    repo_relative = REPO_ROOT / candidate
    if repo_relative.exists():
        return repo_relative
    return candidate


def load_jsonl_records(jsonl_path: str, limit: int = 0) -> list[dict]:
    records = []
    with _resolve_repo_path(jsonl_path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
            if limit > 0 and len(records) >= limit:
                break
    return records

def prepare_and_upload_data(collection_name: str, raw_data_list: list):
    """
    处理原始数据，生成向量，并上传到 Milvus
    """
    processed_data = []
    
    print(f"开始处理 {len(raw_data_list)} 条数据...")

    for item in raw_data_list:
        # 1. 提取文本字段用于生成向量
        vuln_code = item.get("vulnerable_code_snippet", "")
        logic_text = item.get("unsafe_sanitizer_logic", "")
        
        # 2. 生成稠密向量 (Dense Vectors)
        # 注意：这里假设 embeddings_model.embed_query 返回的是 float list
        # 如果 logic_text 为空，可能需要处理异常或给默认空向量
        try:
            vuln_vector = embeddings_model.embed_query(vuln_code) if vuln_code else [0.0] * 1024
            sanitizer_vector = embeddings_model.embed_query(logic_text) if logic_text else [0.0] * 1024
        except Exception as e:
            print(f"向量生成失败 ID {item.get('id')}: {e}")
            continue

        # 3. 构建符合 Schema 的字典
        # 注意：必须严格对应 set_schema 中的字段名
        row = {
            # --- 主键 ---
            "id": str(item["id"]),  # 确保是字符串
            
            # --- 标量字段 ---
            "CVE_ID": item.get("CVE_ID", ""),
            "vulnerable_code_snippet": vuln_code,
            "unsafe_sanitizer_logic": logic_text, # BM25 会自动读取这个字段生成稀疏向量
            "patch_content": item.get("patch_content", ""),
            "programming_language": item.get("programming_language", "Unknown"),
            "cwe_id": item.get("cwe_id", ""),
            "bypass_poc": item.get("bypass_poc", ""),

            # --- 复杂字段 (JSON / Array) ---
            "validation_api_list": item.get("validation_api_list", []),           # 列表
            "unsafe_sanitizer_info": item.get("unsafe_sanitizer_info", {}),       # 字典/JSON
            # "validation_api_text": " ".join(item.get("validation_api_list", [])), # 用于 BM25 的文本字段
            # --- 向量字段 (必须传入 List[float]) ---
            "vulnerable_code_vector": vuln_vector,
            "unsafe_sanitizer_dense_vector": sanitizer_vector,
        }
        
        processed_data.append(row)

    # 4. 批量上传
    # 建议分批上传，比如每 100 条一次，避免请求包过大
    batch_size = 50
    total = len(processed_data)

    for i in range(0, total, batch_size):
        batch_data = processed_data[i : i + batch_size]
        print(f"上传第 {i // batch_size + 1} 批数据，包含 {len(batch_data)} 条...")
        upsert_data(collection_name, batch_data)
            
def process_logic(unsafe_logic: dict) -> str:
    """
    将复杂的 unsafe_sanitizer_logic 字段转换为字符串
    """
    if not unsafe_logic:
        return ""
    
    details = unsafe_logic.get("details", [])
    actions = unsafe_logic.get("actions", [])
    logic_nlp = unsafe_logic.get("logic_with_nlp", "")
    logic_str = logic_nlp  + '; ' + ", ".join(actions) + '; ' + ", ".join(details)
    
    return logic_str

def process_item(item: dict) -> dict:
    """
    item 示例结构：
    {
        "id": "unique_id_123",
        "CVE_ID": "CVE-2024-12345",
        "patch_content": "...",
        "cwe_id": ["CWE-79", "CWE-89"],
        "programming_language": "Python",
        "unsafe_sanitizer_info": {"reason": "..."},
        "vulnerable_code_snippet": "...vulnerable code snippet...",
        "unsafe_sanitizer_logic": {
            "logic_with_nlp": "...",
            "actions": ["action1", "action2"],
            "details": ["detail1", "detail2"]
        },
        "validation_api_list": ["funcA", "funcB", ...]
    }
    
    
    """

    idx = item.get("id", "")
    cve_id = item.get("CVE_ID", "")
    patch_content = item.get("patch_content", "")
    cwe_id = item.get("cwe_id", [])
    language = item.get("programming_language", "")
    unsafe_sanitizer_info = item.get("unsafe_sanitizer_info", {})


    code = item.get("vulnerable_code_snippet", "")
    if not code:
        # raise ValueError("缺少 code 字段")
        return

    logic_str = item.get("unsafe_sanitizer_logic", {})

    validation_api_list = item.get("validation_api_list", [])
    # validation_api_text = " ".join(validation_api_list) if validation_api_list else ""

    code_vector = embeddings_model.embed_query(code)
    sanitizer_vector = embeddings_model.embed_query(logic_str)

    return {
        "id": str(idx),
        "CVE_ID": cve_id,
        "cwe_id": cwe_id,
        "vulnerable_code_snippet": code,
        "unsafe_sanitizer_logic": logic_str,
        "unsafe_sanitizer_info": unsafe_sanitizer_info,
        "patch_content": patch_content,
        "programming_language": language,
        "bypass_poc": item.get("bypass_poc", ""),

        "validation_api_list": validation_api_list,
        "vulnerable_code_vector": code_vector,
        "unsafe_sanitizer_dense_vector": sanitizer_vector,
    }




    pass  # Placeholder for any item-specific processing if needed


if __name__ == "__main__":
    import asyncio
    # asyncio.run(main())
    # exit(1)
    import os
    import json
    import uuid
    import re
    from rag.rag_search import search
    knowledge_path = Path('/home/sanitizer/Sanitizer/output/knowledge')
    my_source_data = []
    pattern = r'CWE-\d{1,5}'
    for cve in knowledge_path.iterdir():
        print(f"Processing {cve}...")
        cve_id = cve.name
        cve_rag_exist = asyncio.run(search(expr="CVE_ID == '{}'".format(cve_id), top_k=2))
        # print(f"RAG search result for {cve_id}: {cve_rag_exist}")
        # input("Press Enter to continue...")
        if cve_rag_exist:
            print(f"{cve_id} 已存在于 Milvus 中，跳过上传。")
            continue
        knowledge_graph_path = cve / "knowledge_graph_result.json"
        by_batch_qwen_path = cve / "by_batch_qwen.json"
        if not knowledge_graph_path.exists():
            print(f"缺少 knowledge_graph_result.json，跳过 {cve}。")
            continue
        knowledge_data = json.loads(knowledge_graph_path.read_text(encoding='utf-8'))
        by_batch_qwen_data = json.loads(by_batch_qwen_path.read_text(encoding='utf-8'))
        patch_path = _resolve_repo_path(by_batch_qwen_data.get("patch_path", ""))
        if not patch_path.exists():
            continue
        patch_content = patch_path.read_text(encoding='utf-8', errors='ignore')
        bypass_poc = knowledge_data.get("bypass_poc", [])
        if isinstance(bypass_poc, list):
            bypass_poc_str = ", ".join(bypass_poc)
        else:
            bypass_poc_str = str(bypass_poc)
        cwe_str = knowledge_data.get("cwe_id", "")
        cwe_id =re.findall(pattern, cwe_str)
        # print(f"cwe_id: {cwe_id}")
        item_knowledge = {
            "id": str(uuid.uuid4()),
            "CVE_ID": cve_id,
            "patch_content": patch_content,
            "cwe_id": cwe_id,
            "programming_language": knowledge_data.get("language", ""),
            "vulnerable_code_snippet": knowledge_data.get("code", ""),
            "unsafe_sanitizer_logic": process_logic(knowledge_data.get("unsafe_sanitizer_logic", {})),
            "unsafe_sanitizer_info": knowledge_data.get("unsafe_sanitizer_info", {}),
            "validation_api_list": knowledge_data.get("api_list", []),
            

            "bypass_poc": bypass_poc_str,
        }
        # print(item_knowledge)

        item = process_item(item_knowledge)
        if not item:
            print(f"处理 {cve} 时出错，跳过。")
            continue
        my_source_data.append(item)
        # break  # 测试只处理一个 CVE
    

    prepare_and_upload_data("sanitizer_logic", my_source_data)


def upload_from_to_rag_jsonl(
    jsonl_path: str = str(DEFAULT_JSONL_PATH),
    collection_name: str = "sanitizer_logic",
    limit: int = 5,
):
    raw_data_list = load_jsonl_records(jsonl_path, limit=limit)
    if not raw_data_list:
        print(f"未在 {jsonl_path} 中读取到任何记录。")
        return
    print(f"从 {jsonl_path} 读取到 {len(raw_data_list)} 条记录，准备上传到 {collection_name}。")
    prepare_and_upload_data(collection_name, raw_data_list)


    # import asyncio
    # asyncio.run(main())
