from __future__ import annotations

import argparse
from typing import Sequence

from langchain_classic.retrievers import ContextualCompressionRetriever
from langchain_classic.retrievers.document_compressors import CrossEncoderReranker
from langchain_milvus import Milvus
from pymilvus import DataType, Function, FunctionType, MilvusClient
from sangraph_logging import get_logger

from rag.config import (
    default_collection_name,
    get_cross_encoder_model,
    get_embedding_model,
    milvus_connection_args,
)

logger = get_logger(__name__)

def _create_client() -> MilvusClient:
    return MilvusClient(**milvus_connection_args())


def get_milvus_vectorstore(
    collection_name: str | None = None,
    auto_id: bool = True,
    vector_field: str = "unsafe_sanitizer_dense_vector",
) -> Milvus:
    """
    获取Milvus向量数据库实例

    Args:
        host (str): Milvus服务器主机地址
        port (int): Milvus服务器端口号
        collection_name (str): 向量数据库的集合名称
    """
    client = Milvus(
        collection_name=collection_name or default_collection_name(),
        embedding_function=get_embedding_model(),
        connection_args=milvus_connection_args(),
        vector_field=vector_field,
        auto_id=auto_id,
    )
    return client

def get_compressed_milvus_vectorstore_retriever(
    collection_name: str | None = None,
    auto_id: bool = True,
    search_type: str = "similarity",
    search_kwargs: dict | None = None,
    top_n: int = 5,
) -> ContextualCompressionRetriever:
    """
    获取压缩后的Milvus向量数据库检索器实例

    Args:
        collection_name (str): 向量数据库的集合名称，默认为 None
        auto_id (bool): 是否自动生成ID，默认为 True
        search_type (str): 检索类型，默认为 "similarity"
        search_kwargs (dict): 检索参数，默认为 {"k":20}
        top_n (int): 交叉编码器重排序的返回结果数量，默认为 5
    """
    milvus_vectorstore = get_milvus_vectorstore(
        collection_name=collection_name or default_collection_name(),
        auto_id=auto_id,
    )
    retriever = milvus_vectorstore.as_retriever(
        search_type=search_type,
        search_kwargs=search_kwargs or {"k": 20},
    )

    cross_encoder = CrossEncoderReranker(
        model=get_cross_encoder_model(),
        top_n=top_n,
    )

    compression_retriever = ContextualCompressionRetriever(
        base_retriever=retriever,
        base_compressor=cross_encoder
    )
    return compression_retriever

def get_compressed_retriever(query: str, documents: list, top_n: int = 5):
    """
    使用交叉编码器对文档进行重排序

    Args:
        query (str): 查询文本
        documents (list): 待重排序的文档列表
        top_n (int): 返回的前N个重排序结果，默认为 5

    Returns:
        list: 重排序后的文档列表
    """
    cross_encoder = CrossEncoderReranker(
        model=get_cross_encoder_model(),
        top_n=top_n,
    )
    reranked_docs = cross_encoder.compress_documents(query=query, documents=documents)
    return reranked_docs

def add_test_data_to_milvus(
    collection_name: str,
    texts: list,
    metadatas: list,
    auto_id: bool = True,
    ids: list | None = None,
):
    """
    向Milvus向量数据库添加测试数据

    Args:
        client (Milvus): Milvus向量数据库客户端实例
        texts (list): 需要添加的文本列表
        metadatas (list): 对应的元数据列表
        auto_id (bool): 是否自动生成ID，默认为 True
    """
    if ids:
        auto_id = False
    client = get_milvus_vectorstore(collection_name=collection_name, auto_id=auto_id)
    client.add_texts(texts=texts, metadatas=metadatas, ids=ids)
    logger.info("Added %s records to Milvus collection=%s", len(texts), collection_name)

def set_schema():
    schema = MilvusClient.create_schema()
    schema.add_field(field_name="id",
                     datatype=DataType.VARCHAR,
                     max_length=64,
                     description="主键ID",
                     is_primary=True,
                     auto_id=False)

    schema.add_field(field_name="CVE_ID",
                     datatype=DataType.VARCHAR,
                     max_length=100,
                     description="CVE编号")

    schema.add_field(field_name="patch_content",
                     datatype=DataType.VARCHAR,
                     max_length=65535,
                     description="补丁内容")

    schema.add_field(field_name="cwe_id",
                     datatype=DataType.ARRAY,
                     element_type=DataType.VARCHAR,
                     max_length=1024,
                     max_capacity=100,
                     description="CWE编号，如 CWE-89")

    schema.add_field(field_name="programming_language",
                     datatype=DataType.VARCHAR,
                     max_length=32,
                     description="代码所属编程语言，如 PHP, Java, Python")

    schema.add_field(field_name="bypass_poc",
                     datatype=DataType.VARCHAR,
                     max_length=2048,
                     description="能够绕过该消毒逻辑的攻击载荷(PoC)")

    schema.add_field(field_name="unsafe_sanitizer_info",
                     datatype=DataType.JSON,
                     description="不健全的消毒函数相关信息")

    # --- 维度 1: 逻辑描述 (Logic Description) ---
    schema.add_field(field_name="unsafe_sanitizer_logic",
                     datatype=DataType.VARCHAR,
                     enable_analyzer=True,
                     max_length=4096,
                     description="不健全的消毒函数逻辑描述, fix_logic_with_nlp;fix_actions;fix_details")

    schema.add_field(field_name="unsafe_sanitizer_dense_vector",
                     datatype=DataType.FLOAT_VECTOR,
                     dim=1024,
                     description="不健全的消毒函数稠密向量")

    schema.add_field(field_name="unsafe_sanitizer_sparse_vector",
                     datatype=DataType.SPARSE_FLOAT_VECTOR,
                     description="不健全的消毒函数稀疏向量")

    schema.add_field(field_name="vulnerable_code_snippet",
                     datatype=DataType.VARCHAR,
                     enable_analyzer=True,
                     max_length=8192,
                     description="原始的、未修复的脆弱代码片段")

    schema.add_field(field_name="vulnerable_code_vector",
                     datatype=DataType.FLOAT_VECTOR,
                     dim=1024,
                     description="漏洞代码的稠密向量")

    schema.add_field(field_name="vulnerable_code_sparse_vector",
                     datatype=DataType.SPARSE_FLOAT_VECTOR,
                     description="漏洞代码的稀疏向量")

    schema.add_field(field_name="validation_api_list",
                     datatype=DataType.ARRAY,
                     element_type=DataType.VARCHAR,
                     max_length=1024,
                     max_capacity=100,
                     nullable=True,
                     description="无害处理中的调用的函数列表")
    schema.add_function(Function(
        name="logic_bm25",
        input_field_names=["unsafe_sanitizer_logic"],
        output_field_names=["unsafe_sanitizer_sparse_vector"],
        function_type=FunctionType.BM25
    ))

    schema.add_function(Function(
        name="code_bm25",
        input_field_names=["vulnerable_code_snippet"],
        output_field_names=["vulnerable_code_sparse_vector"],
        function_type=FunctionType.BM25,
    ))
    return schema



def set_collection_index(collection_name: str):
    client = _create_client()
    index_params = MilvusClient.prepare_index_params()
    index_params.add_index(
        field_name="unsafe_sanitizer_dense_vector",
        index_type="HNSW",
        metric_type="COSINE",
        params={"M": 16, "efConstruction": 200},
    )
    index_params.add_index(
        field_name="unsafe_sanitizer_sparse_vector",
        index_type="SPARSE_INVERTED_INDEX",
        metric_type="BM25",
    )
    index_params.add_index(
        field_name="vulnerable_code_vector",
        index_type="HNSW",
        metric_type="COSINE",
        params={"M": 16, "efConstruction": 200},
    )
    index_params.add_index(
        field_name="vulnerable_code_sparse_vector",
        index_type="SPARSE_INVERTED_INDEX",
        metric_type="BM25",
    )
    index_params.add_index(
        field_name="validation_api_list",
        index_type="AUTOINDEX",
    )
    index_params.add_index(
        field_name="cwe_id",
        index_type="AUTOINDEX",
    )
    index_params.add_index(
        field_name="id",
        index_type="STL_SORT",
    )
    logger.info("Creating Milvus indexes for collection=%s", collection_name)
    try:
        client.create_index(collection_name=collection_name, index_params=index_params)
        logger.info("Successfully created Milvus indexes for collection=%s", collection_name)
    except Exception as e:
        logger.exception("Failed creating Milvus indexes for collection=%s: %s", collection_name, e)
    finally:
        client.close()


def _collection_exists(client: MilvusClient, collection_name: str) -> bool:
    return collection_name in client.list_collections()


def create_collection(collection_name: str | None = None):
    resolved_name = collection_name or default_collection_name()
    client = _create_client()
    try:
        if _collection_exists(client, resolved_name):
            logger.info("Milvus collection already exists collection=%s", resolved_name)
            return
        client.create_collection(collection_name=resolved_name, schema=set_schema())
        logger.info("Created Milvus collection collection=%s", resolved_name)
    finally:
        client.close()
    set_collection_index(collection_name=resolved_name)

def upsert_data(collection_name: str, data: list):
    client = _create_client()
    try:
        client.upsert(collection_name=collection_name, data=data)
    finally:
        client.close()

def drop_collection(collection_name: str):
    client = _create_client()
    try:
        if not _collection_exists(client, collection_name):
            logger.info("Milvus collection does not exist collection=%s", collection_name)
            return
        client.drop_collection(collection_name=collection_name)
        logger.info("Dropped Milvus collection collection=%s", collection_name)
    finally:
        client.close()


def describe_collection(collection_name: str | None = None):
    resolved_name = collection_name or default_collection_name()
    client = _create_client()
    try:
        return client.describe_collection(collection_name=resolved_name)
    finally:
        client.close()

def check_idx_exists(collection_name: str, index_name: str):
    client = _create_client()
    try:
        exists = client.query(collection_name=collection_name, ids=[index_name])
        return len(exists) > 0
    finally:
        client.close()

def alter_collection_add_field(collection_name: str, field_name: str, field_params: dict):
    client = _create_client()
    try:
        client.alter_collection_field(collection_name=collection_name, field_name=field_name, field_params=field_params)
        logger.info("Added field to Milvus collection collection=%s field=%s", collection_name, field_name)
    finally:
        client.close()

async def search_rag_with_sanitizer_logic(query: str, expr: str, top_k: int = 5):
    vector_store = get_compressed_milvus_vectorstore_retriever(
        collection_name=default_collection_name(),
        top_n=top_k,
    )
    if expr:
        results = await vector_store.ainvoke(query, expr=expr)
    else:
        results = await vector_store.ainvoke(query)
    return results

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Milvus collection operator helpers.")
    parser.add_argument(
        "command",
        choices=["create-collection", "drop-collection", "describe-collection"],
    )
    parser.add_argument(
        "--collection-name",
        default=default_collection_name(),
        help="Milvus collection name.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(list(argv) if argv is not None else None)
    if args.command == "create-collection":
        create_collection(collection_name=args.collection_name)
    elif args.command == "drop-collection":
        drop_collection(collection_name=args.collection_name)
    elif args.command == "describe-collection":
        print(describe_collection(collection_name=args.collection_name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

    
