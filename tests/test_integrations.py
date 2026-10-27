import pytest
from recguard import Policy, RecGuard, RecGuardError
from recguard.integrations import guard_items


@pytest.fixture
def engine():
    r = RecGuard()
    r.register_policy(Policy(policy_id="rag", version=1, denied_categories=["internal-only"], require_evidence=True))
    return r


def test_guard_items_generic(engine):
    items = [{"sku": "a", "s": 0.4, "src": ["kb-1"]}, {"sku": "b", "s": 0.9, "src": []}, {"sku": "c", "s": 0.7, "src": ["kb-2"]}]
    kept, d = guard_items(engine, items, tenant_id="acme", purpose="rag",
                          to_candidate=lambda x, rank: {"item_id": x["sku"], "score": x["s"], "evidence_ids": x["src"]})
    assert [x["sku"] for x in kept] == ["c", "a"] and d["rejections"][0]["reason"] == "EVIDENCE_REQUIRED"
    with pytest.raises(RecGuardError, match="BLOCKED"):
        guard_items(engine, items[1:2], tenant_id="acme", purpose="rag", to_candidate=lambda x, r: {"item_id": x["sku"], "score": 1})
    assert guard_items(engine, items[1:2], tenant_id="acme", purpose="rag", on_block="empty",
                       to_candidate=lambda x, r: {"item_id": x["sku"], "score": 1})[0] == []


def test_langchain_runnable_after_a_retriever(engine):
    lc = pytest.importorskip("langchain_core")
    from langchain_core.documents import Document
    from langchain_core.runnables import RunnableLambda
    from recguard.integrations import langchain_guard
    docs = [Document(id="faq-1", page_content="Refund policy", metadata={"evidence_ids": ["kb-v3"]}),
            Document(id="memo-9", page_content="Internal pricing memo", metadata={"evidence_ids": ["kb-v3"], "categories": ["internal-only"]}),
            Document(page_content="Untracked snippet", metadata={"id": "web-7"})]
    retriever = RunnableLambda(lambda query: docs)
    chain = retriever | langchain_guard(engine, tenant_id="acme", purpose="rag")
    kept = chain.invoke("how do refunds work?")
    assert [d.id or d.metadata.get("id") for d in kept] == ["faq-1"]


def test_llamaindex_node_postprocessor(engine):
    pytest.importorskip("llama_index.core")
    from llama_index.core.schema import NodeWithScore, TextNode
    from recguard.integrations import RecGuardNodePostprocessor
    nodes = [NodeWithScore(node=TextNode(id_="n1", text="ok", metadata={"evidence_ids": ["kb"]}), score=0.5),
             NodeWithScore(node=TextNode(id_="n2", text="secret", metadata={"evidence_ids": ["kb"], "categories": ["internal-only"]}), score=0.9),
             NodeWithScore(node=TextNode(id_="n3", text="better", metadata={"evidence_ids": ["kb"]}), score=0.8)]
    post = RecGuardNodePostprocessor.create(engine, "acme", "rag")
    kept = post.postprocess_nodes(nodes)
    assert [n.node.node_id for n in kept] == ["n3", "n1"]
