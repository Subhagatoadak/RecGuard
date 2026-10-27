import asyncio, json
import pytest
pytest.importorskip("mcp.server.mcpserver")
from recguard import Policy, RecGuard
from recguard.mcp_server import _Embedded, build_server


def call(server, name, **arguments):
    result = asyncio.run(server.call_tool(name, arguments))
    structured = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
    if structured:
        return structured
    return json.loads(result.content[0].text)


@pytest.fixture
def server():
    engine = RecGuard()
    engine.register_policy(Policy(policy_id="p", version=1, require_evidence=False, denied_categories=["rx-only"]))
    engine.register_policy(Policy(policy_id="board", version=1, require_evidence=False, purposes=["capex"], require_approval=True))
    return build_server(_Embedded(engine))


def test_tools_are_listed_and_humans_only_actions_are_absent(server):
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == {"recguard_evaluate", "recguard_verify", "recguard_explain_policy", "recguard_pending_reviews"}
    assert not any("approve" in n or "outcome" in n or "present" in n for n in names)


def test_agent_evaluates_verifies_and_reads_policy(server):
    d = call(server, "recguard_evaluate", tenant_id="acme", purpose="shop", k=2, candidates=[
        {"item_id": "vitamin-b12", "score": 0.9}, {"item_id": "isotretinoin", "score": 0.95, "categories": ["rx-only"]}])
    assert d["status"] == "REPAIRED" and [r["item_id"] for r in d["results"]] == ["vitamin-b12"]
    assert d["rejections"][0]["reason"] == "DENIED_CATEGORY"
    assert call(server, "recguard_verify", tenant_id="acme", decision_id=d["decision_id"], receipt=d["receipt"], results=d["results"])["valid"]
    forged = [{**d["results"][0], "item_id": "isotretinoin", "categories": ["rx-only"]}]
    assert not call(server, "recguard_verify", tenant_id="acme", decision_id=d["decision_id"], receipt=d["receipt"], results=forged)["valid"]
    assert call(server, "recguard_explain_policy", tenant_id="acme", purpose="shop")["effective_policy"]["denied_categories"] == ["rx-only"]
    held = call(server, "recguard_evaluate", tenant_id="acme", purpose="capex", candidates=[{"item_id": "plant-2", "score": 1}])
    assert held["status"] == "PENDING_APPROVAL"
    assert call(server, "recguard_pending_reviews", tenant_id="acme")["pending"][0]["decision_id"] == held["decision_id"]
