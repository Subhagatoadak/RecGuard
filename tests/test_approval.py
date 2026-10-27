import pytest
from fastapi.testclient import TestClient
from recguard import Candidate, Denied, Outcome, Policy, Request, RecGuard, review
from recguard.api import create_app

PACK = {"recguard": 1, "name": "approvals", "constants": {"big": 100},
        "policies": [{"policy_id": "base", "version": 1, "require_evidence": False}],
        "checks": [{"name": "spend", "rules": [
            {"reject": "NEGATIVE", "if": "item.score < 0"},
            {"review": "LARGE_MOVE", "if": "item.score >= big"},
            {"reject": "BANNED", "if": "item.item_id == 'banned'"}]}]}


def req(*items, rid="r", purpose="plan"):
    return Request(tenant_id="acme", request_id=rid, purpose=purpose, k=5,
                   candidates=[Candidate(item_id=i, tenant_id="acme", score=s) for i, s in items])


def test_review_rule_holds_decision_until_approved():
    r = RecGuard()
    r.load_policy_pack(PACK)
    d = r.evaluate(req(("small", 5), ("large", 150)))
    assert d.status == "PENDING_APPROVAL" and [x.item_id for x in d.results] == ["large", "small"]
    assert [(x.item_id, x.reason) for x in d.review_required] == [("large", "spend:LARGE_MOVE")]
    assert not r.verify("acme", d.decision_id, d.receipt, d.results)       # cannot be shown yet
    with pytest.raises(Denied):
        r.presented("acme", d.decision_id, d.receipt, d.results)
    pending = r.pending_reviews("acme")
    assert pending[0]["decision_id"] == d.decision_id and [x["item_id"] for x in pending[0]["results"]] == ["large", "small"]
    with pytest.raises(Denied, match="REVIEWER_REQUIRED"):
        r.review("acme", d.decision_id, True, "")
    approved = r.review("acme", d.decision_id, True, "cfo@acme", "within quarterly plan")
    assert approved["status"] == "PASS" and approved["receipt"] != d.receipt
    assert r.verify("acme", d.decision_id, approved["receipt"], d.results)
    assert not r.verify("acme", d.decision_id, d.receipt, d.results)       # old receipt is dead
    r.presented("acme", d.decision_id, approved["receipt"], d.results)
    r.outcome(Outcome(outcome_id="o1", tenant_id="acme", decision_id=d.decision_id, reward=1, outcome_type="BUSINESS_GOAL"))
    assert r.pending_reviews("acme") == []
    with pytest.raises(Denied, match="NOT_PENDING_APPROVAL"):
        r.review("acme", d.decision_id, True, "cfo@acme")
    audit = r.db.conn.execute("SELECT payload FROM audit WHERE kind='DECISION_REVIEWED'").fetchone()["payload"]
    assert "cfo@acme" in audit and "within quarterly plan" in audit


def test_reject_review_and_policy_change_and_reject_rules_win():
    r = RecGuard()
    r.load_policy_pack(PACK)
    d = r.evaluate(req(("large", 150)))
    assert r.review("acme", d.decision_id, False, "cfo@acme")["status"] == "BLOCKED"
    assert not r.verify("acme", d.decision_id, d.receipt, d.results)
    d2 = r.evaluate(req(("large", 150), rid="r2"))
    r.register_policy(Policy(policy_id="base", version=2, require_evidence=False, denied_categories=["x"]))
    with pytest.raises(Denied, match="POLICY_CHANGED_SINCE_DECISION"):
        r.review("acme", d2.decision_id, True, "cfo@acme")
    # reject rules after a matching review rule still apply
    d3 = r.evaluate(req(("banned", 150), ("ok", 1), rid="r3"))
    assert d3.status == "REPAIRED" and [x.reason for x in d3.rejections] == ["spend:BANNED"]


def test_policy_and_decision_level_review_and_python_checks():
    r = RecGuard()
    r.register_policy(Policy(policy_id="base", version=1, require_evidence=False))
    r.register_policy(Policy(policy_id="board", version=1, require_evidence=False, purposes=["capex"], require_approval=True))
    assert r.evaluate(req(("a", 1))).status == "PASS"
    held = r.evaluate(req(("a", 1), purpose="capex", rid="c1"))
    assert held.status == "PENDING_APPROVAL" and held.review_required[0].reason == "POLICY_REQUIRES_APPROVAL"
    r.register_check("manual", lambda c, q: review("NEW_VENDOR") if c.item_id.startswith("new") else None)
    r.register_decision_check("many", lambda items, q: review("MANY_ITEMS") if len(items) > 2 else None)
    d = r.evaluate(req(("new-1", 3), ("b", 2), ("c", 1), rid="m1"))
    assert d.status == "PENDING_APPROVAL"
    assert {(x.item_id, x.reason) for x in d.review_required} == {("new-1", "manual:NEW_VENDOR"), (None, "many:MANY_ITEMS")}
    blocked = r.evaluate(req(("x", 1), rid="m2", purpose="capex"))
    assert blocked.status == "PENDING_APPROVAL"


def test_review_api_records_token_subject():
    r = RecGuard()
    r.load_policy_pack(PACK)
    tokens = {"s" * 32: {"tenant_id": "acme", "scopes": ["recommend:serve"]},
              "v" * 32: {"tenant_id": "acme", "scopes": ["decisions:review"], "subject": "priya.cfo"}}
    client = TestClient(create_app(r, tokens))
    h = lambda t: {"Authorization": "Bearer " + t}
    d = client.post("/v1/recommendations/evaluate", headers=h("s" * 32), json={
        "tenant_id": "acme", "purpose": "plan", "request_id": "x", "k": 1,
        "candidates": [{"item_id": "large", "tenant_id": "acme", "score": 500}]}).json()
    assert d["status"] == "PENDING_APPROVAL"
    assert client.get("/v1/reviews/acme", headers=h("s" * 32)).status_code == 403
    assert client.get("/v1/reviews/acme", headers=h("v" * 32)).json()["pending"][0]["decision_id"] == d["decision_id"]
    ok = client.post("/v1/reviews", headers=h("v" * 32), json={"tenant_id": "acme", "decision_id": d["decision_id"], "approve": True})
    assert ok.status_code == 200 and ok.json()["status"] == "PASS"
    assert client.post("/v1/recommendations/verify", headers=h("s" * 32), json={
        "tenant_id": "acme", "decision_id": d["decision_id"], "receipt": ok.json()["receipt"], "results": d["results"]}).json()["valid"]
    assert "priya.cfo" in r.db.conn.execute("SELECT reviewer FROM decisions").fetchone()["reviewer"]


def test_rule_needs_exactly_one_outcome():
    from recguard import load_pack
    with pytest.raises(Exception, match="exactly one"):
        load_pack({**PACK, "checks": [{"name": "x", "rules": [{"reject": "A", "review": "B", "if": "True"}]}]})
