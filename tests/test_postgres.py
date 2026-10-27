"""Runs against a real PostgreSQL when RECGUARD_TEST_PG_URL is set (CI provides one)."""
import os, threading, time, uuid
import pytest
from recguard import Candidate, Denied, Outcome, Policy, Request, RecGuard, Telemetry

PG = os.environ.get("RECGUARD_TEST_PG_URL")
pytestmark = pytest.mark.skipif(not PG, reason="set RECGUARD_TEST_PG_URL to run PostgreSQL tests")
KEY = b"P" * 32


@pytest.fixture
def tenant():
    return "t" + uuid.uuid4().hex[:12]  # isolate runs on a shared database


def req(tenant, *ids, rid=None, purpose="shop", k=3):
    return Request(tenant_id=tenant, request_id=rid or uuid.uuid4().hex, purpose=purpose, k=k,
                   candidates=[Candidate(item_id=i, tenant_id=tenant, score=1.0 / (n + 1), evidence_ids=["e"],
                                         categories=["bad"] if i.startswith("bad") else [])
                               for n, i in enumerate(ids)])


def test_full_lifecycle_on_postgres(tenant):
    r = RecGuard(PG, signing_key=KEY)
    r.register_policy(Policy(policy_id=f"p-{tenant}", version=1, tenant_id=tenant, denied_categories=["bad"]))
    with pytest.raises(Denied, match="VERSION_NOT_MONOTONIC"):
        r.register_policy(Policy(policy_id=f"p-{tenant}", version=1, tenant_id=tenant))
    d = r.evaluate(req(tenant, "a", "bad-1", "b"))
    assert d.status == "REPAIRED" and [x.item_id for x in d.results] == ["a", "b"]
    assert r.verify(tenant, d.decision_id, d.receipt, d.results)
    r.presented(tenant, d.decision_id, d.receipt, d.results)
    r.presented(tenant, d.decision_id, d.receipt, d.results)  # ON CONFLICT DO NOTHING path
    r.event(Telemetry(event_id="e1", tenant_id=tenant, decision_id=d.decision_id, event_type="CLICK", latency_ms=12.5, cost_usd=0.01))
    with pytest.raises(Denied, match="DUPLICATE_EVENT"):
        r.event(Telemetry(event_id="e1", tenant_id=tenant, event_type="CLICK"))
    r.outcome(Outcome(outcome_id="o1", tenant_id=tenant, decision_id=d.decision_id, reward=1, outcome_type="CONVERSION"))
    with pytest.raises(Denied, match="DUPLICATE_OR_ALREADY_REWARDED"):
        r.outcome(Outcome(outcome_id="o2", tenant_id=tenant, decision_id=d.decision_id, reward=1, outcome_type="CONVERSION"))
    m = r.metrics(tenant)
    assert m["decisions"] == 1 and m["outcomes"] == 1 and m["mean_reward"] == 1.0 and m["observed_ctr"] == 1.0
    assert m["reason_counts"] == {"DENIED_CATEGORY": 1} and m["eligibility_rate"] == round(2 / 3, 4)
    assert m["conversion_per_presented_decision"] == 1.0 and m["audit_chain_valid"]
    assert isinstance(m["eligibility_rate"], float) and isinstance(m["token_count_logged"], int)
    head = r.db.audit_head(tenant)
    assert r.db.audit_verify(tenant, head["head"])["valid"] and head["entries"] >= 4


def test_packs_shadow_approval_purge_and_learning_on_postgres(tenant):
    r = RecGuard(PG, signing_key=KEY)
    r.load_policy_pack({"recguard": 1, "name": f"pk-{tenant}", "policies": [
        {"policy_id": f"base-{tenant}", "version": 1, "tenant_id": tenant, "require_evidence": False, "allow_experiment": True}],
        "checks": [{"name": f"c-{tenant}", "rules": [{"review": "BIG", "if": "item.item_id == 'big'"}]}]})
    r.load_policy_pack({"recguard": 1, "name": f"sh-{tenant}", "mode": "shadow",
                        "checks": [{"name": f"s-{tenant}", "rules": [{"reject": "NO_B", "if": "item.item_id == 'b'"}]}]})
    held = r.evaluate(req(tenant, "big", "b"))
    assert held.status == "PENDING_APPROVAL" and held.shadow.would_reject[0].reason == f"s-{tenant}:NO_B"
    assert r.pending_reviews(tenant)[0]["decision_id"] == held.decision_id
    ok = r.review(tenant, held.decision_id, True, "reviewer@x")
    assert r.verify(tenant, held.decision_id, ok["receipt"], held.results)
    assert r.shadow_report(tenant)["would_reject_items"] == {f"s-{tenant}:NO_B": 1}
    r.mode(tenant, "EXPERIMENT")
    for i in range(30):
        d = r.evaluate(req(tenant, "x", "y", rid=f"exp-{i}"))
        r.presented(tenant, d.decision_id, d.receipt, d.results)
        r.outcome(Outcome(outcome_id=f"o{i}", tenant_id=tenant, decision_id=d.decision_id, reward=0.5, outcome_type="RELEVANCE"))
    assert r.assess_challenger(tenant, "diverse")["reason"] in ("INSUFFICIENT_HOLDOUT", "INSUFFICIENT_OVERLAP", "NO_CONSERVATIVE_IMPROVEMENT")
    with r.db.tx() as c:
        c.execute("UPDATE decisions SET at=? WHERE tenant=?", (time.time() - 10_000, tenant))
    deleted = r.purge(tenant, 3600)
    assert deleted["decisions"] == 31 and r.metrics(tenant)["decisions"] == 0 and r.db.audit_verify(tenant)["valid"]


def test_two_workers_and_concurrent_threads_keep_one_audit_chain(tenant):
    workers = [RecGuard(PG, signing_key=KEY), RecGuard(PG, signing_key=KEY)]  # like two uvicorn processes
    workers[0].register_policy(Policy(policy_id=f"w-{tenant}", version=1, tenant_id=tenant, require_evidence=False))
    errors = []

    def run(engine, n):
        try:
            for i in range(10):
                d = engine.evaluate(req(tenant, "a", "b", rid=f"{n}-{i}"))
                assert engine.verify(tenant, d.decision_id, d.receipt, d.results)
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(workers[n % 2], n)) for n in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert not errors, errors
    assert workers[1].metrics(tenant)["decisions"] == 80
    assert workers[0].db.audit_verify(tenant)["valid"] and workers[1].db.audit_verify(tenant)["checked"] == 81
