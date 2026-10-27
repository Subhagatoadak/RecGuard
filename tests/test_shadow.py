from fastapi.testclient import TestClient
from recguard import Candidate, Request, RecGuard
from recguard.api import create_app

LIVE = {"recguard": 1, "name": "live", "policies": [{"policy_id": "base", "version": 1, "require_evidence": False,
                                                     "denied_categories": ["old-ban"]}]}
SHADOW = {"recguard": 1, "name": "next", "mode": "shadow",
          "policies": [{"policy_id": "base", "version": 2, "require_evidence": False, "denied_categories": ["new-ban"]}],
          "constants": {"floor": 0.5},
          "checks": [{"name": "quality", "rules": [{"reject": "LOW_SCORE", "if": "item.score < floor"}]}],
          "decision_checks": [{"name": "small", "rules": [{"reject": "TOO_MANY", "if": "len(items) > 2"}]}]}


def req(*items, rid="r"):
    return Request(tenant_id="acme", request_id=rid, purpose="shop", k=5,
                   candidates=[Candidate(item_id=i, tenant_id="acme", score=s, categories=c) for i, s, c in items])


def test_shadow_pack_reports_but_never_changes_outcomes():
    r = RecGuard()
    r.load_policy_pack(LIVE)
    baseline = r.evaluate(req(("a", 0.9, []), ("b", 0.8, ["new-ban"]), ("c", 0.2, []), ("d", 0.7, ["old-ban"])))
    summary = r.load_policy_pack(SHADOW)
    assert summary["mode"] == "shadow"
    d = r.evaluate(req(("a", 0.9, []), ("b", 0.8, ["new-ban"]), ("c", 0.2, []), ("d", 0.7, ["old-ban"])))
    assert [x.item_id for x in d.results] == [x.item_id for x in baseline.results] == ["a", "b", "c"]
    assert d.policy_fingerprint == baseline.policy_fingerprint      # shadow packs don't touch receipts
    assert {(x.item_id, x.reason) for x in d.shadow.would_reject} == {("b", "DENIED_CATEGORY"), ("c", "quality:LOW_SCORE")}
    assert d.shadow.would_admit == ["d"]                            # old-ban dropped in the v2 policy
    assert d.shadow.decision_violations == []                        # only "a" survives the shadow rules
    wide = r.evaluate(req(("a", 0.9, []), ("e", 0.9, []), ("f", 0.9, []), rid="r2"))
    assert wide.shadow.decision_violations == ["small:TOO_MANY"] and wide.shadow.would_reject == []
    quiet = r.evaluate(req(("a", 0.9, []), rid="r3"))
    report = r.shadow_report("acme")
    assert report["decisions_evaluated"] == 3 and report["decisions_affected"] == 2 and quiet.shadow.would_reject == []
    assert report["would_reject_items"] == {"DENIED_CATEGORY": 1, "quality:LOW_SCORE": 1}
    assert report["decision_violations"] == {"small:TOO_MANY": 1} and report["would_admit_items"] == 1


def test_enforcing_the_pack_ends_the_shadow_run_and_applies_the_rules():
    r = RecGuard()
    r.load_policy_pack(LIVE)
    r.load_policy_pack(SHADOW)
    enforced = r.load_policy_pack({**SHADOW, "mode": "enforce"})
    assert enforced["mode"] == "enforce" and r.shadow_report("acme")["shadow_packs"] == []
    d = r.evaluate(req(("a", 0.9, []), ("b", 0.8, ["new-ban"]), ("c", 0.2, []), ("d", 0.7, ["old-ban"])))
    assert d.shadow is None and [x.item_id for x in d.results] == ["a", "d"]


def test_broken_shadow_rule_never_breaks_serving():
    r = RecGuard()
    r.load_policy_pack(LIVE)
    r.load_policy_pack({"recguard": 1, "name": "bad", "mode": "shadow", "context": ["T"],
                        "checks": [{"name": "boom", "rules": [{"reject": "X", "if": "T['missing']"}]}]}, context={"T": {}})
    d = r.evaluate(req(("a", 0.9, [])))
    assert d.status == "PASS" and d.shadow.would_reject[0].reason == "CHECK_ERROR:boom"


def test_shadow_endpoint():
    r = RecGuard()
    r.load_policy_pack(LIVE)
    r.load_policy_pack(SHADOW)
    r.evaluate(req(("a", 0.1, [])))
    client = TestClient(create_app(r, {"m" * 32: {"tenant_id": "acme", "scopes": ["metrics:read"]}}))
    body = client.get("/v1/shadow/acme", headers={"Authorization": "Bearer " + "m" * 32}).json()
    assert body["shadow_packs"] == ["next"] and body["would_reject_items"] == {"quality:LOW_SCORE": 1}


def test_v1_database_gains_v2_columns(tmp_path):
    import sqlite3
    path = str(tmp_path / "v1.sqlite")
    RecGuard(path, signing_key=b"K" * 32).db.conn.close()
    conn = sqlite3.connect(path)
    for column in ("shadow", "approval", "reviews", "reviewer"):
        conn.execute(f"ALTER TABLE decisions DROP COLUMN {column}")
    conn.execute("PRAGMA user_version=1"); conn.commit(); conn.close()
    r = RecGuard(path, signing_key=b"K" * 32)
    r.load_policy_pack(LIVE)
    r.load_policy_pack(SHADOW)
    assert r.evaluate(req(("a", 0.1, []))).shadow.would_reject[0].reason == "quality:LOW_SCORE"
    assert r.db.conn.execute("PRAGMA user_version").fetchone()[0] == 2
