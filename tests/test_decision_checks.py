import pytest
from recguard import Candidate, Request, RecGuard, load_pack

SPEND = {"tv:inc": 50, "yt:inc": 30, "meta:dec": -40, "search:inc": 25}

PACK = {
    "recguard": 1, "name": "plan-rules", "context": ["SPEND"],
    "constants": {"tolerance": 10, "max_increases": 2},
    "policies": [{"policy_id": "base", "version": 1, "require_evidence": False, "max_results": 10}],
    "decision_checks": [
        {"name": "few-increases", "on_violation": "trim",
         "rules": [{"reject": "TOO_MANY_INCREASES", "if": "len([x for x in items if SPEND[x.item_id] > 0]) > max_increases"}]},
        {"name": "budget-neutral", "on_violation": "block",
         "rules": [{"reject": "NOT_BUDGET_NEUTRAL", "if": "abs(sum(SPEND[x.item_id] for x in items)) > tolerance"}]},
    ],
}


def req(*ids, k=10):
    scores = {i: 10 - n for n, i in enumerate(ids)}
    return Request(tenant_id="acme", request_id="r", purpose="plan", k=k,
                   candidates=[Candidate(item_id=i, tenant_id="acme", score=scores[i]) for i in ids])


def test_trim_drops_lowest_ranked_until_rule_passes_then_block_checks_the_rest():
    r = RecGuard()
    r.load_policy_pack(PACK, context={"SPEND": SPEND})
    # tv+yt+search are three increases: trim drops search (lowest ranked); tv+yt-meta = +40 -> not neutral -> block
    d = r.evaluate(req("tv:inc", "yt:inc", "meta:dec", "search:inc"))
    assert d.status == "BLOCKED"
    assert ("search:inc", "few-increases:TOO_MANY_INCREASES") in {(x.item_id, x.reason) for x in d.rejections}
    assert {x.reason for x in d.rejections if x.source == "decision"} >= {"budget-neutral:NOT_BUDGET_NEUTRAL"}
    ok = r.evaluate(req("yt:inc", "meta:dec"))  # +30 -40 = -10, within tolerance
    assert ok.status == "PASS" and [x.item_id for x in ok.results] == ["yt:inc", "meta:dec"]


def test_trim_counts_as_repair_and_min_results_still_applies():
    pack = {**PACK, "decision_checks": PACK["decision_checks"][:1],
            "policies": [{"policy_id": "base", "version": 1, "require_evidence": False, "min_results": 3}]}
    r = RecGuard()
    r.load_policy_pack(pack, context={"SPEND": SPEND})
    d = r.evaluate(req("tv:inc", "yt:inc", "search:inc", "meta:dec"))
    assert d.status == "REPAIRED" and [x.item_id for x in d.results] == ["tv:inc", "yt:inc", "meta:dec"]
    short = r.evaluate(req("tv:inc", "yt:inc", "search:inc"))  # trimmed to 2 < min_results 3
    assert short.status == "BLOCKED"


def test_decision_check_errors_fail_closed():
    r = RecGuard()
    r.register_decision_check("boom", lambda items, request: 1 / 0)
    r.load_policy_pack({"recguard": 1, "name": "p", "policies": [{"policy_id": "b", "version": 1, "require_evidence": False}]})
    d = r.evaluate(req("a"))
    assert d.status == "BLOCKED" and "CHECK_ERROR:boom" in d.reason_codes


def test_decision_checks_are_in_the_fingerprint_and_pack_tests():
    r = RecGuard()
    r.load_policy_pack(PACK, context={"SPEND": SPEND})
    d = r.evaluate(req("yt:inc", "meta:dec"))
    edited = {**PACK, "constants": {"tolerance": 5, "max_increases": 2}}
    r.load_policy_pack(edited, context={"SPEND": SPEND})
    assert not r.verify("acme", d.decision_id, d.receipt, d.results)
    tested = {**PACK, "tests": [
        {"name": "neutral plan", "context": {"SPEND": SPEND}, "items": [{"item_id": "yt:inc"}, {"item_id": "meta:dec"}], "expect": None},
        {"name": "overspend", "context": {"SPEND": SPEND}, "items": [{"item_id": "tv:inc"}], "expect": "budget-neutral:NOT_BUDGET_NEUTRAL"}]}
    assert all(t["passed"] for t in load_pack(tested).run_tests())


def test_decision_rules_cannot_use_item_and_item_rules_cannot_use_items():
    bad = {**PACK, "decision_checks": [{"name": "x", "rules": [{"reject": "X", "if": "item.score > 1"}]}]}
    with pytest.raises(Exception, match=r"unknown name\(s\) \['item'\]"):
        load_pack(bad).validate_names()


def test_split_lets_decision_rules_read_structured_ids():
    pack = {"recguard": 1, "name": "ids", "constants": {"cap": 50},
            "policies": [{"policy_id": "b", "version": 1, "require_evidence": False}],
            "decision_checks": [{"name": "total-change", "on_violation": "trim",
                                 "rules": [{"reject": "TOO_MUCH_CHANGE", "if": "sum(int(split(x.item_id, ':')[2]) for x in items) > cap"}]}]}
    r = RecGuard()
    r.load_policy_pack(pack)
    d = r.evaluate(req("tv:increase:30", "yt:increase:20", "meta:decrease:10"))
    assert [x.item_id for x in d.results] == ["tv:increase:30", "yt:increase:20"]
