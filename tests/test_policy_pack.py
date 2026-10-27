import json
import re
import textwrap
import pytest
from recguard import Candidate, Request, RecGuard, PackError, load_pack
from recguard.__main__ import main as cli

CATALOG = {"a": {"price": 100, "tags": ["ok"]}, "b": {"price": 9000, "tags": ["ok"]}, "c": {"price": 50, "tags": ["recalled"]}}

PACK = """
recguard: 1
name: shop
context: [CATALOG]
constants: {max_price: 5000}
policies:
  - {policy_id: base, version: 1, require_evidence: false}
checks:
  - name: catalog
    let:
      trusted: "get(CATALOG, item.item_id)"
    rules:
      - {reject: NOT_IN_CATALOG, if: "trusted is None"}
      - {reject: TOO_EXPENSIVE, if: "trusted.price > max_price"}
      - {reject: RECALLED, if: "'recalled' in trusted.tags", unless: "request.purpose == 'audit'"}
"""


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(textwrap.dedent(text))
    return path


def req(*ids, purpose="shop", **kw):
    return Request(tenant_id="acme", request_id="r", purpose=purpose, k=5,
                   candidates=[Candidate(item_id=i, tenant_id="acme", score=1.0, **kw) for i in ids])


def test_yaml_pack_registers_policies_and_declarative_checks(tmp_path):
    r = RecGuard()
    summary = r.load_policy_pack(write(tmp_path, "shop.yaml", PACK), context={"CATALOG": CATALOG})
    assert summary["policies_registered"] == ["base@v1"] and summary["checks"] == ["catalog"]
    d = r.evaluate(req("a", "b", "c", "ghost"))
    assert [x.item_id for x in d.results] == ["a"]
    assert {x.item_id: x.reason for x in d.rejections} == {
        "b": "catalog:TOO_EXPENSIVE", "c": "catalog:RECALLED", "ghost": "catalog:NOT_IN_CATALOG"}
    assert [x.item_id for x in r.evaluate(req("c", purpose="audit")).results] == ["c"]  # `unless`


def test_json_pack_and_mapping_need_no_yaml(tmp_path):
    import yaml
    data = yaml.safe_load(PACK)
    path = tmp_path / "shop.json"
    path.write_text(json.dumps(data))
    for source in (path, data):
        r = RecGuard()
        r.load_policy_pack(source, context={"CATALOG": CATALOG})
        assert [x.item_id for x in r.evaluate(req("a", "b")).results] == ["a"]


def test_parse_item_id_groups_and_aggregates(tmp_path):
    pack = write(tmp_path, "plan.yaml", """
        recguard: 1
        name: plan
        context: [PLANS]
        constants: {limit: 30, budget: 100}
        policies: [{policy_id: p, version: 1, require_evidence: false}]
        checks:
          - name: plan
            parse_item_id: '(?P<channel>[a-z]+):(?P<action>increase|decrease):(?P<pct>\\d+)'
            let:
              lines: "PLANS[channel]"
              totals: "{w: sum(x['amount'] for x in lines if x['week'] == w) for w in [1, 2]}"
            rules:
              - {reject: TOO_BIG, if: "pct > limit"}
              - {reject: OVER_BUDGET, if: "any(v > budget for v in values(totals))"}
        """)
    plans = {"tv": [{"week": 1, "amount": 60}, {"week": 1, "amount": 60}, {"week": 2, "amount": 10}],
             "web": [{"week": 1, "amount": 50}, {"week": 2, "amount": 50}]}
    r = RecGuard()
    r.load_policy_pack(pack, context={"PLANS": plans})
    d = r.evaluate(req("web:increase:10", "web:increase:45", "tv:decrease:5", "bogus"))
    assert [x.item_id for x in d.results] == ["web:increase:10"]
    assert {x.item_id: x.reason for x in d.rejections} == {
        "web:increase:45": "plan:TOO_BIG", "tv:decrease:5": "plan:OVER_BUDGET", "bogus": "plan:ITEM_ID_UNPARSEABLE"}


@pytest.mark.parametrize("expr,message", [
    ("item.__class__", "attribute '__class__'"),
    ("__import__('os')", "name '__import__'"),
    ("item.item_id.upper()", "only plain function calls"),
    ("(lambda: 1)()", "only plain function calls"),
    ("[f for f in [len]][0](item)", "only plain function calls"),
    ("open('x')", "unknown name(s) ['open']"),
    ("(x := 1)", "NamedExpr is not allowed"),
    ("item is 3", "may only compare with None"),
    ("f'{item}'", "JoinedStr is not allowed"),
    ("max_pricee > 1", "unknown name(s) ['max_pricee']"),
    ("len(*[1])", "positional arguments only"),
    ("max(1, key=abs)", "positional arguments only"),
])
def test_disallowed_syntax_and_typos_fail_at_load(expr, message):
    data = {"recguard": 1, "name": "bad", "constants": {"max_price": 1},
            "checks": [{"name": "c", "rules": [{"reject": "X", "if": expr}]}]}
    with pytest.raises(PackError, match=re.escape(message)):
        load_pack(data).validate_names()


def test_runtime_errors_and_runaway_loops_fail_closed():
    data = {"recguard": 1, "name": "rt", "context": ["DATA"],
            "policies": [{"policy_id": "p", "version": 1, "require_evidence": False}],
            "checks": [{"name": "boom", "rules": [{"reject": "X", "if": "DATA['missing'] > 1"}]},
                       {"name": "loop", "rules": [{"reject": "Y", "if": "sum(1 for a in range(9000) for b in range(9000)) < 0"}]}]}
    r = RecGuard()
    r.load_policy_pack(data, context={"DATA": {}})
    d = r.evaluate(req("a"))
    assert d.status == "BLOCKED" and d.rejections[0].reason == "CHECK_ERROR:boom"
    r.unregister_check("boom")
    assert r.evaluate(req("a")).rejections[0].reason == "CHECK_ERROR:loop"


def test_missing_context_and_reserved_names_are_rejected():
    data = {"recguard": 1, "name": "ctx", "context": ["CATALOG"], "checks": [{"name": "c", "rules": [{"reject": "X", "if": "False"}]}]}
    with pytest.raises(PackError, match="context values not provided"):
        RecGuard().load_policy_pack(data)
    with pytest.raises(PackError, match="reserved"):
        load_pack({**data, "context": [], "constants": {"item": 1}}).validate_names()


def test_reload_is_idempotent_and_edits_invalidate_receipts(tmp_path):
    r = RecGuard()
    path = write(tmp_path, "shop.yaml", PACK)
    r.load_policy_pack(path, context={"CATALOG": CATALOG})
    d = r.evaluate(req("a"))
    again = r.load_policy_pack(path, context={"CATALOG": CATALOG})
    assert again["policies_unchanged"] == ["base@v1"] and again["policies_registered"] == []
    assert r.verify("acme", d.decision_id, d.receipt, d.results)  # identical pack: same fingerprint
    path.write_text(textwrap.dedent(PACK).replace("max_price: 5000", "max_price: 50"))
    r.load_policy_pack(path, context={"CATALOG": CATALOG})
    assert not r.verify("acme", d.decision_id, d.receipt, d.results)  # edited rule: receipt invalid
    assert [x.reason for x in r.evaluate(req("a")).rejections] == ["catalog:TOO_EXPENSIVE"]


def test_changed_policy_body_needs_new_version(tmp_path):
    r = RecGuard()
    path = write(tmp_path, "shop.yaml", PACK)
    r.load_policy_pack(path, context={"CATALOG": CATALOG})
    path.write_text(textwrap.dedent(PACK).replace("require_evidence: false", "require_evidence: true"))
    with pytest.raises(Exception, match="VERSION_NOT_MONOTONIC"):
        r.load_policy_pack(path, context={"CATALOG": CATALOG})


def test_pack_checks_cannot_clobber_code_checks():
    r = RecGuard()
    r.register_check("catalog", lambda c, q: None)
    with pytest.raises(ValueError, match="outside pack"):
        r.load_policy_pack({"recguard": 1, "name": "x", "checks": [{"name": "catalog", "rules": [{"reject": "X", "if": "False"}]}]})


def test_includes_merge_and_detect_cycles(tmp_path):
    write(tmp_path, "base.yaml", """
        recguard: 1
        name: base
        constants: {cap: 2}
        policies: [{policy_id: g, version: 1, require_evidence: false}]
        """)
    full = write(tmp_path, "full.yaml", """
        recguard: 1
        name: full
        include: [base.yaml]
        checks: [{name: cap, rules: [{reject: OVER, if: "item.score > cap"}]}]
        """)
    pack = load_pack(full)
    assert pack.name == "full" and [p.policy_id for p in pack.policies] == ["g"] and pack.constants == {"cap": 2}
    write(tmp_path, "a.yaml", "recguard: 1\nname: a\ninclude: [b.yaml]\n")
    write(tmp_path, "b.yaml", "recguard: 1\nname: b\ninclude: [a.yaml]\n")
    with pytest.raises(PackError, match="include cycle"):
        load_pack(tmp_path / "a.yaml")


def test_cli_validate(tmp_path, capsys):
    good = write(tmp_path, "good.yaml", PACK)
    bad = write(tmp_path, "bad.yaml", PACK.replace("trusted.price", "trusted.__dict__"))
    with pytest.raises(SystemExit) as ok:
        cli(["policy", "validate", str(good)])
    assert ok.value.code == 0 and "pack 'shop'" in capsys.readouterr().out
    with pytest.raises(SystemExit) as fail:
        cli(["policy", "validate", str(good), str(bad)])
    assert fail.value.code == 1 and "__dict__" in capsys.readouterr().err


def test_attribute_access_on_objects_but_not_functions_or_classes():
    from dataclasses import dataclass

    @dataclass(frozen=True)
    class Line:
        amount: int

    data = {"recguard": 1, "name": "attrs", "context": ["LINES", "helper", "Line"],
            "policies": [{"policy_id": "p", "version": 1, "require_evidence": False}],
            "checks": [{"name": "obj", "rules": [{"reject": "BIG", "if": "sum(x.amount for x in LINES) > 10"}]},
                       {"name": "fn", "applies_when": "item.item_id == 'f'", "rules": [{"reject": "X", "if": "helper.anything"}]},
                       {"name": "cls", "applies_when": "item.item_id == 'c'", "rules": [{"reject": "X", "if": "Line.mro"}]}]}
    r = RecGuard()
    r.load_policy_pack(data, context={"LINES": [Line(4), Line(5)], "helper": len, "Line": Line})
    assert [x.item_id for x in r.evaluate(req("ok")).results] == ["ok"]          # dataclass attributes work
    assert r.evaluate(req("f")).rejections[0].reason == "CHECK_ERROR:fn"        # function attributes blocked
    assert r.evaluate(req("c")).rejections[0].reason == "CHECK_ERROR:cls"       # class attributes blocked


def test_disabled_policy_version_retires_it():
    r = RecGuard()
    r.load_policy_pack({"recguard": 1, "name": "p", "policies": [
        {"policy_id": "base", "version": 1, "require_evidence": False},
        {"policy_id": "strict", "version": 1, "denied_categories": ["x"], "require_evidence": False}]})
    assert r.evaluate(req("a", categories=["x"])).status == "BLOCKED"
    r.load_policy_pack({"recguard": 1, "name": "p", "policies": [
        {"policy_id": "base", "version": 1, "require_evidence": False},
        {"policy_id": "strict", "version": 2, "enabled": False}]})
    assert r.evaluate(req("a", categories=["x"])).status == "PASS"
    assert "strict" not in str(r.effective_policy("acme", "shop"))


def test_data_version_is_part_of_the_fingerprint(tmp_path):
    r = RecGuard()
    path = write(tmp_path, "shop.yaml", PACK)
    r.load_policy_pack(path, context={"CATALOG": CATALOG}, data_version="catalog-1")
    d = r.evaluate(req("a"))
    r.load_policy_pack(path, context={"CATALOG": CATALOG}, data_version="catalog-1")
    assert r.verify("acme", d.decision_id, d.receipt, d.results)
    r.load_policy_pack(path, context={"CATALOG": CATALOG}, data_version="catalog-2")
    assert not r.verify("acme", d.decision_id, d.receipt, d.results)


def test_pack_tests_run_in_validate(tmp_path, capsys):
    tested = PACK + """
tests:
  - name: cheap item passes
    context: {CATALOG: {a: {price: 1, tags: []}}}
    item: {item_id: a}
    expect: null
  - name: expensive item rejected
    context: {CATALOG: {a: {price: 9999, tags: []}}}
    item: {item_id: a}
    expect: catalog:TOO_EXPENSIVE
  - name: recalled item allowed for audits
    context: {CATALOG: {a: {price: 1, tags: [recalled]}}}
    item: {item_id: a}
    request: {purpose: audit}
    expect: null
"""
    good = write(tmp_path, "good.yaml", tested)
    assert all(r["passed"] for r in load_pack(good).run_tests())
    with pytest.raises(SystemExit) as ok:
        cli(["policy", "validate", str(good)])
    assert ok.value.code == 0 and "tests 3/3 passed" in capsys.readouterr().out
    bad = write(tmp_path, "bad.yaml", tested.replace("expect: catalog:TOO_EXPENSIVE", "expect: null"))
    with pytest.raises(SystemExit) as fail:
        cli(["policy", "validate", str(bad)])
    assert fail.value.code == 1 and "got 'catalog:TOO_EXPENSIVE'" in capsys.readouterr().err


def test_schema_command(capsys):
    cli(["policy", "schema"])
    schema = json.loads(capsys.readouterr().out)
    assert schema["title"] == "PolicyPack" and "checks" in schema["properties"]


def test_api_loads_packs_at_startup_and_limits_body_size(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from recguard.api import from_environment
    pack = write(tmp_path, "server.yaml", """
        recguard: 1
        name: server
        constants: {blocked: [bad]}
        policies: [{policy_id: base, version: 1, require_evidence: false}]
        checks: [{name: block, rules: [{reject: BLOCKED_ID, if: "item.item_id in blocked"}]}]
        """)
    token = "t" * 32
    monkeypatch.setenv("RECGUARD_TOKENS_JSON", json.dumps({token: {"tenant_id": "acme", "scopes": ["recommend:serve"]}}))
    monkeypatch.setenv("RECGUARD_SIGNING_KEY", "k" * 40)
    monkeypatch.setenv("RECGUARD_DB", str(tmp_path / "db.sqlite"))
    monkeypatch.setenv("RECGUARD_POLICY_PACKS", str(pack))
    monkeypatch.setenv("RECGUARD_MAX_BODY_BYTES", "2000")
    client = TestClient(from_environment())
    body = {"tenant_id": "acme", "purpose": "p", "request_id": "r", "k": 2,
            "candidates": [{"item_id": "ok", "tenant_id": "acme", "score": 1}, {"item_id": "bad", "tenant_id": "acme", "score": 2}]}
    d = client.post("/v1/recommendations/evaluate", json=body, headers={"Authorization": "Bearer " + token}).json()
    assert [x["item_id"] for x in d["results"]] == ["ok"] and d["rejections"][0]["reason"] == "block:BLOCKED_ID"
    big = {**body, "candidates": body["candidates"] * 40}
    assert client.post("/v1/recommendations/evaluate", json=big, headers={"Authorization": "Bearer " + token}).status_code == 413
