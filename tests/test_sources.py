import json, os, textwrap, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
import pytest
from recguard import Candidate, Request, RecGuard, load_pack

PACK = """
recguard: 1
name: catalog-rules
sources:
  CATALOG: {type: file, path: catalog.csv, key: sku}
constants: {max_price: 100}
policies: [{policy_id: base, version: 1, require_evidence: false}]
checks:
  - name: catalog
    let: {row: "get(CATALOG, item.item_id)"}
    rules:
      - {reject: NOT_IN_CATALOG, if: "row is None"}
      - {reject: TOO_EXPENSIVE, if: "row.price > max_price"}
tests:
  - {name: inline source, context: {CATALOG: {a: {price: 500}}}, item: {item_id: a}, expect: catalog:TOO_EXPENSIVE}
"""


def req(*ids):
    return Request(tenant_id="acme", request_id="r", purpose="p", k=5,
                   candidates=[Candidate(item_id=i, tenant_id="acme", score=1) for i in ids])


def setup(tmp_path, csv_text="sku,price\na,10\nb,500\n", pack=PACK):
    (tmp_path / "catalog.csv").write_text(csv_text)
    path = tmp_path / "pack.yaml"
    path.write_text(textwrap.dedent(pack))
    return path


def test_file_source_feeds_checks_and_versions_the_data(tmp_path):
    path = setup(tmp_path)
    r = RecGuard()
    summary = r.load_policy_pack(path)
    assert summary["data_version"].startswith("sources:")
    d = r.evaluate(req("a", "b", "z"))
    assert [x.item_id for x in d.results] == ["a"]
    assert {x.item_id: x.reason for x in d.rejections} == {"b": "catalog:TOO_EXPENSIVE", "z": "catalog:NOT_IN_CATALOG"}
    assert all(t["passed"] for t in load_pack(path).run_tests())
    # unchanged data: refresh is a no-op and receipts stay valid
    assert r.refresh_policy_packs(force=True) == [{"pack": "catalog-rules", "changed": False}]
    assert r.verify("acme", d.decision_id, d.receipt, d.results)
    # new data: reload, new fingerprint, new verdicts
    (tmp_path / "catalog.csv").write_text("sku,price\na,10\nb,50\n")
    assert r.refresh_policy_packs(force=True)[0]["changed"] is True
    assert not r.verify("acme", d.decision_id, d.receipt, d.results)
    assert [x.item_id for x in r.evaluate(req("a", "b")).results] == ["a", "b"]


def test_refresh_hot_reloads_edited_rules(tmp_path):
    path = setup(tmp_path)
    r = RecGuard()
    r.load_policy_pack(path)
    path.write_text(textwrap.dedent(PACK).replace("max_price: 100", "max_price: 5"))
    r.refresh_policy_packs(force=True)
    assert r.evaluate(req("a")).rejections[0].reason == "catalog:TOO_EXPENSIVE"


def test_host_context_overrides_sources(tmp_path):
    path = setup(tmp_path)
    r = RecGuard()
    summary = r.load_policy_pack(path, context={"CATALOG": {"b": {"price": 1}}}, data_version="host-v1")
    assert summary["data_version"] == "host-v1"  # nothing fetched
    assert [x.item_id for x in r.evaluate(req("a", "b")).results] == ["b"]


class _Handler(BaseHTTPRequestHandler):
    payload = {"a": {"price": 10}}
    up = True

    def do_GET(self):
        if not _Handler.up:
            self.send_response(503); self.end_headers(); return
        if self.headers.get("Authorization") != "Bearer s3cret":
            self.send_response(401); self.end_headers(); return
        body = json.dumps(_Handler.payload).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def http_source():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _Handler.up, _Handler.payload = True, {"a": {"price": 10}}
    yield f"http://127.0.0.1:{server.server_port}/catalog"
    server.shutdown()


def test_http_source_with_env_header_staleness_and_auto_refresh(tmp_path, http_source, monkeypatch):
    monkeypatch.setenv("CATALOG_TOKEN", "s3cret")
    pack = PACK.replace("CATALOG: {type: file, path: catalog.csv, key: sku}",
                        f"CATALOG: {{type: http, url: '{http_source}', headers: {{Authorization: 'Bearer ${{CATALOG_TOKEN}}'}}, "
                        "refresh_seconds: 5, max_age_seconds: 5}")
    path = setup(tmp_path, pack=pack)
    r = RecGuard()
    r.load_policy_pack(path)
    assert [x.item_id for x in r.evaluate(req("a")).results] == ["a"]
    # source goes down: last good data keeps serving until max_age, then checks fail closed
    _Handler.up = False
    result = r.refresh_policy_packs(force=True)[0]
    assert "error" in result and r.policy_packs()[0]["last_error"]
    assert [x.item_id for x in r.evaluate(req("a")).results] == ["a"]
    r._packs["catalog-rules"]["state"]["fresh_at"] -= 10       # simulate 10 s without a good fetch
    blocked = r.evaluate(req("a"))
    assert blocked.status == "BLOCKED" and blocked.rejections[0].reason == "CHECK_ERROR:catalog"
    # source recovers with new data; the background refresher picks it up
    _Handler.up, _Handler.payload = True, {"a": {"price": 1000}}
    r._packs["catalog-rules"]["checked_at"] -= 10
    stop = r.start_auto_refresh(0.05)
    deadline = time.time() + 5
    while time.time() < deadline and r.evaluate(req("a")).status != "REPAIRED":
        time.sleep(0.05)
    stop.set()
    assert r.evaluate(req("a")).rejections[0].reason == "catalog:TOO_EXPENSIVE"


def test_missing_env_header_is_a_clear_error(tmp_path, http_source, monkeypatch):
    monkeypatch.delenv("CATALOG_TOKEN", raising=False)
    pack = PACK.replace("CATALOG: {type: file, path: catalog.csv, key: sku}",
                        f"CATALOG: {{type: http, url: '{http_source}', headers: {{Authorization: 'Bearer ${{CATALOG_TOKEN}}'}}}}")
    with pytest.raises(Exception, match="CATALOG_TOKEN"):
        RecGuard().load_policy_pack(setup(tmp_path, pack=pack))


def test_server_runs_data_driven_packs_and_lists_them(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from recguard.api import from_environment
    path = setup(tmp_path)
    admin, serve = "a" * 32, "s" * 32
    monkeypatch.setenv("RECGUARD_TOKENS_JSON", json.dumps({
        admin: {"tenant_id": "*", "scopes": ["policy:read", "policy:write"]},
        serve: {"tenant_id": "acme", "scopes": ["recommend:serve"]}}))
    monkeypatch.setenv("RECGUARD_SIGNING_KEY", "k" * 40)
    monkeypatch.setenv("RECGUARD_DB", str(tmp_path / "db.sqlite"))
    monkeypatch.setenv("RECGUARD_POLICY_PACKS", str(path))
    client = TestClient(from_environment())
    body = {"tenant_id": "acme", "purpose": "p", "request_id": "r", "k": 2,
            "candidates": [{"item_id": "a", "tenant_id": "acme", "score": 1}, {"item_id": "b", "tenant_id": "acme", "score": 1}]}
    d = client.post("/v1/recommendations/evaluate", json=body, headers={"Authorization": "Bearer " + serve}).json()
    assert [x["item_id"] for x in d["results"]] == ["a"]
    packs = client.get("/v1/policy-packs", headers={"Authorization": "Bearer " + admin}).json()["packs"]
    assert packs[0]["pack"] == "catalog-rules" and packs[0]["sources"] == ["CATALOG"]
    (tmp_path / "catalog.csv").write_text("sku,price\na,10\nb,20\n")
    res = client.post("/v1/policy-packs/refresh", headers={"Authorization": "Bearer " + admin}).json()["results"]
    assert res[0]["changed"] is True
    d2 = client.post("/v1/recommendations/evaluate", json={**body, "request_id": "r2"}, headers={"Authorization": "Bearer " + serve}).json()
    assert [x["item_id"] for x in d2["results"]] == ["a", "b"]
