import pytest
from fastapi.testclient import TestClient
from recguard import Policy, RecGuard, check_text
from recguard.api import create_app

FACTS = {"youtube": {"roi": 4.55, "mroi": 4.03}, "search": {"roi": 3.01}, "meta": {"mroi": 0.84}, "crm": {"consent": 0.38}}
TEXT = ("YouTube returns 4.55x on spend. Search returns 6x, our best channel. Meta is saturated at a marginal ROI of 0.84. "
        "Consent coverage is 38%. Budget for 2026 stays flat.")
CLAIMS = [{"subject": "YouTube", "metric": "roi", "value": 4.55, "quote": "YouTube returns 4.55x"},
          {"subject": "search", "metric": "roi", "value": 6, "quote": "Search returns 6x"},
          {"subject": "crm", "metric": "consent", "value": 38, "quote": "Consent coverage is 38%"}]


def test_claims_are_verified_and_every_number_must_be_backed():
    r = check_text(TEXT, CLAIMS, FACTS, ignore=[r"^(19|20)\d\d$"])
    assert r.verdict == "FAIL"
    assert [c.status for c in r.claims] == ["VERIFIED", "MISMATCH", "VERIFIED"]
    assert [s.status for s in r.sentences] == ["VERIFIED", "CONTRADICTED", "UNSUPPORTED_NUMBER", "VERIFIED", "NO_NUMBERS"]
    assert r.unsupported_numbers == ["0.84"]  # true, but nobody claimed it, so it isn't shown
    assert r.safe_text == "YouTube returns 4.55x on spend. Consent coverage is 38%. Budget for 2026 stays flat."


@pytest.mark.parametrize("claim,status", [
    ({"subject": "youtube", "metric": "roi", "value": 4.55, "quote": "YouTube delivers 4.55x"}, "QUOTE_NOT_IN_TEXT"),
    ({"subject": "youtube", "metric": "roi", "value": 4.6, "quote": "YouTube returns 4.55x"}, "VALUE_NOT_IN_QUOTE"),
    ({"subject": "tiktok", "metric": "roi", "value": 4.55, "quote": "YouTube returns 4.55x"}, "UNKNOWN_FACT"),
    ({"subject": "you tube", "metric": "ROI", "value": 4.55, "quote": "YouTube returns 4.55x"}, "VERIFIED"),  # via alias
])
def test_claim_failure_modes(claim, status):
    r = check_text("YouTube returns 4.55x.", [claim], FACTS, aliases={"you tube": "youtube"})
    assert r.claims[0].status == status


def test_rounding_in_text_is_respected():
    # "4.6" is a correct one-decimal rounding of 4.55, so the claim is consistent with its quote ...
    assert check_text("ROI is 4.6.", [{"subject": "youtube", "metric": "roi", "value": 4.55, "quote": "ROI is 4.6"}], FACTS).verdict == "PASS"
    # ... but a quote can't support a value it doesn't round to
    assert check_text("ROI is 4.6.", [{"subject": "youtube", "metric": "roi", "value": 4.7, "quote": "ROI is 4.6"}], FACTS).claims[0].status == "VALUE_NOT_IN_QUOTE"


def test_engine_fact_check_binds_sentences_into_a_receipt():
    r = RecGuard()
    r.register_policy(Policy(policy_id="readout", version=1, purposes=["mmm-readout"], require_evidence=True, max_results=20))
    out = r.fact_check("acme", "mmm-readout", TEXT, CLAIMS, FACTS, ignore=[r"^(19|20)\d\d$"])
    d = out["decision"]
    assert out["safe_text"].startswith("YouTube returns 4.55x") and "Search" not in out["safe_text"]
    assert r.verify("acme", d.decision_id, d.receipt, d.results)
    forged = [d.results[0].model_copy(update={"evidence_ids": ["sha256:" + "0" * 40]})]
    assert not r.verify("acme", d.decision_id, d.receipt, forged)
    nothing = r.fact_check("acme", "mmm-readout", "Search returns 6x.", CLAIMS[1:2], FACTS)
    assert nothing["decision"] is None and nothing["safe_text"] == ""


def test_facts_from_a_pack_source_and_api(tmp_path):
    import json
    (tmp_path / "mmm.json").write_text(json.dumps(FACTS))
    (tmp_path / "pack.yaml").write_text("recguard: 1\nname: mmm\nsources:\n  MMM: {type: file, path: mmm.json}\n"
                                        "policies: [{policy_id: readout, version: 1, require_evidence: true, max_results: 20}]\n")
    r = RecGuard()
    r.load_policy_pack(tmp_path / "pack.yaml")
    client = TestClient(create_app(r, {"s" * 32: {"tenant_id": "acme", "scopes": ["recommend:serve"]}}))
    body = client.post("/v1/fact-check", headers={"Authorization": "Bearer " + "s" * 32}, json={
        "tenant_id": "acme", "purpose": "readout", "text": TEXT, "claims": CLAIMS, "facts_ref": "mmm/MMM",
        "ignore": ["^(19|20)\\\\d\\\\d$"]}).json()
    assert body["report"]["verdict"] == "FAIL" and body["safe_text"].startswith("YouTube returns 4.55x")
    assert body["decision"]["status"] == "PASS"
    bad = client.post("/v1/fact-check", headers={"Authorization": "Bearer " + "s" * 32}, json={
        "tenant_id": "acme", "purpose": "readout", "text": TEXT, "claims": CLAIMS, "facts_ref": "nope/MMM"})
    assert bad.status_code == 409
