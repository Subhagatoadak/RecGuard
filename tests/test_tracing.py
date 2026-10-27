import pytest
pytest.importorskip("opentelemetry.sdk")
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from recguard import Candidate, Outcome, Policy, Request, RecGuard

EXPORTER = InMemorySpanExporter()


@pytest.fixture(scope="module", autouse=True)
def provider():
    tp = TracerProvider()
    tp.add_span_processor(SimpleSpanProcessor(EXPORTER))
    trace.set_tracer_provider(tp)
    yield


def test_spans_are_emitted_without_item_content():
    EXPORTER.clear()
    r = RecGuard()
    r.register_policy(Policy(policy_id="p", version=1, require_evidence=False, denied_categories=["x"]))
    d = r.evaluate(Request(tenant_id="acme", request_id="secret-request", purpose="shop", k=2, candidates=[
        Candidate(item_id="secret-sku-1", tenant_id="acme", score=1), Candidate(item_id="secret-sku-2", tenant_id="acme", score=1, categories=["x"])]))
    r.presented("acme", d.decision_id, d.receipt, d.results)
    r.outcome(Outcome(outcome_id="o", tenant_id="acme", decision_id=d.decision_id, reward=1, outcome_type="CONVERSION"))
    spans = {s.name: s for s in EXPORTER.get_finished_spans()}
    assert {"recguard.evaluate", "recguard.verify", "recguard.presented", "recguard.outcome"} <= set(spans)
    ev = spans["recguard.evaluate"].attributes
    assert ev["recguard.tenant"] == "acme" and ev["recguard.status"] == "REPAIRED" and ev["recguard.results"] == 1
    assert ev["recguard.rejected"] == 1 and list(ev["recguard.reason_codes"]) == ["DENIED_CATEGORY"]
    assert spans["recguard.verify"].attributes["recguard.valid"] is True
    dumped = repr([dict(s.attributes) for s in EXPORTER.get_finished_spans()])
    assert "secret-sku" not in dumped and "secret-request" not in dumped
