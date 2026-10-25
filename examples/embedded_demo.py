"""One self-contained demonstration without a web server or actual sensitive data."""
import json
from recguard import RecGuard, Candidate, Request, Policy, Outcome, Telemetry

engine=RecGuard(signing_key=b'demo-only-never-use-this-in-prod-32')
engine.register_policy(Policy(policy_id='company',version=1,denied_categories=['restricted'],
                               allowed_regions=['IN'],min_results=2,max_results=3,require_evidence=True))

def product(pid, score, category='electronics'):
    return Candidate(item_id=pid,tenant_id='demo',score=score,categories=[category],evidence_ids=['approved-catalog-v1'])

req=Request(tenant_id='demo',request_id='opaque-run-123',purpose='shopping',region='IN',k=2,
    candidates=[product('illegal-1',0.99,'restricted'),product('legal-2',0.90)],
    fallback_candidates=[product('legal-3',0.80)])
result=engine.evaluate(req)
assert result.status == 'REPAIRED'
assert engine.verify('demo',result.decision_id,result.receipt,result.results)
engine.presented('demo',result.decision_id,result.receipt,result.results)
engine.event(Telemetry(event_id='lat-123',tenant_id='demo',decision_id=result.decision_id,
                       event_type='LATENCY',latency_ms=14.8))
engine.outcome(Outcome(outcome_id='conv-123',tenant_id='demo',decision_id=result.decision_id,
                       outcome_type='CONVERSION',reward=1.0))
print('RECOMMENDATIONS:',[x.item_id for x in result.results])
print('DECISION:',result.status,'REASONS:',result.reason_codes)
print('METRICS:',json.dumps(engine.metrics('demo'),indent=2))
print('AUDIT:',engine.db.audit_verify('demo'))
