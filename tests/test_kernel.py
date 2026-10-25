import pytest
from recguard import Candidate, Request, Policy, RecGuard, Outcome, Telemetry
from recguard.core import Denied
from recguard import learning


def c(name, **kw):
    return Candidate(item_id=name,tenant_id="acme",score=kw.pop("score",1.0),evidence_ids=kw.pop("evidence_ids",["catalog-v1"]),**kw)


def req(candidates,k=3,**kw):
    return Request(tenant_id="acme",purpose="shop",request_id=kw.pop("request_id","req"),k=k,
                   region=kw.pop("region","IN"),personalization_consent=kw.pop("personalization_consent",False),
                   candidates=candidates,**kw)


def setup_global(**kw):
    r=RecGuard(signing_key=b"Z"*32)
    p=Policy(policy_id="global",version=1,denied_categories=["adult"],allowed_regions=["IN"],
             min_results=1,max_results=10,**kw)
    r.register_policy(p)
    return r


def test_no_policy_fail_closed():
    r=RecGuard(); d=r.evaluate(req([c('one')]))
    assert d.status=="BLOCKED" and not d.results and "NO_APPLICABLE_POLICY" in d.reason_codes
    assert not r.verify('acme',d.decision_id,d.receipt,[])


def test_deny_override_and_hard_tenant():
    r=setup_global();r.register_policy(Policy(policy_id="tenant",version=1,tenant_id="acme",require_evidence=False))
    d=r.evaluate(req([c('a',categories=['adult'],score=100),c('b',score=10),c('c',score=20),
                      Candidate(item_id='enemy',tenant_id='other',score=999,evidence_ids=['x'])],k=3))
    assert [x.item_id for x in d.results]==['c','b']
    assert {'CROSS_TENANT','DENIED_CATEGORY'}.issubset(set(d.reason_codes))
    assert d.status=='REPAIRED'


def test_region_age_evidence_consent():
    r=setup_global()
    d=r.evaluate(req([c('age',min_age=18),c('geo',region='US'),c('none',evidence_ids=[]),
                      c('personal',uses_personal_data=True)],k=4))
    assert d.status=='BLOCKED'
    assert set(d.reason_codes).issuperset({'AGE_UNVERIFIED_OR_TOO_LOW','ITEM_REGION_MISMATCH','EVIDENCE_REQUIRED','CONSENT_REQUIRED'})


def test_fallback_repairs_without_bypassing_policy():
    r=setup_global()
    d=r.evaluate(req([c('adult',categories=['adult']),c('good',score=10)],k=2,
                     fallback_candidates=[c('fallback',score=2),c('unsafe',categories=['adult'],score=999)]))
    assert [x.item_id for x in d.results]==['good','fallback']
    assert d.status=='REPAIRED'


def test_minimum_result_is_hard_gate():
    r=RecGuard();r.register_policy(Policy(policy_id='min',version=1,min_results=3))
    d=r.evaluate(req([c('a'),c('b')],k=2))
    assert d.status=='BLOCKED' and 'IMPOSSIBLE_RESULT_MINIMUM' in d.reason_codes


def test_consent_allows_personalized_only_with_permission():
    r=setup_global()
    d=r.evaluate(req([c('personal',uses_personal_data=True)],personalization_consent=True,k=1))
    assert d.status=='PASS'
    d2=r.evaluate(req([c('personal',uses_personal_data=True)],k=1))
    assert d2.status=='BLOCKED'


def test_receipt_rejects_tampering_wrong_tenant_and_policy_change():
    r=setup_global();d=r.evaluate(req([c('one'),c('two')],k=2))
    assert r.verify('acme',d.decision_id,d.receipt,d.results)
    assert not r.verify('acme',d.decision_id,d.receipt,list(reversed(d.results)))
    assert not r.verify('other',d.decision_id,d.receipt,d.results)
    assert not r.verify('acme',d.decision_id,'0'*64,d.results)
    r.register_policy(Policy(policy_id='global',version=2,denied_categories=['adult','new']))
    assert not r.verify('acme',d.decision_id,d.receipt,d.results)


def test_present_and_trusted_outcome_only():
    r=setup_global();d=r.evaluate(req([c('a')],k=1))
    item_ids=[x.item_id for x in d.results]
    outcome=Outcome(outcome_id='sale-1',tenant_id='acme',decision_id=d.decision_id,reward=1.0,outcome_type='CONVERSION')
    with pytest.raises(Denied,match='NO_VERIFIED_PRESENTATION'):
        r.outcome(outcome)
    r.presented('acme',d.decision_id,d.receipt,d.results)
    r.outcome(outcome)
    with pytest.raises(Denied,match='DUPLICATE_OR_ALREADY_REWARDED'):
        r.outcome(outcome)
    metrics=r.metrics('acme')
    assert metrics['outcomes']==1 and metrics['mean_reward']==1


def test_telemetry_not_learning_signal():
    r=setup_global(); d=r.evaluate(req([c('a')],k=1))
    r.event(Telemetry(event_id='click1',tenant_id='acme',decision_id=d.decision_id,event_type='CLICK',latency_ms=23,cost_usd=0.01))
    assert r.metrics('acme')['outcomes']==0
    with pytest.raises(Denied,match='DUPLICATE_EVENT'):
        r.event(Telemetry(event_id='click1',tenant_id='acme',event_type='CLICK'))


def test_mode_policy_bounds_exploration():
    r=setup_global()
    r.mode('acme','EXPERIMENT')
    d=r.evaluate(req([c('a'),c('b')],k=2))
    assert d.strategy=='base' and d.propensity==1.0
    r.register_policy(Policy(policy_id='global',version=2,allow_experiment=True,require_evidence=True))
    d2=r.evaluate(req([c('a'),c('b')],k=2))
    assert d2.strategy in learning.ARMS and 0<d2.propensity<=1
    r.register_policy(Policy(policy_id='global',version=3,allow_experiment=True,high_impact=True))
    d3=r.evaluate(req([c('a'),c('b')],k=2))
    assert d3.strategy=='base' and d3.propensity==1.0


def test_audit_detects_changed_content():
    r=setup_global();r.evaluate(req([c('a')],k=1))
    assert r.db.audit_verify('acme')['valid']
    with r.db.tx() as conn:
        conn.execute("UPDATE audit SET kind='TAMPER' WHERE tenant='acme' AND kind='DECISION'")
    assert not r.db.audit_verify('acme')['valid']


def test_policy_versions_and_promotion_gate():
    r=setup_global()
    with pytest.raises(Denied,match='VERSION_NOT_MONOTONIC'):
        r.register_policy(Policy(policy_id='global',version=1))
    assert r.assess_challenger('acme','diverse')['reason']=='INSUFFICIENT_HOLDOUT'
    with pytest.raises(Denied,match='PROMOTION_DENIED'):
        r.promote('acme','diverse')
    r.rollback('acme')


def test_eligibility_order_and_score_normalization():
    items=[c('a',score=100,categories=['red']),c('b',score=99,categories=['red']),c('c',score=98,categories=['blue'])]
    assert [x.item_id for x in RecGuard._rank(items,'base',3)]==['a','b','c']
    assert RecGuard._rank(items,'diverse',2)[0].item_id=='a'
    assert RecGuard._rank(items,'diverse',2)[1].item_id=='c'


def test_serving_kill_switch_revokes_unexpired_receipts():
    r=setup_global();d=r.evaluate(req([c('a')],k=1))
    assert r.verify('acme',d.decision_id,d.receipt,d.results)
    r.set_serving('acme',False)
    assert not r.verify('acme',d.decision_id,d.receipt,d.results)
    b=r.evaluate(req([c('a')],k=1))
    assert b.status=='BLOCKED' and 'SERVING_DISABLED' in b.reason_codes
    assert r.db.audit_verify('acme')['valid']
    r.set_serving('acme',True)
    assert r.serving_enabled('acme')


def test_receipt_binds_candidate_metadata_not_only_order():
    r=setup_global();d=r.evaluate(req([c('a',score=5)],k=1))
    modified=[d.results[0].model_copy(update={'score':999})]
    assert not r.verify('acme',d.decision_id,d.receipt,modified)


def test_persistent_store_requires_stable_signing_key(tmp_path):
    with pytest.raises(ValueError,match='stable explicit signing key'):
        RecGuard(str(tmp_path / 'db.sqlite'))


def test_global_tenant_region_policy_intersection():
    r=RecGuard()
    r.register_policy(Policy(policy_id='world',version=1,allowed_regions=['IN','US']))
    r.register_policy(Policy(policy_id='business',version=1,tenant_id='acme',allowed_regions=['IN']))
    d=r.evaluate(req([c('a')],region='US',k=1))
    assert d.status=='BLOCKED' and 'REGION_NOT_ALLOWED' in d.reason_codes
    ok=r.evaluate(req([c('a')],region='IN',k=1))
    assert ok.status=='PASS'
