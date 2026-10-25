import sqlite3
import time
from collections import Counter
import pytest
from fastapi.testclient import TestClient
from recguard import Candidate, Request, Policy, RecGuard, Outcome, Telemetry, Denied, guard_local, RecGuardError
from recguard.api import create_app, ScopeAuth


def c(name, **kw):
    return Candidate(item_id=name,tenant_id="acme",score=kw.pop("score",1.0),evidence_ids=kw.pop("evidence_ids",["catalog-v1"]),**kw)


def req(candidates,k=3,**kw):
    return Request(tenant_id="acme",purpose="shop",request_id=kw.pop("request_id","req"),k=k,region="IN",candidates=candidates,**kw)


def engine(**kw):
    r=RecGuard(signing_key=b"Z"*32)
    r.register_policy(Policy(policy_id="global",version=1,**kw))
    return r


# ---- regressions ------------------------------------------------------------

def test_truncation_and_reordering_is_pass_not_repair():
    r=engine()
    d=r.evaluate(req([c('low',score=1),c('high',score=2),c('mid',score=1.5)],k=2))
    assert d.status=='PASS' and [x.item_id for x in d.results]==['high','mid']


def test_duplicates_are_reported_and_count_as_repair():
    d=engine().evaluate(req([c('a'),c('a')],k=2))
    assert d.status=='REPAIRED' and 'DUPLICATE_ITEM' in d.reason_codes


def test_tenants_do_not_collide_on_event_or_outcome_ids():
    r=engine()
    for tenant in ('acme','other'):
        d=r.evaluate(Request(tenant_id=tenant,purpose='shop',request_id='x',k=1,
                             candidates=[Candidate(item_id='i',tenant_id=tenant,score=1,evidence_ids=['e'])]))
        r.event(Telemetry(event_id='e1',tenant_id=tenant,event_type='CLICK'))
        r.presented(tenant,d.decision_id,d.receipt,d.results)
        r.outcome(Outcome(outcome_id='o1',tenant_id=tenant,decision_id=d.decision_id,reward=1,outcome_type='CONVERSION'))
    assert r.metrics('acme')['outcomes']==1 and r.metrics('other')['outcomes']==1


def test_active_mode_requires_real_promotion():
    r=engine()
    r.set_serving('acme',True)
    with pytest.raises(Denied,match='NO_PROMOTED_STRATEGY'):
        r.mode('acme','ACTIVE')


def test_malformed_receipt_is_invalid_not_a_crash():
    r=engine();d=r.evaluate(req([c('a')],k=1))
    assert not r.verify('acme',d.decision_id,'é'*64,d.results)
    client=TestClient(create_app(r,{'a'*32:{'tenant_id':'acme','scopes':['recommend:serve']}}))
    x=client.post('/v1/recommendations/verify',headers={'Authorization':'Bearer '+'a'*32},
                  json={'tenant_id':'acme','decision_id':d.decision_id,'receipt':'é','results':[]})
    assert x.status_code==422


def test_rollback_endpoint_needs_only_tenant():
    client=TestClient(create_app(RecGuard(),{'d'*32:{'tenant_id':'acme','scopes':['learning:admin']}}))
    x=client.post('/v1/learning/rollback',json={'tenant_id':'acme'},headers={'Authorization':'Bearer '+'d'*32})
    assert x.status_code==200


def test_token_grants_are_validated_at_startup():
    with pytest.raises(ValueError,match='invalid grant'):
        ScopeAuth({'a'*32:{'tenant_id':'acme','scopes':'recommend:serve'}})
    with pytest.raises(ValueError):
        ScopeAuth({'short':{'tenant_id':'acme','scopes':['x']}})


def test_global_kill_switch_stops_every_tenant():
    r=engine();d=r.evaluate(req([c('a')],k=1))
    r.set_serving('*',False)
    assert not r.verify('acme',d.decision_id,d.receipt,d.results)
    assert 'SERVING_DISABLED' in r.evaluate(req([c('a')],k=1)).reason_codes
    r.set_serving('*',True)
    assert r.evaluate(req([c('a')],k=1)).status=='PASS'


def test_legacy_v0_database_is_migrated(tmp_path):
    path=str(tmp_path/'old.sqlite')
    conn=sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE decisions(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, request_id TEXT NOT NULL, purpose TEXT NOT NULL, segment TEXT NOT NULL, strategy TEXT NOT NULL, propensity REAL NOT NULL, policy_hash TEXT NOT NULL, status TEXT NOT NULL, output_hash TEXT NOT NULL, receipt TEXT NOT NULL, exp INTEGER NOT NULL, at REAL NOT NULL, candidate_count INTEGER NOT NULL, eligible_count INTEGER NOT NULL);
        CREATE TABLE events(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, decision_id TEXT, kind TEXT NOT NULL, latency_ms REAL, token_count INTEGER, cost_usd REAL, at REAL NOT NULL);
        CREATE TABLE outcomes(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, decision_id TEXT NOT NULL UNIQUE, reward REAL NOT NULL, kind TEXT NOT NULL, at REAL NOT NULL);
        CREATE INDEX ix_outcome_decision ON outcomes(decision_id);
        INSERT INTO events VALUES('e1','acme',NULL,'CLICK',5,NULL,NULL,1);""")
    conn.commit();conn.close()
    r=RecGuard(path,signing_key=b'K'*32)
    r.event(Telemetry(event_id='e1',tenant_id='other',event_type='CLICK'))
    assert r.metrics('acme')['event_counts']=={'CLICK':1}


# ---- new policy rules -------------------------------------------------------

def test_allowlist_item_blocklist_min_score_and_category_cap():
    r=engine(allowed_categories=['books','music'],denied_item_ids=['banned'],min_score=0.2,max_per_category=1)
    d=r.evaluate(req([c('b1',score=0.9,categories=['books']),c('b2',score=0.8,categories=['books']),
                      c('m1',score=0.7,categories=['music']),c('t1',score=0.95,categories=['toys']),
                      c('banned',score=0.99,categories=['books']),c('weak',score=0.1,categories=['music'])],k=3))
    assert [x.item_id for x in d.results]==['b1','m1']
    assert {'CATEGORY_NOT_ALLOWED','DENIED_ITEM','SCORE_BELOW_MINIMUM','CATEGORY_CAP'}<=set(d.reason_codes)
    assert {x.item_id:x.reason for x in d.rejections}=={'t1':'CATEGORY_NOT_ALLOWED','banned':'DENIED_ITEM','weak':'SCORE_BELOW_MINIMUM'}


def test_fallback_only_fills_gaps_never_outranks_primary():
    d=engine().evaluate(req([c('primary',score=0.1)],k=2,fallback_candidates=[c('backup',score=9)]))
    assert [x.item_id for x in d.results]==['primary','backup'] and d.status=='REPAIRED'


def test_min_results_above_max_is_rejected():
    with pytest.raises(Denied,match='MIN_RESULTS_EXCEEDS_MAX'):
        RecGuard().register_policy(Policy(policy_id='bad',version=1,min_results=5,max_results=2))


def test_effective_policy_is_inspectable():
    r=RecGuard()
    r.register_policy(Policy(policy_id='g',version=1,denied_categories=['x'],max_per_category=3))
    r.register_policy(Policy(policy_id='t',version=1,tenant_id='acme',denied_categories=['y'],max_per_category=2))
    eff=r.effective_policy('acme','shop')
    assert eff['denied_categories']==['x','y'] and eff['max_per_category']==2
    assert r.effective_policy('acme','shop')['fingerprint']==r.evaluate(req([c('a')],k=1)).policy_fingerprint


# ---- plug-ins -----------------------------------------------------------------

def test_custom_check_rejects_and_fails_closed_on_error():
    r=engine()
    r.register_check('stock',lambda cand,rq:'OUT_OF_STOCK' if cand.item_id.startswith('oos') else None)
    r.register_check('flaky',lambda cand,rq:1/0 if cand.item_id=='boom' else None)
    d=r.evaluate(req([c('oos-1'),c('boom'),c('ok')],k=3))
    assert [x.item_id for x in d.results]==['ok']
    assert {'stock:OUT_OF_STOCK','CHECK_ERROR:flaky'}<=set(d.reason_codes)


def test_registering_check_invalidates_outstanding_receipts():
    r=engine();d=r.evaluate(req([c('a')],k=1))
    r.register_check('late',lambda cand,rq:None)
    assert not r.verify('acme',d.decision_id,d.receipt,d.results)


def test_custom_strategy_cannot_inject_or_mutate_items():
    r=engine(allow_experiment=True)
    r.register_strategy('ascending',lambda items,k:sorted(items,key=lambda x:x.score))
    r.register_strategy('evil',lambda items,k:[Candidate(item_id='injected',tenant_id='acme',score=99,evidence_ids=['e'])])
    def mutate(items,k):
        items[0].score=1e9
        return items
    r.register_strategy('mutate',mutate)
    items=[c('a',score=1),c('b',score=2)]
    assert [x.item_id for x in r._order(items,'ascending',Counter())]==['a','b']
    reasons=Counter()
    assert {x.item_id for x in r._order(items,'evil',reasons)}=={'a','b'} and reasons['STRATEGY_OUTPUT_REJECTED']==1
    assert max(x.score for x in r._order(items,'mutate',reasons))==2
    assert 'ascending' in r.STRATEGIES and 'ascending' in r._arms()


def test_unregistered_active_strategy_falls_back_to_base():
    r=engine(allow_experiment=True)
    with r.db.tx() as conn:
        conn.execute("INSERT INTO state(tenant,mode,active_strategy) VALUES('acme','ACTIVE','gone')")
    d=r.evaluate(req([c('a')],k=1))
    assert d.strategy=='base' and 'ACTIVE_STRATEGY_UNAVAILABLE' in d.reason_codes


def test_guard_local_adapter():
    r=engine()
    guarded=guard_local(r,lambda:[{'item_id':'a','score':1,'evidence_ids':['e']}],'acme','shop',k=1)
    assert [x.item_id for x in guarded().results]==['a']
    blocked=guard_local(r,lambda:[{'item_id':'a','score':1}],'acme','shop',k=1)
    with pytest.raises(RecGuardError,match='EVIDENCE_REQUIRED'):
        blocked()


# ---- learning -------------------------------------------------------------------

def test_promotion_approves_a_genuinely_better_strategy():
    r=engine(allow_experiment=True)
    r.mode('acme','EXPERIMENT')
    for i in range(1200):
        d=r.evaluate(req([c('a',score=2,categories=['x']),c('b',score=1.9,categories=['x']),c('z',score=1,categories=['y'])],
                         k=2,request_id=f'r{i}'))
        r.presented('acme',d.decision_id,d.receipt,d.results)
        reward=1.0 if d.strategy=='diverse' else 0.0
        r.outcome(Outcome(outcome_id=f'o{i}',tenant_id='acme',decision_id=d.decision_id,reward=reward,outcome_type='CONVERSION'))
    verdict=r.assess_challenger('acme','diverse')
    assert verdict['approved'],verdict
    assert not r.assess_challenger('acme','novelty')['approved']
    r.promote('acme','diverse')
    assert r.evaluate(req([c('a')],k=1)).strategy=='diverse'
    r.rollback('acme')
    assert r.evaluate(req([c('a')],k=1)).strategy=='base'


# ---- operations -----------------------------------------------------------------

def test_retention_purge_keeps_audit_chain_valid():
    r=engine();d=r.evaluate(req([c('a')],k=1))
    r.event(Telemetry(event_id='e',tenant_id='acme',decision_id=d.decision_id,event_type='CLICK'))
    with r.db.tx() as conn:
        conn.execute("UPDATE decisions SET at=? ",(time.time()-10_000,))
        conn.execute("UPDATE events SET at=? ",(time.time()-10_000,))
    with pytest.raises(Denied):
        r.purge('acme',60)
    assert r.purge('acme',3600)=={'outcomes':0,'presentations':0,'events':1,'decisions':1}
    assert r.metrics('acme')['decisions']==0 and r.db.audit_verify('acme')['valid']


def test_anchored_audit_head_detects_tail_deletion():
    r=engine();r.evaluate(req([c('a')],k=1))
    head=r.db.audit_head('acme')['head']
    assert r.db.audit_verify('acme',head)['valid']
    with r.db.tx() as conn:
        conn.execute("DELETE FROM audit WHERE seq=(SELECT MAX(seq) FROM audit WHERE tenant='acme')")
    assert r.db.audit_verify('acme')['valid']  # undetectable without an anchor...
    assert not r.db.audit_verify('acme',head)['valid']  # ...detected with one


def test_api_batch_health_policies_and_audit_head():
    r=engine()
    tokens={'a'*32:{'tenant_id':'acme','scopes':['recommend:serve','policy:read','audit:read','metrics:read']},
            'o'*32:{'tenant_id':'other','scopes':['recommend:serve']}}
    client=TestClient(create_app(r,tokens))
    h=lambda t:{'Authorization':'Bearer '+t}
    assert client.get('/healthz').json()=={'ok':True}
    one={'tenant_id':'acme','purpose':'shop','request_id':'b','k':1,
         'candidates':[{'item_id':'a','tenant_id':'acme','score':1,'evidence_ids':['e']}]}
    batch=client.post('/v1/recommendations/evaluate-batch',json={'requests':[one,one]},headers=h('a'*32))
    assert [x['status'] for x in batch.json()['decisions']]==['PASS','PASS']
    mixed={'requests':[one,{**one,'tenant_id':'other','candidates':[{**one['candidates'][0],'tenant_id':'other'}]}]}
    assert client.post('/v1/recommendations/evaluate-batch',json=mixed,headers=h('a'*32)).status_code==403
    pol=client.get('/v1/policies/acme?purpose=shop',headers=h('a'*32)).json()
    assert pol['policies'][0]['policy_id']=='global' and pol['effective']['min_results']==1
    head=client.get('/v1/audit/acme/head',headers=h('a'*32)).json()['head']
    assert client.get(f'/v1/audit/acme/verify?expected_head={head}',headers=h('a'*32)).json()['valid']
    prom=client.get('/v1/metrics/acme/prometheus',headers=h('a'*32)).text
    assert 'recguard_decisions_total{tenant="acme"} 2' in prom
