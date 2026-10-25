from fastapi.testclient import TestClient
from recguard import RecGuard
from recguard.api import create_app

TOKENS={'a'*32:{'tenant_id':'acme','scopes':['recommend:serve','metrics:read','audit:read']},
        'b'*32:{'tenant_id':'acme','scopes':['recommend:present','outcomes:write','telemetry:write']},
        'c'*32:{'tenant_id':'*','scopes':['policy:write']},
        'd'*32:{'tenant_id':'acme','scopes':['learning:admin']},
        'e'*32:{'tenant_id':'other','scopes':['recommend:serve']}}

def post(client,path,payload,token='a'*32):
    return client.post(path,json=payload,headers={'Authorization':'Bearer '+token})


def test_end_to_end_cross_language_api():
    r=RecGuard(signing_key=b'X'*32)
    client=TestClient(create_app(r,TOKENS))
    p={'policy':{'policy_id':'global','version':1,'allowed_regions':['IN'],'max_results':2}}
    assert post(client,'/v1/policies',p,'c'*32).status_code==200
    request={'tenant_id':'acme','purpose':'shop','request_id':'r1','region':'IN','k':2,
             'candidates':[{'item_id':'x','tenant_id':'acme','score':0.9,'evidence_ids':['dataset-1']},
                           {'item_id':'y','tenant_id':'acme','score':0.7,'evidence_ids':['dataset-2']} ]}
    assert post(client,'/v1/recommendations/evaluate',request,'e'*32).status_code==403
    assert post(client,'/v1/recommendations/evaluate',request,'z'*32).status_code==401
    d=post(client,'/v1/recommendations/evaluate',request).json()
    assert d['status']=='PASS'
    verification={'tenant_id':'acme','decision_id':d['decision_id'],'receipt':d['receipt'],
                  'results':d['results']}
    assert post(client,'/v1/recommendations/verify',verification).json()['valid']
    assert post(client,'/v1/recommendations/presented',verification,'a'*32).status_code==403
    assert post(client,'/v1/recommendations/presented',verification,'b'*32).status_code==200
    assert post(client,'/v1/outcomes',{'tenant_id':'acme','decision_id':d['decision_id'],'outcome_id':'o1',
                                     'outcome_type':'CONVERSION','reward':1},'b'*32).status_code==200
    assert client.get('/v1/metrics/acme',headers={'Authorization':'Bearer '+'a'*32}).json()['mean_reward']==1
    assert client.get('/v1/audit/acme/verify',headers={'Authorization':'Bearer '+'a'*32}).json()['valid']


def test_telemetry_rejects_unbounded_content():
    client=TestClient(create_app(RecGuard(),TOKENS))
    x=post(client,'/v1/telemetry/events',{'event_id':'event1','tenant_id':'acme','event_type':'CLICK',
                                        'raw_prompt':'SECRET_PRIVATE_TEXT'},'b'*32)
    assert x.status_code==422


def test_api_serving_switch_and_metrics_scrape():
    r=RecGuard()
    # Scoped policy token for the tenant instead of the global policy owner.
    tokens=dict(TOKENS)
    tokens['f'*32]={'tenant_id':'acme','scopes':['policy:write']}
    client=TestClient(create_app(r,tokens))
    assert post(client,'/v1/policies',{'policy':{'policy_id':'base','version':1,'tenant_id':'acme'}},'f'*32).status_code==200
    stopped=post(client,'/v1/system/serving',{'tenant_id':'acme','enabled':False},'f'*32)
    assert stopped.status_code==200 and stopped.json()['enabled'] is False
    d=post(client,'/v1/recommendations/evaluate',{
        'tenant_id':'acme','purpose':'shop','request_id':'t1','k':1,
        'candidates':[{'item_id':'a','tenant_id':'acme','score':0.4,'evidence_ids':['c']}]}).json()
    assert d['status']=='BLOCKED' and 'SERVING_DISABLED' in d['reason_codes']
    response=client.get('/v1/metrics/acme/prometheus',headers={'Authorization':'Bearer '+'a'*32})
    assert response.status_code==200 and 'recguard_decisions_total{tenant="acme"} 1' in response.text
    assert post(client,'/v1/system/serving',{'tenant_id':'acme','enabled':True},'f'*32).json()['enabled'] is True
