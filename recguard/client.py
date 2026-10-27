"""Portable stdlib Python integration client. Other languages call the JSON REST API."""
from __future__ import annotations
import json
import urllib.error
import urllib.request
import uuid
from typing import Callable
from .contracts import Request, Candidate


class RecGuardError(PermissionError):
    """Any failure to obtain an authorized decision. Hosts must fail closed on it."""
    def __init__(self, message:str, status:int|None=None):
        super().__init__(message)
        self.status=status


class RecGuardClient:
    def __init__(self,base_url:str,serve_token:str,present_token:str|None=None,outcome_token:str|None=None,
                 telemetry_token:str|None=None,timeout:float=5,review_token:str|None=None):
        self.url=base_url.rstrip('/')
        self.serve_token=serve_token
        self.present_token=present_token
        self.outcome_token=outcome_token
        self.telemetry_token=telemetry_token
        self.review_token=review_token
        self.timeout=timeout

    def _call(self,method:str,path:str,token:str|None,data:dict|None=None):
        if not token:raise RecGuardError(f'token required for {path}')
        body=json.dumps(data).encode() if data is not None else None
        request=urllib.request.Request(self.url+path,data=body,method=method,
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(request,timeout=self.timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            try:detail=json.load(exc).get('detail')
            except Exception:detail=None
            raise RecGuardError(f'RECGUARD_HTTP_{exc.code}: {detail}',exc.code) from None
        except (urllib.error.URLError,TimeoutError,OSError) as exc:
            raise RecGuardError(f'RECGUARD_UNREACHABLE: {exc}') from None

    def _post(self,path:str,data:dict,token:str|None):
        return self._call('POST',path,token,data)

    def guard(self, request:Request) -> dict:
        """Host MUST use only `results` returned from gateway; fail closed on error.

        PENDING_APPROVAL raises too: show nothing until a reviewer approves (see `review`)."""
        result=self._post('/v1/recommendations/evaluate',request.model_dump(mode='json'),self.serve_token)
        if result['status']=='BLOCKED':
            raise RecGuardError('RECGUARD_BLOCKED: '+','.join(result['reason_codes']))
        if result['status']=='PENDING_APPROVAL':
            raise RecGuardError('RECGUARD_PENDING_APPROVAL: '+result['decision_id'])
        if not self.verify(result,request.tenant_id):
            raise RecGuardError('RECGUARD_VERIFICATION_FAILED')
        return result

    def guard_many(self, requests:list[Request]) -> list[dict]:
        """Batch evaluate; BLOCKED decisions are returned (not raised) so one bad request can't sink the batch."""
        payload={'requests':[r.model_dump(mode='json') for r in requests]}
        return self._post('/v1/recommendations/evaluate-batch',payload,self.serve_token)['decisions']

    @staticmethod
    def _receipt(decision:dict,tenant_id:str) -> dict:
        return {'tenant_id':tenant_id,'decision_id':decision['decision_id'],'receipt':decision['receipt'],
                'results':decision['results']}

    def verify(self,decision:dict,tenant_id:str) -> bool:
        return self._post('/v1/recommendations/verify',self._receipt(decision,tenant_id),self.serve_token)['valid']

    def record_presentation(self,decision:dict,tenant_id:str):
        """Call only after the host has actually shown the exact verified items."""
        return self._post('/v1/recommendations/presented',self._receipt(decision,tenant_id),self.present_token)

    def record_outcome(self,tenant_id:str,decision_id:str,reward:float,outcome_type:str='CONVERSION',outcome_id:str|None=None):
        """Trusted, normalized reward in [0,1]; send from your backend only."""
        return self._post('/v1/outcomes',{'tenant_id':tenant_id,'decision_id':decision_id,'reward':reward,
            'outcome_type':outcome_type,'outcome_id':outcome_id or uuid.uuid4().hex},self.outcome_token)

    def record_event(self,tenant_id:str,event_type:str,decision_id:str|None=None,event_id:str|None=None,**measures):
        """Content-free telemetry: latency_ms, token_count, cost_usd only."""
        return self._post('/v1/telemetry/events',{'tenant_id':tenant_id,'event_type':event_type,
            'event_id':event_id or uuid.uuid4().hex,'decision_id':decision_id,**measures},self.telemetry_token)


    def effective_policy(self,tenant_id:str,purpose:str) -> dict | None:
        """The composed policy RecGuard enforces (needs policy:read on the serve token)."""
        from urllib.parse import quote
        return self._call('GET',f'/v1/policies/{quote(tenant_id)}?purpose={quote(purpose)}',self.serve_token)['effective']

    def pending_reviews(self,tenant_id:str) -> list[dict]:
        return self._call('GET',f'/v1/reviews/{tenant_id}',self.review_token)['pending']

    def review(self,tenant_id:str,decision_id:str,approve:bool,note:str='') -> dict:
        """Approve (returns a fresh receipt) or reject a PENDING_APPROVAL decision."""
        return self._post('/v1/reviews',{'tenant_id':tenant_id,'decision_id':decision_id,'approve':approve,'note':note},self.review_token)


def wrap_recommender(model_fn:Callable,client:RecGuardClient,tenant_id:str,purpose:str,**base):
    """Thin adapter: model_fn returns Candidate models or dicts, nothing else changes."""
    def guarded(*args,**kwargs):
        raw=model_fn(*args,**kwargs)
        candidates=[c if isinstance(c,Candidate) else Candidate.model_validate({'tenant_id':tenant_id,**c}) for c in raw]
        req=Request(tenant_id=tenant_id,purpose=purpose,request_id=uuid.uuid4().hex,candidates=candidates,**base)
        return client.guard(req)
    return guarded


def guard_local(engine, model_fn:Callable, tenant_id:str, purpose:str, **base):
    """Same adapter for the embedded kernel (no network): returns the verified Decision."""
    def guarded(*args,**kwargs):
        raw=model_fn(*args,**kwargs)
        candidates=[c if isinstance(c,Candidate) else Candidate.model_validate({'tenant_id':tenant_id,**c}) for c in raw]
        decision=engine.evaluate(Request(tenant_id=tenant_id,purpose=purpose,request_id=uuid.uuid4().hex,candidates=candidates,**base))
        if decision.status=='BLOCKED':
            raise RecGuardError('RECGUARD_BLOCKED: '+','.join(decision.reason_codes))
        return decision
    return guarded
