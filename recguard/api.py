"""Language-neutral API. Each token is tenant-bound and scope-limited.

Set RECGUARD_TOKENS_JSON to a JSON object mapping opaque bearer tokens to
{tenant_id, scopes}. NEVER expose this mapping or JWT signing key to models.
Requires the `server` extra (FastAPI); the core kernel does not.
"""
from __future__ import annotations
import hashlib, json, os
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, ValidationError
from fastapi.responses import PlainTextResponse
from .contracts import (Request, BatchRequest, PolicyRegistration, Telemetry, Outcome, VerifyRequest, ModeUpdate,
                        ServingUpdate, RetentionRequest, ReviewDecision, TokenGrant, ID)
from .core import RecGuard, Denied

class ScopeAuth:
    def __init__(self, mapping: dict, oidc=None):
        self.oidc = oidc
        mapping = mapping or {}
        if not isinstance(mapping, dict) or (not mapping and oidc is None) or any(not isinstance(k, str) or len(k) < 24 for k in mapping):
            raise ValueError("RECGUARD_TOKENS_JSON requires nonempty tokens >=24 characters (or configure OIDC)")
        try:
            grants = {k: TokenGrant.model_validate(v) for k, v in mapping.items()}
        except ValidationError as exc:
            raise ValueError(f"RECGUARD_TOKENS_JSON has an invalid grant: {exc.errors()[0]['msg']}") from None
        # Hash lookup avoids storing bearer token plaintext in auth registry.
        self._registry = {hashlib.sha256(k.encode()).hexdigest(): g for k, g in grants.items()}

    def require(self,authorization:str|None,scope:str,tenant:str) -> TokenGrant:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401,"missing bearer token")
        raw=authorization[7:]
        token=self._registry.get(hashlib.sha256(raw.encode()).hexdigest())
        if token is None and self.oidc is not None and raw.count(".")==2:
            try:
                token=self.oidc.grant(raw)
            except ValueError as exc:
                raise HTTPException(401,str(exc)) from None
        if not token:
            raise HTTPException(401,"invalid bearer token")
        if token.tenant_id!=tenant or scope not in token.scopes:
            raise HTTPException(403,"tenant or scope mismatch")
        return token

class BodyLimit:
    """ASGI middleware: reject request bodies over `limit` bytes with 413 (declared or streamed)."""

    def __init__(self, app, limit: int):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.limit):
            return await self._reject(send)
        seen = 0

        async def limited():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.limit:
                    raise _TooLarge()
            return message

        try:
            await self.app(scope, limited, send)
        except _TooLarge:
            await self._reject(send)

    @staticmethod
    async def _reject(send):
        await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"detail":"request body too large"}'})


class _TooLarge(Exception):
    pass


class StrategyRequest(BaseModel):
    tenant_id: ID
    strategy: ID

class TenantRequest(BaseModel):
    tenant_id: ID  # extra fields (e.g. legacy `strategy`) are ignored


def create_app(engine:RecGuard,token_mapping:dict|None,max_body_bytes:int=1_000_000,oidc=None)->FastAPI:
    auth=ScopeAuth(token_mapping,oidc)
    app=FastAPI(title="RecGuard control, serving, and telemetry API",version="0.3.0")
    app.add_middleware(BodyLimit,limit=max_body_bytes)

    def authorize(authorization:str|None,tenant:str,scope:str):
        return auth.require(authorization,scope,tenant)

    def denied(exc:Denied):
        raise HTTPException(409,str(exc)) from exc

    @app.get('/healthz')
    def health():
        # Unauthenticated liveness: proves the DB answers, reveals nothing tenant-specific.
        with engine.db.tx() as c:
            c.execute("SELECT 1")
        return {"ok":True}

    @app.post('/v1/policies')
    def policy(payload:PolicyRegistration,authorization:str|None=Header(default=None)):
        tenant=payload.policy.tenant_id or '*'
        authorize(authorization,tenant,'policy:write')
        try:engine.register_policy(payload.policy)
        except Denied as exc:denied(exc)
        return {"ok":True,"policy_id":payload.policy.policy_id,"version":payload.policy.version}

    @app.get('/v1/policy-packs')
    def list_packs(authorization:str|None=Header(default=None)):
        authorize(authorization,'*','policy:read')
        return {"packs":engine.policy_packs()}

    @app.post('/v1/policy-packs/refresh')
    def refresh_packs(authorization:str|None=Header(default=None)):
        authorize(authorization,'*','policy:write')
        return {"results":engine.refresh_policy_packs(force=True)}

    @app.get('/v1/policies/{tenant_id}')
    def list_policies(tenant_id:str,purpose:str|None=Query(default=None),authorization:str|None=Header(default=None)):
        authorize(authorization,tenant_id,'policy:read')
        return {"policies":[p.model_dump(mode="json") for p in engine.policies(tenant_id)],
                "effective":engine.effective_policy(tenant_id,purpose) if purpose else None}

    @app.post('/v1/system/serving')
    def serving(payload:ServingUpdate,authorization:str|None=Header(default=None)):
        authorize(authorization,payload.tenant_id,'policy:write')
        engine.set_serving(payload.tenant_id,payload.enabled)
        return {"enabled":engine.serving_enabled(payload.tenant_id)}

    @app.post('/v1/recommendations/evaluate')
    def recommend(req:Request,authorization:str|None=Header(default=None)):
        authorize(authorization,req.tenant_id,'recommend:serve')
        return engine.evaluate(req)

    @app.post('/v1/recommendations/evaluate-batch')
    def recommend_batch(payload:BatchRequest,authorization:str|None=Header(default=None)):
        for tenant in {r.tenant_id for r in payload.requests}:
            authorize(authorization,tenant,'recommend:serve')
        return {"decisions":engine.evaluate_many(payload.requests)}

    @app.post('/v1/recommendations/verify')
    def verify(req:VerifyRequest,authorization:str|None=Header(default=None)):
        authorize(authorization,req.tenant_id,'recommend:serve')
        return {"valid":engine.verify(req.tenant_id,req.decision_id,req.receipt,req.results)}

    @app.post('/v1/recommendations/presented')
    def presented(req:VerifyRequest,authorization:str|None=Header(default=None)):
        authorize(authorization,req.tenant_id,'recommend:present')
        try:engine.presented(req.tenant_id,req.decision_id,req.receipt,req.results)
        except Denied as exc:denied(exc)
        return {"ok":True}

    @app.post('/v1/telemetry/events')
    def events(event:Telemetry,authorization:str|None=Header(default=None)):
        authorize(authorization,event.tenant_id,'telemetry:write')
        try:engine.event(event)
        except Denied as exc:denied(exc)
        return {"accepted":True}

    @app.post('/v1/outcomes')
    def outcomes(outcome:Outcome,authorization:str|None=Header(default=None)):
        authorize(authorization,outcome.tenant_id,'outcomes:write')
        try:engine.outcome(outcome)
        except Denied as exc:denied(exc)
        return {"accepted":True}

    @app.post('/v1/learning/mode')
    def mode(payload:ModeUpdate,authorization:str|None=Header(default=None)):
        authorize(authorization,payload.tenant_id,'learning:admin')
        try:engine.mode(payload.tenant_id,payload.mode.value)
        except Denied as exc:denied(exc)
        return {"ok":True,"mode":payload.mode}

    @app.post('/v1/learning/assess')
    def assess(payload:StrategyRequest,authorization:str|None=Header(default=None)):
        authorize(authorization,payload.tenant_id,'learning:admin')
        return engine.assess_challenger(payload.tenant_id,payload.strategy)

    @app.post('/v1/learning/promote')
    def promote(payload:StrategyRequest,authorization:str|None=Header(default=None)):
        authorize(authorization,payload.tenant_id,'learning:admin')
        try:return engine.promote(payload.tenant_id,payload.strategy)
        except Denied as exc:denied(exc)

    @app.post('/v1/learning/rollback')
    def rollback(payload:TenantRequest,authorization:str|None=Header(default=None)):
        authorize(authorization,payload.tenant_id,'learning:admin')
        engine.rollback(payload.tenant_id)
        return {"ok":True,"mode":"OFF","strategy":"base"}

    @app.post('/v1/data/purge')
    def purge(payload:RetentionRequest,authorization:str|None=Header(default=None)):
        authorize(authorization,payload.tenant_id,'data:admin')
        try:return {"deleted":engine.purge(payload.tenant_id,payload.older_than_seconds)}
        except Denied as exc:denied(exc)

    @app.get('/v1/metrics/{tenant_id}')
    def metrics(tenant_id:str,authorization:str|None=Header(default=None)):
        authorize(authorization,tenant_id,'metrics:read')
        return engine.metrics(tenant_id)

    @app.get('/v1/reviews/{tenant_id}')
    def pending(tenant_id:str,authorization:str|None=Header(default=None)):
        authorize(authorization,tenant_id,'decisions:review')
        return {"pending":engine.pending_reviews(tenant_id)}

    @app.post('/v1/reviews')
    def review(payload:ReviewDecision,authorization:str|None=Header(default=None)):
        grant=authorize(authorization,payload.tenant_id,'decisions:review')
        reviewer=grant.subject or "token:"+hashlib.sha256((authorization or "").encode()).hexdigest()[:12]
        try:return engine.review(payload.tenant_id,payload.decision_id,payload.approve,reviewer,payload.note)
        except Denied as exc:denied(exc)

    @app.get('/v1/shadow/{tenant_id}')
    def shadow(tenant_id:str,authorization:str|None=Header(default=None)):
        authorize(authorization,tenant_id,'metrics:read')
        return engine.shadow_report(tenant_id)

    @app.get('/v1/metrics/{tenant_id}/prometheus',response_class=PlainTextResponse)
    def prometheus(tenant_id:str,authorization:str|None=Header(default=None)):
        authorize(authorization,tenant_id,'metrics:read')
        metric=engine.metrics(tenant_id,include_audit=False)
        label=tenant_id.replace('\\','\\\\').replace('"','\\"').replace('\n','\\n')
        lines=[]
        mapping={
            'recguard_decisions_total':metric['decisions'],
            'recguard_policy_block_fraction':metric['block_rate'],
            'recguard_repair_fraction':metric['repair_rate'],
            'recguard_verified_presentations_total':metric['verified_presentations'],
            'recguard_outcomes_total':metric['outcomes'],
            'recguard_observed_reward_mean':metric['mean_reward'],
            'recguard_observed_ctr':metric['observed_ctr'],
            'recguard_latency_p95_milliseconds':metric['latency_ms_p95'],
            'recguard_logged_cost_usd_total':metric['cost_usd_logged'],
        }
        for name,val in mapping.items():
            if val is not None:
                lines.append(f'{name}{{tenant="{label}"}} {val}')
        for code,count in sorted(metric['reason_counts'].items()):
            code=code.replace('\\','\\\\').replace('"','\\"')
            lines.append(f'recguard_reason_total{{tenant="{label}",code="{code}"}} {count}')
        return "\n".join(lines)+"\n"

    @app.get('/v1/audit/{tenant_id}/verify')
    def audit(tenant_id:str,expected_head:str|None=Query(default=None,pattern="^[0-9a-f]{64}$"),
              authorization:str|None=Header(default=None)):
        authorize(authorization,tenant_id,'audit:read')
        return engine.db.audit_verify(tenant_id,expected_head)

    @app.get('/v1/audit/{tenant_id}/head')
    def audit_head(tenant_id:str,authorization:str|None=Header(default=None)):
        authorize(authorization,tenant_id,'audit:read')
        return engine.db.audit_head(tenant_id)
    return app


def from_environment():
    from .oidc import OIDCAuth
    tokens=os.environ.get('RECGUARD_TOKENS_JSON')
    signing=os.environ.get('RECGUARD_SIGNING_KEY')
    oidc=OIDCAuth.from_environment()
    if (not tokens and oidc is None) or not signing or len(signing.encode())<32:
        raise RuntimeError('Set RECGUARD_TOKENS_JSON (or RECGUARD_OIDC_ISSUER) and a strong RECGUARD_SIGNING_KEY (min 32 bytes). Fail-closed startup.')
    ttl=int(os.getenv('RECGUARD_RECEIPT_TTL','300'))
    engine=RecGuard(os.getenv('RECGUARD_DB','recguard.db'),signing.encode(),receipt_ttl=ttl)
    # Policy-as-code: comma-separated YAML/JSON packs loaded at startup. Packs that declare
    # `context:` need host data and can only be loaded by an embedding application.
    for path in filter(None,(x.strip() for x in os.getenv('RECGUARD_POLICY_PACKS','').split(','))):
        engine.load_policy_pack(path,data_version=os.getenv('RECGUARD_POLICY_DATA_VERSION') or None)
    # Re-read pack files and re-fetch due `sources:` in the background (hot reload).
    interval=float(os.getenv('RECGUARD_POLICY_REFRESH_SECONDS','0') or 0)
    if not interval:
        due=[p['refresh_seconds'] for p in engine.policy_packs() if p['refresh_seconds']]
        interval=min(due) if due else 0
    if interval:
        engine.start_auto_refresh(interval)
    app=create_app(engine,json.loads(tokens) if tokens else {},max_body_bytes=int(os.getenv('RECGUARD_MAX_BODY_BYTES','1000000')),oidc=oidc)
    from .tracing import configure_from_environment
    configure_from_environment(app)
    return app

# Secure-by-default: no default bearer tokens or signing keys.
# Use `uvicorn recguard.api:from_environment --factory` (or `recguard serve`) to start.
