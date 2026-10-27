"""MCP server: lets LLM agents call RecGuard as tools (optional `mcp` extra).

    recguard mcp                         # stdio, for Claude Desktop / Claude Code / IDE agents
    recguard mcp --transport streamable-http

Backends (environment):
  * remote: RECGUARD_URL + RECGUARD_SERVE_TOKEN (+ RECGUARD_REVIEW_TOKEN to list pending reviews)
  * embedded: RECGUARD_DB + RECGUARD_SIGNING_KEY (+ RECGUARD_POLICY_PACKS)

Agents can evaluate, verify and explain - deliberately NOT approve reviews, record
presentations or record outcomes: an agent must never approve or reward its own output.
"""
from __future__ import annotations
import os, uuid
from typing import Any
from .contracts import Candidate, Request

INSTRUCTIONS = (
    "RecGuard enforces recommendation policy. Before showing any recommendation, product, plan or ranked list to a "
    "user, call recguard_evaluate with your candidates and show ONLY the returned `results`. If status is BLOCKED, "
    "show nothing and explain the reason codes. If status is PENDING_APPROVAL, tell the user a human must approve "
    "first. Never re-add rejected items."
)


class _Embedded:
    def __init__(self, engine):
        self.engine = engine

    def evaluate(self, request: Request) -> dict:
        return self.engine.evaluate(request).model_dump(mode="json")

    def verify(self, tenant_id, decision_id, receipt, results) -> bool:
        return self.engine.verify(tenant_id, decision_id, receipt, [Candidate.model_validate(r) for r in results])

    def effective_policy(self, tenant_id, purpose):
        return self.engine.effective_policy(tenant_id, purpose)

    def pending_reviews(self, tenant_id):
        return self.engine.pending_reviews(tenant_id)


class _Remote:
    def __init__(self, client):
        self.client = client

    def evaluate(self, request: Request) -> dict:
        return self.client._post("/v1/recommendations/evaluate", request.model_dump(mode="json"), self.client.serve_token)

    def verify(self, tenant_id, decision_id, receipt, results) -> bool:
        return self.client.verify({"decision_id": decision_id, "receipt": receipt, "results": results}, tenant_id)

    def effective_policy(self, tenant_id, purpose):
        return self.client.effective_policy(tenant_id, purpose)

    def pending_reviews(self, tenant_id):
        return self.client.pending_reviews(tenant_id)


def backend_from_environment():
    if os.getenv("RECGUARD_URL"):
        from .client import RecGuardClient
        token = os.getenv("RECGUARD_SERVE_TOKEN")
        if not token:
            raise RuntimeError("RECGUARD_SERVE_TOKEN is required with RECGUARD_URL")
        return _Remote(RecGuardClient(os.environ["RECGUARD_URL"], token, review_token=os.getenv("RECGUARD_REVIEW_TOKEN")))
    from .core import RecGuard
    key = os.getenv("RECGUARD_SIGNING_KEY")
    if not key:
        raise RuntimeError("Set RECGUARD_URL (remote) or RECGUARD_SIGNING_KEY (+ RECGUARD_DB) for an embedded engine")
    engine = RecGuard(os.getenv("RECGUARD_DB", "recguard.db"), key.encode())
    keys = [x.strip() for x in os.getenv("RECGUARD_POLICY_PUBLIC_KEYS", "").split(",") if x.strip()]
    if keys:
        engine.trust_pack_keys(keys)
    for path in filter(None, (x.strip() for x in os.getenv("RECGUARD_POLICY_PACKS", "").split(","))):
        engine.load_policy_pack(path)
    return _Embedded(engine)


def build_server(backend=None):
    try:
        from mcp.server.mcpserver import MCPServer
        from mcp.types import ToolAnnotations
    except ImportError:
        raise RuntimeError("The MCP server needs: pip install 'recguard-kernel[mcp]'") from None
    backend = backend or backend_from_environment()
    server = MCPServer(name="recguard", instructions=INSTRUCTIONS)

    @server.tool(description="Check candidate recommendations against policy. Show the user ONLY the returned results.")
    def recguard_evaluate(tenant_id: str, purpose: str, candidates: list[dict[str, Any]], k: int = 5,
                          region: str | None = None, segment: str = "general", age: int | None = None,
                          personalization_consent: bool = False, request_id: str | None = None) -> dict:
        """candidates: [{"item_id": "...", "score": 0.9, "categories": [...], "evidence_ids": [...], ...}]"""
        request = Request(tenant_id=tenant_id, purpose=purpose, k=k, region=region, segment=segment, age=age,
                          personalization_consent=personalization_consent, request_id=request_id or uuid.uuid4().hex,
                          candidates=[Candidate.model_validate({"tenant_id": tenant_id, **c}) for c in candidates])
        d = backend.evaluate(request)
        return {"status": d["status"], "results": d["results"], "decision_id": d["decision_id"], "receipt": d["receipt"],
                "reason_codes": d["reason_codes"], "rejections": d["rejections"],
                "review_required": d.get("review_required", []), "expires_at": d["expires_at"]}

    @server.tool(description="Verify that results are exactly what RecGuard approved and are still valid.",
                 annotations=ToolAnnotations(readOnlyHint=True))
    def recguard_verify(tenant_id: str, decision_id: str, receipt: str, results: list[dict[str, Any]]) -> dict:
        return {"valid": backend.verify(tenant_id, decision_id, receipt, results)}

    @server.tool(description="Explain the policy RecGuard enforces for a tenant and purpose (rules, limits, checks).",
                 annotations=ToolAnnotations(readOnlyHint=True))
    def recguard_explain_policy(tenant_id: str, purpose: str) -> dict:
        return {"effective_policy": backend.effective_policy(tenant_id, purpose)}

    @server.tool(description="List decisions waiting for human approval (read-only; approval is for humans).",
                 annotations=ToolAnnotations(readOnlyHint=True))
    def recguard_pending_reviews(tenant_id: str) -> dict:
        return {"pending": backend.pending_reviews(tenant_id)}

    return server


def main(transport: str = "stdio"):
    build_server().run(transport=transport)
