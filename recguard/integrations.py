"""Framework adapters: put RecGuard between retrieval/ranking and whatever consumes it.

    from recguard.integrations import guard_items, langchain_guard, RecGuardNodePostprocessor

    chain = retriever | langchain_guard(engine, tenant_id="acme", purpose="support-answers")
    query_engine = index.as_query_engine(node_postprocessors=[RecGuardNodePostprocessor.create(engine, "acme", "rag")])

`guard` is an embedded RecGuard or a RecGuardClient. Policy attributes (categories,
region, min_age, evidence_ids, uses_personal_data, available, novelty) are read from
item metadata, which must come from your trusted index, never from the LLM.
"""
from __future__ import annotations
import uuid
from typing import Any, Callable, Iterable
from .client import RecGuardError
from .contracts import Candidate, Request

ATTRIBUTES = ("categories", "region", "min_age", "available", "uses_personal_data", "evidence_ids", "novelty")


def _decide(guard, request: Request) -> dict:
    if hasattr(guard, "evaluate") and hasattr(guard, "db"):  # embedded engine
        return guard.evaluate(request).model_dump(mode="json")
    return guard._post("/v1/recommendations/evaluate", request.model_dump(mode="json"), guard.serve_token)


def guard_items(guard, items: Iterable[Any], *, tenant_id: str, purpose: str,
                to_candidate: Callable[[Any, int], dict], k: int | None = None, on_block: str = "raise",
                **request_fields) -> tuple[list[Any], dict]:
    """Evaluate arbitrary items; return (approved items in RecGuard's order, decision).

    on_block="raise" raises RecGuardError for BLOCKED / PENDING_APPROVAL; "empty" returns [].
    Items whose candidate IDs repeat are kept once (first wins), as RecGuard dedupes them.
    """
    items = list(items)
    if not items:
        return [], {}
    by_id: dict[str, Any] = {}
    candidates = []
    for rank, item in enumerate(items):
        fields = to_candidate(item, rank)
        candidate = Candidate.model_validate({"tenant_id": tenant_id, **fields})
        by_id.setdefault(candidate.item_id, item)
        candidates.append(candidate)
    request = Request(tenant_id=tenant_id, purpose=purpose, k=min(k or len(candidates), 50),
                      request_id=request_fields.pop("request_id", uuid.uuid4().hex), candidates=candidates, **request_fields)
    decision = _decide(guard, request)
    if decision["status"] in ("BLOCKED", "PENDING_APPROVAL"):
        if on_block == "empty":
            return [], decision
        raise RecGuardError(f"RECGUARD_{decision['status']}: " + ",".join(decision["reason_codes"]))
    return [by_id[r["item_id"]] for r in decision["results"]], decision


def _metadata_candidate(item_id: str, score: float, metadata: dict) -> dict:
    fields = {"item_id": item_id, "score": float(score)}
    fields.update({key: metadata[key] for key in ATTRIBUTES if key in metadata})
    return fields


def _safe_id(raw, rank: int) -> str:
    text = "".join(ch if ch.isalnum() or ch in "_.:-" else "_" for ch in str(raw or ""))[:128]
    return text if text[:1].isalnum() else f"item-{rank}"


def langchain_guard(guard, *, tenant_id: str, purpose: str, id_key: str = "id", score_key: str = "score",
                    k: int | None = None, on_block: str = "raise", **request_fields):
    """A LangChain Runnable: list[Document] -> approved list[Document]. Compose after a retriever."""
    from langchain_core.runnables import RunnableLambda

    def to_candidate(doc, rank):
        meta = doc.metadata or {}
        item_id = _safe_id(meta.get(id_key) or getattr(doc, "id", None), rank)
        score = meta.get(score_key, 1.0 / (rank + 1))  # retriever order when no score is attached
        return _metadata_candidate(item_id, score, meta)

    def run(documents):
        kept, _ = guard_items(guard, documents, tenant_id=tenant_id, purpose=purpose, to_candidate=to_candidate,
                              k=k, on_block=on_block, **dict(request_fields))
        return kept

    return RunnableLambda(run, name="RecGuard")


def _node_postprocessor_class():
    from llama_index.core.postprocessor.types import BaseNodePostprocessor

    class RecGuardNodePostprocessor(BaseNodePostprocessor):
        """LlamaIndex node postprocessor: keeps only RecGuard-approved nodes, in RecGuard's order."""
        guard: Any
        tenant_id: str
        purpose: str
        k: int | None = None
        on_block: str = "raise"
        request_fields: dict = {}

        @classmethod
        def create(cls, guard, tenant_id: str, purpose: str, **kwargs):
            return cls(guard=guard, tenant_id=tenant_id, purpose=purpose, **kwargs)

        @classmethod
        def class_name(cls) -> str:
            return "RecGuardNodePostprocessor"

        def _postprocess_nodes(self, nodes, query_bundle=None):
            def to_candidate(node_with_score, rank):
                node = node_with_score.node
                score = node_with_score.score if node_with_score.score is not None else 1.0 / (rank + 1)
                return _metadata_candidate(_safe_id(node.node_id, rank), score, node.metadata or {})
            kept, _ = guard_items(self.guard, nodes, tenant_id=self.tenant_id, purpose=self.purpose,
                                  to_candidate=to_candidate, k=self.k, on_block=self.on_block, **dict(self.request_fields))
            return kept

    return RecGuardNodePostprocessor


def __getattr__(name):  # lazy, so llama-index is only imported when used
    if name == "RecGuardNodePostprocessor":
        cls = _node_postprocessor_class()
        globals()[name] = cls
        return cls
    raise AttributeError(name)
