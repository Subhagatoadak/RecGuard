from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator
import math

ID = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:\-]*$")]

class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")

class Candidate(Strict):
    item_id: ID
    tenant_id: ID
    score: float
    categories: list[ID] = Field(default_factory=list, max_length=20)
    region: ID | None = None
    min_age: int | None = Field(default=None, ge=0, le=130)
    available: bool = True
    uses_personal_data: bool = False
    evidence_ids: list[ID] = Field(default_factory=list, max_length=30)
    novelty: float = Field(default=0.0, ge=0, le=1)

    @field_validator("score")
    @classmethod
    def finite(cls, x):
        if not math.isfinite(x):
            raise ValueError("scores must be finite")
        return x

class Request(Strict):
    tenant_id: ID
    request_id: ID
    purpose: ID
    subject_ref: ID | None = None  # pseudonymous only; not persisted by kernel
    segment: ID = "general"  # governed, low-cardinality context label; avoid PII here
    region: ID | None = None
    age: int | None = Field(default=None, ge=0, le=130)
    personalization_consent: bool = False
    k: int = Field(default=5, ge=1, le=50)
    candidates: list[Candidate] = Field(min_length=1, max_length=500)
    fallback_candidates: list[Candidate] = Field(default_factory=list, max_length=100)

class Policy(Strict):
    policy_id: ID
    version: int = Field(ge=1)
    tenant_id: ID | None = None  # None = global policy
    purposes: list[ID] = Field(default_factory=list)  # empty means all
    denied_categories: list[ID] = Field(default_factory=list)
    allowed_regions: list[ID] | None = None
    require_evidence: bool = True
    require_consent_for_personalization: bool = True
    max_results: int = Field(default=10, ge=1, le=50)
    min_results: int = Field(default=1, ge=1, le=50)
    allow_experiment: bool = False
    high_impact: bool = False
    allowed_categories: list[ID] | None = None  # allowlist; items need at least one listed category
    denied_item_ids: list[ID] = Field(default_factory=list, max_length=10_000)
    min_score: float | None = None
    max_per_category: int | None = Field(default=None, ge=1, le=50)  # exposure/diversity cap per category
    enabled: bool = True  # retire a policy by registering a new version with enabled: false

    @field_validator("min_score")
    @classmethod
    def finite_threshold(cls, x):
        if x is not None and not math.isfinite(x):
            raise ValueError("min_score must be finite")
        return x

class DecisionState(StrEnum):
    PASS = "PASS"
    REPAIRED = "REPAIRED"
    BLOCKED = "BLOCKED"

class Rejection(Strict):
    item_id: ID
    reason: str
    source: str  # "candidates" or "fallback"

class Decision(Strict):
    decision_id: ID
    request_id: ID
    tenant_id: ID
    status: DecisionState
    results: list[Candidate]
    strategy: str
    propensity: float
    policy_fingerprint: str
    reason_codes: list[str]
    receipt: str
    expires_at: int
    rejections: list[Rejection] = Field(default_factory=list)  # explain why each item was dropped

class Telemetry(Strict):
    event_id: ID
    tenant_id: ID
    event_type: StrEnum("EventType", {x:x for x in ["RENDERED", "NOT_RENDERED", "CLICK", "LATENCY", "ERROR", "POLICY_CHECK", "ABSTAIN"]})
    decision_id: ID | None = None
    latency_ms: float | None = Field(default=None, ge=0, le=1e7)
    token_count: int | None = Field(default=None, ge=0, le=10**8)
    cost_usd: float | None = Field(default=None, ge=0, le=1e6)
    # No arbitrary free-text fields; endpoint is content-free by construction.

class Outcome(Strict):
    outcome_id: ID
    tenant_id: ID
    decision_id: ID
    reward: float = Field(ge=0, le=1)  # verified normalized outcome from trusted backend
    outcome_type: StrEnum("OutcomeType", {x:x for x in ["CONVERSION", "SATISFACTION", "RELEVANCE", "BUSINESS_GOAL"]})

class BatchRequest(Strict):
    requests: list[Request] = Field(min_length=1, max_length=100)

class RetentionRequest(Strict):
    tenant_id: ID
    older_than_seconds: int = Field(ge=3600)

class PolicyRegistration(Strict):
    policy: Policy

class VerifyRequest(Strict):
    decision_id: ID
    tenant_id: ID
    receipt: str = Field(pattern=r"^[0-9a-f]{64}$")  # hex HMAC-SHA256
    results: list[Candidate] = Field(max_length=50)

class ModeUpdate(Strict):
    tenant_id: ID
    mode: StrEnum("LearningMode", {x:x for x in ["OFF", "SHADOW", "EXPERIMENT", "ACTIVE"]})
    # EXPERIMENT/ACTIVE only safe when each effective policy allows exploration.

class ServingUpdate(Strict):
    tenant_id: ID  # "*" switches serving off for every tenant
    enabled: bool

class TokenGrant(Strict):
    tenant_id: ID | Literal["*"]
    scopes: list[ID] = Field(min_length=1)
