/**
 * Fail-closed client for the RecGuard API. Keep tokens in a trusted backend, never in browsers.
 * Show users ONLY `decision.results`; anything else (errors, BLOCKED, PENDING_APPROVAL) means show nothing.
 */

export interface Candidate {
  item_id: string;
  tenant_id: string;
  score: number;
  categories?: string[];
  region?: string | null;
  min_age?: number | null;
  available?: boolean;
  uses_personal_data?: boolean;
  evidence_ids?: string[];
  novelty?: number;
}

export interface RecommendationRequest {
  tenant_id: string;
  request_id: string;
  purpose: string;
  candidates: Candidate[];
  fallback_candidates?: Candidate[];
  k?: number;
  segment?: string;
  region?: string | null;
  age?: number | null;
  personalization_consent?: boolean;
  subject_ref?: string | null;
}

export interface Rejection { item_id: string; reason: string; source: string }
export interface ReviewItem { item_id: string | null; reason: string }
export interface ShadowReport {
  would_reject: Rejection[];
  would_admit: string[];
  decision_violations: string[];
  error: string | null;
}

export type DecisionStatus = "PASS" | "REPAIRED" | "BLOCKED" | "PENDING_APPROVAL";

export interface Decision {
  decision_id: string;
  request_id: string;
  tenant_id: string;
  status: DecisionStatus;
  results: Candidate[];
  strategy: string;
  propensity: number;
  policy_fingerprint: string;
  reason_codes: string[];
  receipt: string;
  expires_at: number;
  rejections: Rejection[];
  shadow: ShadowReport | null;
  review_required: ReviewItem[];
}

export type OutcomeType = "CONVERSION" | "SATISFACTION" | "RELEVANCE" | "BUSINESS_GOAL";
export type EventType = "RENDERED" | "NOT_RENDERED" | "CLICK" | "LATENCY" | "ERROR" | "POLICY_CHECK" | "ABSTAIN";

export interface ClientOptions {
  baseUrl: string;
  serveToken: string;
  presentToken?: string;
  outcomeToken?: string;
  telemetryToken?: string;
  reviewToken?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

/** Any failure to obtain an authorized result. Hosts must fail closed on it. */
export class RecGuardError extends Error {
  constructor(message: string, readonly status?: number, readonly decision?: Decision) {
    super(message);
    this.name = "RecGuardError";
  }
}

export class RecGuardClient {
  private readonly url: string;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly options: ClientOptions) {
    this.url = options.baseUrl.replace(/\/+$/, "");
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    if (!this.fetchImpl) throw new Error("No fetch implementation available (Node 18+ or pass options.fetch)");
  }

  private async call<T>(method: "GET" | "POST", path: string, token: string | undefined, body?: unknown): Promise<T> {
    if (!token) throw new RecGuardError(`token required for ${path}`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.options.timeoutMs ?? 5000);
    let response: Response;
    try {
      response = await this.fetchImpl(this.url + path, {
        method,
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (error) {
      throw new RecGuardError(`RECGUARD_UNREACHABLE: ${(error as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) {
      let detail: unknown;
      try { detail = ((await response.json()) as { detail?: unknown }).detail; } catch { detail = undefined; }
      throw new RecGuardError(`RECGUARD_HTTP_${response.status}: ${JSON.stringify(detail ?? null)}`, response.status);
    }
    return (await response.json()) as T;
  }

  /** Raw decision (may be BLOCKED or PENDING_APPROVAL). Prefer `guard` for display paths. */
  evaluate(request: RecommendationRequest): Promise<Decision> {
    return this.call("POST", "/v1/recommendations/evaluate", this.options.serveToken, request);
  }

  evaluateBatch(requests: RecommendationRequest[]): Promise<Decision[]> {
    return this.call<{ decisions: Decision[] }>("POST", "/v1/recommendations/evaluate-batch", this.options.serveToken, { requests })
      .then((r) => r.decisions);
  }

  /** Evaluate and verify; throws unless there are approved, verified results to show. */
  async guard(request: RecommendationRequest): Promise<Decision> {
    const decision = await this.evaluate(request);
    if (decision.status === "BLOCKED") {
      throw new RecGuardError(`RECGUARD_BLOCKED: ${decision.reason_codes.join(",")}`, undefined, decision);
    }
    if (decision.status === "PENDING_APPROVAL") {
      throw new RecGuardError(`RECGUARD_PENDING_APPROVAL: ${decision.decision_id}`, undefined, decision);
    }
    if (!(await this.verify(decision, request.tenant_id))) {
      throw new RecGuardError("RECGUARD_VERIFICATION_FAILED", undefined, decision);
    }
    return decision;
  }

  private static receipt(decision: Pick<Decision, "decision_id" | "receipt" | "results">, tenantId: string) {
    return { tenant_id: tenantId, decision_id: decision.decision_id, receipt: decision.receipt, results: decision.results };
  }

  async verify(decision: Pick<Decision, "decision_id" | "receipt" | "results">, tenantId: string): Promise<boolean> {
    const r = await this.call<{ valid: boolean }>("POST", "/v1/recommendations/verify", this.options.serveToken,
      RecGuardClient.receipt(decision, tenantId));
    return r.valid === true;
  }

  /** Call only after the host has actually shown exactly these verified results. */
  recordPresentation(decision: Pick<Decision, "decision_id" | "receipt" | "results">, tenantId: string): Promise<{ ok: boolean }> {
    return this.call("POST", "/v1/recommendations/presented", this.options.presentToken, RecGuardClient.receipt(decision, tenantId));
  }

  /** Trusted, normalized reward in [0, 1], from your backend only. */
  recordOutcome(tenantId: string, decisionId: string, reward: number, outcomeType: OutcomeType = "CONVERSION",
                outcomeId: string = crypto.randomUUID().replace(/-/g, "")): Promise<{ accepted: boolean }> {
    return this.call("POST", "/v1/outcomes", this.options.outcomeToken,
      { tenant_id: tenantId, decision_id: decisionId, reward, outcome_type: outcomeType, outcome_id: outcomeId });
  }

  /** Content-free telemetry: latency_ms, token_count and cost_usd only. */
  recordEvent(tenantId: string, eventType: EventType,
              measures: { decision_id?: string; latency_ms?: number; token_count?: number; cost_usd?: number; event_id?: string } = {}) {
    const { event_id, ...rest } = measures;
    return this.call<{ accepted: boolean }>("POST", "/v1/telemetry/events", this.options.telemetryToken,
      { tenant_id: tenantId, event_type: eventType, event_id: event_id ?? crypto.randomUUID().replace(/-/g, ""), ...rest });
  }

  effectivePolicy(tenantId: string, purpose: string): Promise<Record<string, unknown> | null> {
    return this.call<{ effective: Record<string, unknown> | null }>("GET",
      `/v1/policies/${encodeURIComponent(tenantId)}?purpose=${encodeURIComponent(purpose)}`, this.options.serveToken)
      .then((r) => r.effective);
  }

  pendingReviews(tenantId: string): Promise<Array<Record<string, unknown>>> {
    return this.call<{ pending: Array<Record<string, unknown>> }>("GET", `/v1/reviews/${encodeURIComponent(tenantId)}`,
      this.options.reviewToken).then((r) => r.pending);
  }

  /** Approve (returns a fresh receipt) or reject a PENDING_APPROVAL decision. For human reviewers' tools. */
  review(tenantId: string, decisionId: string, approve: boolean, note = "") {
    return this.call<{ decision_id: string; status: string; receipt: string | null; expires_at: number | null }>(
      "POST", "/v1/reviews", this.options.reviewToken, { tenant_id: tenantId, decision_id: decisionId, approve, note });
  }
}
