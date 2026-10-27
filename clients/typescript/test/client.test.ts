import { test } from "node:test";
import assert from "node:assert/strict";
import { RecGuardClient, RecGuardError, type Decision } from "../src/index.js";

const decision = (status: Decision["status"]): Decision => ({
  decision_id: "d1", request_id: "r1", tenant_id: "acme", status, strategy: "base", propensity: 1,
  results: status === "BLOCKED" ? [] : [{ item_id: "a", tenant_id: "acme", score: 1 }],
  policy_fingerprint: "f", reason_codes: status === "BLOCKED" ? ["DENIED_CATEGORY"] : [], receipt: "0".repeat(64),
  expires_at: 0, rejections: [], shadow: null, review_required: [],
});

function fakeFetch(routes: Record<string, unknown>, calls: Array<{ url: string; init: RequestInit }> = []): typeof fetch {
  return (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const path = new URL(String(url)).pathname;
    const body = routes[path];
    if (body instanceof Error) throw body;
    if (body === undefined) return new Response(JSON.stringify({ detail: "nope" }), { status: 404 });
    if (typeof body === "number") return new Response(JSON.stringify({ detail: "denied" }), { status: body });
    return new Response(JSON.stringify(body), { status: 200 });
  }) as typeof fetch;
}

const request = { tenant_id: "acme", request_id: "r1", purpose: "shop", candidates: [{ item_id: "a", tenant_id: "acme", score: 1 }] };

test("guard returns verified decisions and sends bearer tokens", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const client = new RecGuardClient({ baseUrl: "http://rg/", serveToken: "s".repeat(32),
    fetch: fakeFetch({ "/v1/recommendations/evaluate": decision("PASS"), "/v1/recommendations/verify": { valid: true } }, calls) });
  const d = await client.guard(request);
  assert.equal(d.results[0]?.item_id, "a");
  assert.equal(calls[0]?.url, "http://rg/v1/recommendations/evaluate");
  assert.equal((calls[0]?.init.headers as Record<string, string>).Authorization, `Bearer ${"s".repeat(32)}`);
});

test("guard fails closed on BLOCKED, PENDING_APPROVAL, failed verification, HTTP errors and outages", async () => {
  const cases: Array<[Record<string, unknown>, RegExp]> = [
    [{ "/v1/recommendations/evaluate": decision("BLOCKED") }, /RECGUARD_BLOCKED: DENIED_CATEGORY/],
    [{ "/v1/recommendations/evaluate": decision("PENDING_APPROVAL") }, /RECGUARD_PENDING_APPROVAL/],
    [{ "/v1/recommendations/evaluate": decision("PASS"), "/v1/recommendations/verify": { valid: false } }, /VERIFICATION_FAILED/],
    [{ "/v1/recommendations/evaluate": 403 }, /RECGUARD_HTTP_403/],
    [{ "/v1/recommendations/evaluate": new TypeError("ECONNREFUSED") }, /RECGUARD_UNREACHABLE/],
  ];
  for (const [routes, message] of cases) {
    const client = new RecGuardClient({ baseUrl: "http://rg", serveToken: "s".repeat(32), fetch: fakeFetch(routes) });
    await assert.rejects(client.guard(request), (e: unknown) => e instanceof RecGuardError && message.test(e.message));
  }
});

test("scoped calls require their own tokens", async () => {
  const client = new RecGuardClient({ baseUrl: "http://rg", serveToken: "s".repeat(32), fetch: fakeFetch({}) });
  await assert.rejects(client.recordOutcome("acme", "d1", 1), /token required/);
  await assert.rejects(client.review("acme", "d1", true), /token required/);
});

test("times out and fails closed", async () => {
  const hanging = ((_u: unknown, init?: RequestInit) => new Promise((_, reject) =>
    init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))))) as typeof fetch;
  const client = new RecGuardClient({ baseUrl: "http://rg", serveToken: "s".repeat(32), timeoutMs: 20, fetch: hanging });
  await assert.rejects(client.evaluate(request), /RECGUARD_UNREACHABLE/);
});
