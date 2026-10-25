// Node.js 18+: language-neutral HTTP integration. Keep tokens in the TRUSTED BACKEND.
// RECGUARD_URL, RECGUARD_SERVE_TOKEN and RECGUARD_PRESENT_TOKEN must be in process env.
const url = process.env.RECGUARD_URL ?? 'http://127.0.0.1:8765';
async function call(path, token, payload) {
  const response = await fetch(url + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: JSON.stringify(payload)
  });
  if (!response.ok) throw new Error(`RecGuard failed closed: ${response.status}`);
  return await response.json();
}
export async function guardRecommendations(request) {
  const result = await call('/v1/recommendations/evaluate', process.env.RECGUARD_SERVE_TOKEN, request);
  if (result.status === 'BLOCKED') throw new Error('No authorized recommendations');
  const receipt = {tenant_id: request.tenant_id, decision_id: result.decision_id,
                   receipt: result.receipt, results: result.results};
  const verification = await call('/v1/recommendations/verify', process.env.RECGUARD_SERVE_TOKEN, receipt);
  if (!verification.valid) throw new Error('RecGuard receipt invalid');
  // DO NOT display original candidates; only display `result.results`.
  // After actual host presentation, send receipt to /v1/recommendations/presented
  // with the separately scoped trusted presentation token.
  return {results:result.results, receipt};
}
