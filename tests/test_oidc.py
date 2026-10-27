import json, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from recguard import Candidate, Policy, Request, RecGuard
from recguard.api import create_app
from recguard.oidc import OIDCAuth

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key())), "kid": "k1", "use": "sig", "alg": "RS256"}


@pytest.fixture(scope="module")
def issuer():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            base = f"http://127.0.0.1:{self.server.server_port}"
            body = {"/.well-known/openid-configuration": {"issuer": base, "jwks_uri": base + "/jwks"},
                    "/jwks": {"keys": [JWK]}}.get(self.path)
            self.send_response(200 if body else 404); self.end_headers()
            self.wfile.write(json.dumps(body or {}).encode())

        def log_message(self, *a):
            pass
    server = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def token(iss, key=KEY, kid="k1", alg="RS256", **claims):
    body = {"iss": iss, "aud": "recguard-api", "exp": int(time.time()) + 300, "sub": "priya@acme.example",
            "recguard_tenant": "acme", "scope": "recguard:recommend:serve recguard:decisions:review other:thing", **claims}
    return jwt.encode(body, key, algorithm=alg, headers={"kid": kid})


@pytest.fixture
def client(issuer):
    r = RecGuard()
    r.register_policy(Policy(policy_id="p", version=1, require_evidence=False))
    r.register_policy(Policy(policy_id="hold", version=1, require_evidence=False, purposes=["capex"], require_approval=True))
    oidc = OIDCAuth(issuer, "recguard-api", scope_prefix="recguard:")  # JWKS via discovery
    return TestClient(create_app(r, {}, oidc=oidc)), issuer, r


def evaluate(client, tok, tenant="acme", purpose="shop"):
    return client.post("/v1/recommendations/evaluate", headers={"Authorization": "Bearer " + tok}, json={
        "tenant_id": tenant, "purpose": purpose, "request_id": "r", "k": 1,
        "candidates": [{"item_id": "a", "tenant_id": tenant, "score": 1}]})


def test_valid_token_maps_tenant_scopes_and_subject(client):
    c, iss, engine = client
    assert evaluate(c, token(iss)).status_code == 200
    held = evaluate(c, token(iss), purpose="capex").json()
    ok = c.post("/v1/reviews", headers={"Authorization": "Bearer " + token(iss)},
                json={"tenant_id": "acme", "decision_id": held["decision_id"], "approve": True})
    assert ok.status_code == 200
    reviewer = engine.db.conn.execute("SELECT reviewer FROM decisions WHERE id=?", (held["decision_id"],)).fetchone()["reviewer"]
    assert reviewer == "priya@acme.example"  # from the `sub` claim
    assert c.get("/v1/reviews/acme", headers={"Authorization": "Bearer " + token(iss)}).json()["pending"] == []


@pytest.mark.parametrize("bad,code", [
    (lambda iss: token(iss, aud="someone-else"), 401),
    (lambda iss: token(iss, exp=int(time.time()) - 600), 401),
    (lambda iss: token("https://evil.example", ), 401),
    (lambda iss: token(iss, key=OTHER), 401),                       # signed by an unknown key
    (lambda iss: jwt.encode({"iss": iss, "aud": "recguard-api", "exp": int(time.time()) + 60, "recguard_tenant": "acme",
                             "scope": "recguard:recommend:serve"}, None, algorithm="none", headers={"kid": "k1"}), 401),
    (lambda iss: token(iss, recguard_tenant="other"), 403),          # tenant mismatch
    (lambda iss: token(iss, scope="recguard:metrics:read"), 403),    # missing scope
    (lambda iss: token(iss, recguard_tenant=None), 401),             # no tenant claim
])
def test_invalid_tokens_are_rejected(client, bad, code):
    c, iss, _ = client
    assert evaluate(c, bad(iss)).status_code == code


def test_hmac_algorithms_are_refused_by_configuration(issuer):
    with pytest.raises(ValueError, match="asymmetric"):
        OIDCAuth(issuer, "aud", algorithms=("HS256",))
