"""OIDC / JWT bearer authentication for the API (optional `oidc` extra: PyJWT with crypto).

Tokens from your identity provider are verified against its JWKS (signature, issuer,
audience, expiry). The tenant, scopes and subject come from configurable claims:

    RECGUARD_OIDC_ISSUER=https://login.example.com/        # enables OIDC
    RECGUARD_OIDC_AUDIENCE=recguard-api
    RECGUARD_OIDC_JWKS_URL=...                             # default: issuer discovery document
    RECGUARD_OIDC_TENANT_CLAIM=recguard_tenant             # "*" for global admins
    RECGUARD_OIDC_SCOPE_CLAIM=scope                        # space-separated string or list ("scp" also read)
    RECGUARD_OIDC_SCOPE_PREFIX=recguard:                   # optional; stripped from scopes
    RECGUARD_OIDC_ALGORITHMS=RS256,ES256
"""
from __future__ import annotations
import json, os, urllib.request
from .contracts import TokenGrant


class OIDCAuth:
    def __init__(self, issuer: str, audience: str, jwks_url: str | None = None, tenant_claim: str = "recguard_tenant",
                 scope_claim: str = "scope", scope_prefix: str = "", subject_claim: str = "sub",
                 algorithms: tuple[str, ...] = ("RS256", "ES256"), leeway: int = 30):
        try:
            import jwt
        except ImportError:
            raise RuntimeError("OIDC needs PyJWT: pip install 'recguard-kernel[oidc]'") from None
        if any(a.upper().startswith("HS") or a.lower() == "none" for a in algorithms):
            raise ValueError("OIDC accepts asymmetric algorithms only (no HS*/none)")
        self._jwt = jwt
        self.issuer, self.audience = issuer, audience
        self.tenant_claim, self.scope_claim, self.scope_prefix, self.subject_claim = tenant_claim, scope_claim, scope_prefix, subject_claim
        self.algorithms, self.leeway = list(algorithms), leeway
        self.jwks = jwt.PyJWKClient(jwks_url or self._discover(issuer), cache_keys=True, lifespan=300, timeout=10)

    @staticmethod
    def _discover(issuer: str) -> str:
        url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.load(response)["jwks_uri"]

    @classmethod
    def from_environment(cls) -> "OIDCAuth | None":
        issuer = os.getenv("RECGUARD_OIDC_ISSUER")
        if not issuer:
            return None
        audience = os.getenv("RECGUARD_OIDC_AUDIENCE")
        if not audience:
            raise RuntimeError("RECGUARD_OIDC_AUDIENCE is required with RECGUARD_OIDC_ISSUER")
        return cls(issuer, audience, os.getenv("RECGUARD_OIDC_JWKS_URL") or None,
                   os.getenv("RECGUARD_OIDC_TENANT_CLAIM", "recguard_tenant"), os.getenv("RECGUARD_OIDC_SCOPE_CLAIM", "scope"),
                   os.getenv("RECGUARD_OIDC_SCOPE_PREFIX", ""), os.getenv("RECGUARD_OIDC_SUBJECT_CLAIM", "sub"),
                   tuple(a.strip() for a in os.getenv("RECGUARD_OIDC_ALGORITHMS", "RS256,ES256").split(",") if a.strip()))

    def grant(self, token: str) -> TokenGrant:
        """Verify a JWT and map it to a tenant-scoped grant. Raises ValueError when invalid."""
        jwt = self._jwt
        try:
            key = self.jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=self.algorithms, audience=self.audience, issuer=self.issuer,
                                leeway=self.leeway, options={"require": ["exp", "iss", "aud"]})
        except jwt.PyJWTError as exc:
            raise ValueError(f"invalid token: {type(exc).__name__}") from None
        raw = claims.get(self.scope_claim, claims.get("scp", []))
        scopes = raw.split() if isinstance(raw, str) else list(raw or [])
        if self.scope_prefix:
            scopes = [s[len(self.scope_prefix):] for s in scopes if s.startswith(self.scope_prefix)]
        subject = str(claims.get(self.subject_claim) or "")[:128] or None
        if subject is not None:
            subject = "".join(ch if ch.isalnum() or ch in "_.:-@" else "_" for ch in subject)
            subject = subject if subject[0].isalnum() else "u" + subject
        try:
            return TokenGrant(tenant_id=claims.get(self.tenant_claim), scopes=scopes, subject=subject)
        except Exception:
            raise ValueError("token lacks a valid tenant claim or scopes") from None
