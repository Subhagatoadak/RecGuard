"""Ed25519 signatures for policy packs (optional `signing` extra: cryptography).

Governance signs the *resolved* pack digest (includes merged); engines configured with
trusted public keys refuse packs whose `<pack>.sig` is missing, from an unknown key, or
doesn't match the pack's current content.
"""
from __future__ import annotations
import base64, datetime, hashlib, json, os
from pathlib import Path
from .policy_pack import PackError, PolicyPack, load_pack


def _crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError:
        raise RuntimeError("Pack signing needs: pip install 'recguard-kernel[signing]'") from None
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def key_id(public_key) -> str:
    serialization, _, _ = _crypto()
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def generate_keypair(prefix: str | Path) -> tuple[Path, Path]:
    """Write <prefix>.key (private, 0600) and <prefix>.pub. Refuses to overwrite."""
    serialization, Ed25519PrivateKey, _ = _crypto()
    private_path, public_path = Path(f"{prefix}.key"), Path(f"{prefix}.pub")
    if private_path.exists() or public_path.exists():
        raise FileExistsError(f"{private_path} or {public_path} already exists")
    private = Ed25519PrivateKey.generate()
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return private_path, public_path


def load_public_keys(paths) -> dict:
    serialization, _, Ed25519PublicKey = _crypto()
    keys = {}
    for path in paths:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(f"{path}: not an Ed25519 public key")
        keys[key_id(key)] = key
    return keys


def sign_pack(pack_path: str | Path, private_key_path: str | Path, signer: str = "") -> Path:
    serialization, Ed25519PrivateKey, _ = _crypto()
    private = serialization.load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    pack = load_pack(pack_path)
    signature = private.sign(f"recguard-pack:v1:{pack.digest}".encode())
    body = {"recguard_signature": 1, "pack": pack.name, "digest": pack.digest, "key_id": key_id(private.public_key()),
            "signer": signer, "signed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "signature": base64.b64encode(signature).decode()}
    out = Path(f"{pack_path}.sig")
    out.write_text(json.dumps(body, indent=2) + "\n")
    return out


def verify_pack(pack: PolicyPack, signature: dict | str | Path | None, trusted: dict) -> dict:
    """Return the signature record if valid for this exact pack content; raise PackError otherwise."""
    if signature is None and pack._origin is not None:
        signature = Path(f"{pack._origin}.sig")
    if signature is None:
        raise PackError(f"pack {pack.name!r}: signature required (no .sig file)")
    if isinstance(signature, (str, Path)):
        try:
            signature = json.loads(Path(signature).read_text())
        except (OSError, ValueError):
            raise PackError(f"pack {pack.name!r}: signature file missing or unreadable") from None
    key = trusted.get(signature.get("key_id"))
    if key is None:
        raise PackError(f"pack {pack.name!r}: signed by an untrusted key {signature.get('key_id')!r}")
    if signature.get("digest") != pack.digest:
        raise PackError(f"pack {pack.name!r}: content changed since it was signed")
    try:
        key.verify(base64.b64decode(signature["signature"]), f"recguard-pack:v1:{pack.digest}".encode())
    except Exception:
        raise PackError(f"pack {pack.name!r}: invalid signature") from None
    return signature
