import json, textwrap
import pytest
from recguard import RecGuard, PackError
from recguard.__main__ import main as cli
from recguard import signing

PACK = """
recguard: 1
name: signed
policies: [{policy_id: base, version: 1, require_evidence: false}]
checks: [{name: c, rules: [{reject: X, if: "item.score < 0"}]}]
"""


@pytest.fixture
def keys(tmp_path):
    gov = signing.generate_keypair(tmp_path / "governance")
    rogue = signing.generate_keypair(tmp_path / "rogue")
    return gov, rogue


def test_signed_pack_loads_and_tampering_or_unknown_keys_fail(tmp_path, keys):
    (gov_key, gov_pub), (rogue_key, _) = keys
    assert oct((tmp_path / "governance.key").stat().st_mode)[-3:] == "600"
    pack = tmp_path / "pack.yaml"
    pack.write_text(textwrap.dedent(PACK))
    r = RecGuard()
    r.trust_pack_keys([gov_pub])
    with pytest.raises(PackError, match="signature"):
        r.load_policy_pack(pack)                                   # unsigned
    signing.sign_pack(pack, rogue_key)
    with pytest.raises(PackError, match="untrusted key"):
        r.load_policy_pack(pack)                                   # wrong signer
    signing.sign_pack(pack, gov_key, signer="governance-board")
    summary = r.load_policy_pack(pack)
    assert summary["signed_by"] == json.loads((tmp_path / "pack.yaml.sig").read_text())["key_id"]
    pack.write_text(textwrap.dedent(PACK).replace("item.score < 0", "item.score < -1"))
    with pytest.raises(PackError, match="changed since it was signed"):
        r.load_policy_pack(pack)                                   # edited after signing
    result = r.refresh_policy_packs(force=True)[0]                 # hot reload refuses too, keeps last good
    assert "changed since it was signed" in result["error"]
    sig = json.loads((tmp_path / "pack.yaml.sig").read_text())
    with pytest.raises(PackError, match="mapping|signature"):
        r.load_policy_pack({"recguard": 1, "name": "inline"})      # in-memory packs need an explicit signature
    sig_bad = {**sig, "signature": sig["signature"][:-4] + "AAAA"}
    pack.write_text(textwrap.dedent(PACK))
    with pytest.raises(PackError, match="invalid signature"):
        r.load_policy_pack(pack, signature=sig_bad)


def test_cli_keygen_sign_verify(tmp_path, capsys):
    pack = tmp_path / "pack.yaml"
    pack.write_text(textwrap.dedent(PACK))
    cli(["policy", "keygen", str(tmp_path / "gov")])
    cli(["policy", "sign", str(pack), "--key", str(tmp_path / "gov.key"), "--signer", "board"])
    cli(["policy", "verify", str(pack), "--pub", str(tmp_path / "gov.pub")])
    out = capsys.readouterr().out
    assert "wrote" in out and "signed by key" in out and "board" in out
    pack.write_text(textwrap.dedent(PACK) + "description: edited\n")
    with pytest.raises(SystemExit) as fail:
        cli(["policy", "verify", str(pack), "--pub", str(tmp_path / "gov.pub")])
    assert fail.value.code == 1
    with pytest.raises(SystemExit):
        cli(["policy", "keygen", str(tmp_path / "gov")])           # never overwrites keys


def test_server_refuses_unsigned_packs_at_startup(tmp_path, keys, monkeypatch):
    from recguard.api import from_environment
    (gov_key, gov_pub), _ = keys
    pack = tmp_path / "pack.yaml"
    pack.write_text(textwrap.dedent(PACK))
    monkeypatch.setenv("RECGUARD_TOKENS_JSON", json.dumps({"t" * 32: {"tenant_id": "acme", "scopes": ["recommend:serve"]}}))
    monkeypatch.setenv("RECGUARD_SIGNING_KEY", "k" * 40)
    monkeypatch.setenv("RECGUARD_DB", str(tmp_path / "db.sqlite"))
    monkeypatch.setenv("RECGUARD_POLICY_PACKS", str(pack))
    monkeypatch.setenv("RECGUARD_POLICY_PUBLIC_KEYS", str(gov_pub))
    with pytest.raises(PackError, match="signature"):
        from_environment()                                          # fail closed: no unsigned rules in production
    signing.sign_pack(pack, gov_key)
    assert from_environment() is not None
