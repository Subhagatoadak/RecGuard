"""Single-node SQLite persistence; replace with transactional Postgres for multi-pod deployment."""
from __future__ import annotations
import sqlite3, threading, hashlib, hmac, json, time
from contextlib import contextmanager

SCHEMA_VERSION = 2
# Columns added after v0, created on fresh databases and added in place on older ones.
DECISION_COLUMNS = {
    "reasons": "TEXT NOT NULL DEFAULT '[]'",
    "shadow": "TEXT NOT NULL DEFAULT '{}'",        # shadow-mode verdict summary (v2)
    "approval": "TEXT",                              # NULL | pending | approved | rejected (v2)
    "reviews": "TEXT NOT NULL DEFAULT '[]'",       # reasons a human review is required (v2)
    "reviewer": "TEXT",                              # who approved/rejected (v2)
}


def canon(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

class Store:
    def __init__(self, path: str, signing_key: bytes):
        if len(signing_key) < 32:
            raise ValueError("signing key must be at least 32 bytes")
        self.key = signing_key
        self.audit_key = hmac.new(signing_key, b'recguard:audit:v1', hashlib.sha256).digest()
        self.receipt_key = hmac.new(signing_key, b'recguard:receipt:v1', hashlib.sha256).digest()
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.lock = threading.RLock()
        with self.tx() as c:
            version = c.execute("PRAGMA user_version").fetchone()[0]
            legacy = version == 0 and c.execute("SELECT 1 FROM sqlite_master WHERE name='events'").fetchone()
            if legacy:
                # v0 keyed events/outcomes globally, letting tenants collide on ids.
                c.execute("ALTER TABLE events RENAME TO events_v0")
                c.execute("ALTER TABLE outcomes RENAME TO outcomes_v0")
                c.execute("DROP INDEX IF EXISTS ix_outcome_decision")
            for statement in """
                CREATE TABLE IF NOT EXISTS policies(tenant TEXT, id TEXT, version INTEGER, purpose TEXT, body TEXT, PRIMARY KEY(tenant,id,version));
                CREATE TABLE IF NOT EXISTS state(tenant TEXT PRIMARY KEY, mode TEXT NOT NULL DEFAULT 'OFF', active_strategy TEXT NOT NULL DEFAULT 'base', serving_disabled INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS decisions(id TEXT PRIMARY KEY, tenant TEXT NOT NULL, request_id TEXT NOT NULL, purpose TEXT NOT NULL, segment TEXT NOT NULL, strategy TEXT NOT NULL, propensity REAL NOT NULL, policy_hash TEXT NOT NULL, status TEXT NOT NULL, output_hash TEXT NOT NULL, receipt TEXT NOT NULL, exp INTEGER NOT NULL, at REAL NOT NULL, candidate_count INTEGER NOT NULL, eligible_count INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS events(id TEXT NOT NULL, tenant TEXT NOT NULL, decision_id TEXT, kind TEXT NOT NULL, latency_ms REAL, token_count INTEGER, cost_usd REAL, at REAL NOT NULL, PRIMARY KEY(tenant,id));
                CREATE TABLE IF NOT EXISTS presentations(decision_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS outcomes(id TEXT NOT NULL, tenant TEXT NOT NULL, decision_id TEXT NOT NULL UNIQUE, reward REAL NOT NULL, kind TEXT NOT NULL, at REAL NOT NULL, PRIMARY KEY(tenant,id));
                CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, prev_hash TEXT NOT NULL, digest TEXT NOT NULL, at REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_decision_tenant ON decisions(tenant,at);
                CREATE INDEX IF NOT EXISTS ix_outcome_decision ON outcomes(decision_id);
                CREATE INDEX IF NOT EXISTS ix_event_tenant ON events(tenant,at);
                CREATE INDEX IF NOT EXISTS ix_audit_tenant ON audit(tenant,seq)""".split(";"):
                c.execute(statement)
            if legacy:
                c.execute("INSERT INTO events SELECT * FROM events_v0")
                c.execute("INSERT INTO outcomes SELECT * FROM outcomes_v0")
                c.execute("DROP TABLE events_v0")
                c.execute("DROP TABLE outcomes_v0")
            existing = {row[1] for row in c.execute("PRAGMA table_info(decisions)").fetchall()}
            for column, ddl in DECISION_COLUMNS.items():
                if column not in existing:
                    c.execute(f"ALTER TABLE decisions ADD COLUMN {column} {ddl}")
            c.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

    @contextmanager
    def tx(self):
        with self.lock:
            outer = not self.conn.in_transaction
            if outer:
                self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
                if outer:
                    self.conn.commit()
            except Exception:
                if outer:
                    self.conn.rollback()
                raise

    def audit(self, tenant: str, kind: str, payload: dict):
        """Authenticated hash chain (per-tenant); detects post-hoc row modification/deletion of prefix."""
        with self.tx() as c:
            prev = c.execute("SELECT digest FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1", (tenant,)).fetchone()
            previous = prev["digest"] if prev else "0"*64
            timestamp = time.time()
            body = canon({"tenant":tenant, "kind":kind, "payload":payload, "prev":previous, "at":timestamp})
            digest = hmac.new(self.audit_key, body.encode(), hashlib.sha256).hexdigest()
            c.execute("INSERT INTO audit(tenant,kind,payload,prev_hash,digest,at) VALUES(?,?,?,?,?,?)", (tenant,kind,canon(payload),previous,digest,timestamp))
            return digest

    def audit_head(self, tenant: str) -> dict:
        """Latest chain digest; anchor it externally to detect tail deletion."""
        with self.tx() as c:
            row = c.execute("SELECT seq,digest,at FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 1", (tenant,)).fetchone()
            count = c.execute("SELECT COUNT(*) FROM audit WHERE tenant=?", (tenant,)).fetchone()[0]
        return {"tenant_id":tenant,"entries":count,"head":row["digest"] if row else "0"*64,"seq":row["seq"] if row else None,"at":row["at"] if row else None}

    def audit_verify(self, tenant: str, expected_head: str | None = None) -> dict:
        with self.tx() as c:
            rows = c.execute("SELECT * FROM audit WHERE tenant=? ORDER BY seq", (tenant,)).fetchall()
            prev = "0"*64
            for row in rows:
                body = canon({"tenant":tenant,"kind":row["kind"],"payload":json.loads(row["payload"]),"prev":row["prev_hash"],"at":row["at"]})
                expected = hmac.new(self.audit_key, body.encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected,row["digest"]) or row["prev_hash"]!=prev:
                    return {"valid":False,"checked":len(rows),"first_invalid_seq":row["seq"]}
                prev = row["digest"]
            if expected_head is not None and expected_head != prev and expected_head not in {r["digest"] for r in rows}:
                return {"valid":False,"checked":len(rows),"reason":"ANCHORED_HEAD_MISSING"}
            return {"valid":True,"checked":len(rows),"last_hash":prev}

    def purge(self, tenant: str, before: float) -> dict:
        """Purpose-bound retention: drop operational rows older than `before` (audit chain is kept)."""
        with self.tx() as c:
            old = "SELECT id FROM decisions WHERE tenant=? AND at<?"
            counts = {
                "outcomes": c.execute(f"DELETE FROM outcomes WHERE tenant=? AND decision_id IN ({old})", (tenant,tenant,before)).rowcount,
                "presentations": c.execute(f"DELETE FROM presentations WHERE tenant=? AND decision_id IN ({old})", (tenant,tenant,before)).rowcount,
                "events": c.execute("DELETE FROM events WHERE tenant=? AND at<?", (tenant,before)).rowcount,
                "decisions": c.execute("DELETE FROM decisions WHERE tenant=? AND at<?", (tenant,before)).rowcount,
            }
            self.audit(tenant, "RETENTION_PURGE", {"before":before, **counts})
        return counts
