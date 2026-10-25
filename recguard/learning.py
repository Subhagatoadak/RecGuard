"""Policy-bounded bandit and conservative off-policy evaluation.

EXPERIMENT randomizes only between compliant rerankers. The epsilon-greedy
propensity of the chosen arm is logged explicitly and is required for OPE.
No telemetry event may produce a learning reward; only separate signed outcomes.
"""
from __future__ import annotations
from collections import defaultdict
import hashlib, math, random, statistics

ARMS = ("base", "diverse", "novelty")
EPSILON = 0.25  # explicit exploration; low-volume demonstration, configurable later


def in_holdout(decision_id: str) -> bool:
    """Stable 50% split; the bandit never learns from holdout decisions."""
    return int(hashlib.sha256(decision_id.encode()).hexdigest(), 16) % 2 == 0


def select_arm(conn, tenant: str, segment: str, seed: int | None = None, arms: tuple[str, ...] = ARMS) -> tuple[str, float]:
    """Epsilon-greedy contextual bandit: empirical Beta(1,1) posterior means.

    Segment is a low-cardinality, governed context label; there is no direct
    identity-based personalization. In non-stationary environments use decay.
    """
    rows = conn.execute("""SELECT d.id, d.strategy, o.reward FROM decisions d
        JOIN outcomes o ON o.decision_id=d.id
        WHERE d.tenant=? AND d.segment=? AND d.status != 'BLOCKED' AND d.propensity < 1""", (tenant, segment)).fetchall()
    n = defaultdict(int)
    sums = defaultdict(float)
    for r in rows:
        if in_holdout(r["id"]):
            continue
        n[r["strategy"]] += 1
        sums[r["strategy"]] += r["reward"]
    means = {arm: (1+sums[arm]) / (2+n[arm]) for arm in arms}
    greedy = max(arms, key=lambda a:(means[a], -arms.index(a)))
    rng = random.Random(seed)
    if rng.random() < EPSILON:
        arm = rng.choice(arms)
    else:
        arm = greedy
    propensity = EPSILON / len(arms) + ((1-EPSILON) if arm==greedy else 0)
    return arm, propensity


def _ess(weights):
    return (sum(weights)**2 / sum(x*x for x in weights)) if sum(x*x for x in weights)>0 else 0.0


def evaluate_promotion(conn, tenant: str, challenger: str, seed: int = 23, arms: tuple[str, ...] = ARMS) -> dict:
    """Holdout IPS difference with bootstrap; cautious proof of comparative reward.

    Uses stable 50% holdout to reduce adaptive selection leakage, but repeated
    promotion attempts against the same holdout still invalidate significance.
    In production lock prospective evaluation epochs + preregister candidate.
    """
    if challenger not in arms or challenger == "base":
        return {"approved":False,"reason":"INVALID_CHALLENGER"}
    rows = conn.execute("""SELECT d.id, d.strategy, d.propensity, o.reward FROM decisions d
        JOIN outcomes o ON d.id=o.decision_id JOIN presentations p ON p.decision_id=d.id
        WHERE d.tenant=? AND d.status!='BLOCKED' AND d.propensity < 1 ORDER BY d.at,d.id""", (tenant,)).fetchall()
    holdout = [r for r in rows if in_holdout(r["id"])]
    if len(holdout)<100:
        return {"approved":False,"reason":"INSUFFICIENT_HOLDOUT", "n_holdout":len(holdout),"minimum":100}
    wc=[1/r["propensity"] if r["strategy"]==challenger else 0.0 for r in holdout]
    wb=[1/r["propensity"] if r["strategy"]=="base" else 0.0 for r in holdout]
    ess_c, ess_b=_ess(wc),_ess(wb)
    if min(ess_c,ess_b)<20:
        return {"approved":False,"reason":"INSUFFICIENT_OVERLAP", "n_holdout":len(holdout),"ess_challenger":round(ess_c,2),"ess_base":round(ess_b,2)}
    rewards=[r["reward"] for r in holdout]
    contributions=[(wc[i]-wb[i])*rewards[i] for i in range(len(holdout))]
    effect=statistics.mean(contributions)
    rng=random.Random(seed)
    boot=[]
    for _ in range(500):
        sample=[contributions[rng.randrange(len(contributions))] for _ in contributions]
        boot.append(statistics.mean(sample))
    boot.sort()
    lower,upper=boot[12],boot[487]
    return {"approved": lower>0.0, "reason":"PASSED" if lower>0.0 else "NO_CONSERVATIVE_IMPROVEMENT",
            "estimate":round(effect,4),"ci95":[round(lower,4),round(upper,4)],
            "ess_challenger":round(ess_c,2),"ess_base":round(ess_b,2),"n_holdout":len(holdout),
            "warning":"Policy selected against multiple tests needs a fresh prospective holdout; this is a demonstration gate."}
