"""Pure adapter boundary: any recommender supplies candidates; RecGuard governs output."""
from __future__ import annotations
import hashlib, hmac, json, re, secrets, sqlite3, time
from collections import Counter
from dataclasses import dataclass
from typing import Callable
from .contracts import Candidate, Decision, DecisionState, Outcome, Policy, Rejection, Request, Telemetry
from .storage import Store, canon
from . import learning

Check = Callable[[Candidate, Request], "str | None"]
Strategy = Callable[[list[Candidate], int], list[Candidate]]
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,63}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Denied(Exception):
    pass


@dataclass(frozen=True)
class EffectivePolicy:
    denied: frozenset[str]
    regions: frozenset[str] | None
    evidence: bool
    consent: bool
    min_results: int
    max_results: int
    experiment: bool
    high_impact: bool
    fingerprint: str
    allowed_categories: frozenset[str] | None = None
    denied_items: frozenset[str] = frozenset()
    min_score: float | None = None
    max_per_category: int | None = None


class RecGuard:
    BUILTIN_STRATEGIES = learning.ARMS

    def __init__(self, db_path: str = ":memory:", signing_key: bytes | None = None, receipt_ttl: int = 300):
        if db_path != ":memory:" and signing_key is None:
            raise ValueError("Persistent RecGuard requires a stable explicit signing key")
        if not 1 <= receipt_ttl <= 86400:
            raise ValueError("receipt_ttl must be between 1 second and 1 day")
        self.db = Store(db_path, signing_key or secrets.token_bytes(32))
        self.receipt_ttl = receipt_ttl
        self._checks: dict[str, Check] = {}
        self._strategies: dict[str, tuple[Strategy, bool]] = {}

    # ---- extension points -------------------------------------------------

    def register_check(self, name: str, fn: Check):
        """Add a host-specific rule. Return a reason code to reject, None to allow.

        Checks are AND-ed with built-in policy; they can only remove items. A raising
        check fails closed. Registered names are part of the policy fingerprint.
        """
        if not NAME.match(name) or name in self._checks:
            raise ValueError("check name must be a unique identifier")
        self._checks[name] = fn

    def register_strategy(self, name: str, fn: Strategy, explore: bool = True):
        """Add a reranker fn(eligible_candidates, k) -> ordered subset.

        Output is validated: it may only reorder/drop already-eligible items, so a
        strategy can never inject or alter content. `explore` adds it as a bandit arm.
        """
        if not NAME.match(name) or name in self.BUILTIN_STRATEGIES or name in self._strategies or name == "none":
            raise ValueError("strategy name must be a unique identifier")
        self._strategies[name] = (fn, explore)

    @property
    def STRATEGIES(self) -> tuple[str, ...]:
        return self.BUILTIN_STRATEGIES + tuple(self._strategies)

    def _arms(self) -> tuple[str, ...]:
        return self.BUILTIN_STRATEGIES + tuple(n for n, (_, explore) in self._strategies.items() if explore)

    # ---- policy -----------------------------------------------------------

    def register_policy(self, policy: Policy):
        if policy.min_results > policy.max_results:
            raise Denied("MIN_RESULTS_EXCEEDS_MAX")
        tenant=policy.tenant_id or "*"
        with self.db.tx() as c:
            existing=c.execute("SELECT MAX(version) AS v FROM policies WHERE tenant=? AND id=?",(tenant, policy.policy_id)).fetchone()["v"]
            if existing is not None and existing>=policy.version:
                raise Denied("VERSION_NOT_MONOTONIC")
            c.execute("INSERT INTO policies VALUES(?,?,?,?,?)",(tenant,policy.policy_id,policy.version,canon(policy.purposes),policy.model_dump_json()))
            self.db.audit(tenant,"POLICY_REGISTERED",{"policy_id":policy.policy_id,"version":policy.version})

    def policies(self, tenant: str) -> list[Policy]:
        """Latest version of every global and tenant policy visible to `tenant`."""
        with self.db.tx() as c:
            rows=c.execute("""SELECT p.* FROM policies p JOIN
                (SELECT tenant,id,MAX(version) AS version FROM policies WHERE tenant IN ('*',?) GROUP BY tenant,id) l
                ON p.tenant=l.tenant AND p.id=l.id AND p.version=l.version ORDER BY p.tenant,p.id""", (tenant,)).fetchall()
        return [Policy.model_validate_json(row["body"]) for row in rows]

    def _policy(self, tenant: str, purpose: str) -> EffectivePolicy | None:
        relevant=[p for p in self.policies(tenant) if not p.purposes or purpose in p.purposes]
        if not relevant:
            return None
        allowed=[set(p.allowed_regions) for p in relevant if p.allowed_regions is not None]
        allowed_cats=[set(p.allowed_categories) for p in relevant if p.allowed_categories is not None]
        scores=[p.min_score for p in relevant if p.min_score is not None]
        caps=[p.max_per_category for p in relevant if p.max_per_category is not None]
        body=[p.model_dump(mode="json") for p in sorted(relevant, key=lambda x:(x.tenant_id or "*",x.policy_id,x.version))]
        fp=hashlib.sha256(canon({"policies":body,"checks":sorted(self._checks)}).encode()).hexdigest()
        return EffectivePolicy(
            denied=frozenset(cat for p in relevant for cat in p.denied_categories),
            regions=frozenset(set.intersection(*allowed)) if allowed else None,
            evidence=any(p.require_evidence for p in relevant),
            consent=any(p.require_consent_for_personalization for p in relevant),
            min_results=max(p.min_results for p in relevant),
            max_results=min(p.max_results for p in relevant),
            experiment=all(p.allow_experiment for p in relevant),
            high_impact=any(p.high_impact for p in relevant), fingerprint=fp,
            allowed_categories=frozenset(set.intersection(*allowed_cats)) if allowed_cats else None,
            denied_items=frozenset(i for p in relevant for i in p.denied_item_ids),
            min_score=max(scores) if scores else None,
            max_per_category=min(caps) if caps else None)

    def effective_policy(self, tenant: str, purpose: str) -> dict | None:
        """Composed policy actually enforced for a tenant/purpose (for debugging integrations)."""
        pol=self._policy(tenant,purpose)
        if pol is None:
            return None
        sets=lambda v:sorted(v) if v is not None else None
        return {"fingerprint":pol.fingerprint,"denied_categories":sets(pol.denied),"allowed_regions":sets(pol.regions),
                "allowed_categories":sets(pol.allowed_categories),"denied_item_ids":sets(pol.denied_items),
                "require_evidence":pol.evidence,"require_consent_for_personalization":pol.consent,
                "min_results":pol.min_results,"max_results":pol.max_results,"min_score":pol.min_score,
                "max_per_category":pol.max_per_category,"allow_experiment":pol.experiment,"high_impact":pol.high_impact,
                "custom_checks":sorted(self._checks)}

    def _check(self, c:Candidate, req:Request, pol:EffectivePolicy) -> str | None:
        if c.tenant_id != req.tenant_id: return "CROSS_TENANT"
        if not c.available: return "UNAVAILABLE"
        if c.item_id in pol.denied_items: return "DENIED_ITEM"
        if pol.denied.intersection(c.categories):return "DENIED_CATEGORY"
        if pol.allowed_categories is not None and not pol.allowed_categories.intersection(c.categories):return "CATEGORY_NOT_ALLOWED"
        if pol.regions is not None and (req.region is None or req.region not in pol.regions):return "REGION_NOT_ALLOWED"
        if c.region is not None and (req.region is None or req.region!=c.region):return "ITEM_REGION_MISMATCH"
        if c.min_age is not None and (req.age is None or req.age<c.min_age):return "AGE_UNVERIFIED_OR_TOO_LOW"
        if pol.evidence and not c.evidence_ids:return "EVIDENCE_REQUIRED"
        if pol.consent and not req.personalization_consent and c.uses_personal_data:return "CONSENT_REQUIRED"
        if pol.min_score is not None and c.score<pol.min_score:return "SCORE_BELOW_MINIMUM"
        for name,fn in self._checks.items():
            try:
                reason=fn(c.model_copy(deep=True),req)
            except Exception:
                return f"CHECK_ERROR:{name}"
            if reason is not None:
                return f"{name}:{reason}"
        return None

    # ---- ranking ----------------------------------------------------------

    @staticmethod
    def _rank(candidates:list[Candidate], strategy:str, k:int) -> list[Candidate]:
        remaining=sorted(candidates,key=lambda x:(-x.score,x.item_id))
        if strategy=="base":return remaining[:k]
        lo=min(x.score for x in remaining)
        hi=max(x.score for x in remaining)
        norm=lambda x:(x.score-lo)/(hi-lo) if hi>lo else 0.5
        if strategy=="novelty":return sorted(remaining,key=lambda x:(-(0.75*norm(x) + 0.25*x.novelty),x.item_id))[:k]
        if strategy!="diverse": raise Denied("UNKNOWN_STRATEGY")
        picked=[]
        while remaining and len(picked)<k:
            used=Counter(cat for p in picked for cat in p.categories)
            item=min(remaining,key=lambda x:(-(norm(x)-0.65*sum(used[c] for c in x.categories)),x.item_id))
            picked.append(item)
            remaining.remove(item)
        return picked

    def _order(self, items:list[Candidate], strategy:str, reasons:Counter) -> list[Candidate]:
        """Full ordering by strategy; custom output is validated as a subset of `items`."""
        if strategy in self.BUILTIN_STRATEGIES:
            return self._rank(items,strategy,len(items))
        fn,_=self._strategies[strategy]
        by_id={x.item_id:x for x in items}
        try:
            out=fn([x.model_copy(deep=True) for x in items],len(items))
            ids=[x.item_id for x in out]
        except Exception:
            reasons["STRATEGY_ERROR"]+=1
            return self._rank(items,"base",len(items))
        if len(ids)!=len(set(ids)) or any(i not in by_id for i in ids):
            reasons["STRATEGY_OUTPUT_REJECTED"]+=1
            return self._rank(items,"base",len(items))
        return [by_id[i] for i in ids]

    @staticmethod
    def _fill(picked:list[Candidate], ranked:list[Candidate], k:int, cap:int|None, reasons:Counter,
              rejections:list[Rejection], source:str) -> int:
        """Append ranked items until k, honouring the per-category cap. Returns items skipped by the cap."""
        used=Counter(cat for p in picked for cat in p.categories)
        skipped=0
        for item in ranked:
            if len(picked)>=k:break
            if cap is not None and any(used[c]>=cap for c in item.categories):
                skipped+=1;reasons["CATEGORY_CAP"]+=1
                rejections.append(Rejection(item_id=item.item_id,reason="CATEGORY_CAP",source=source))
                continue
            picked.append(item);used.update(item.categories)
        return skipped

    @staticmethod
    def _hash_results(items:list[Candidate]) -> str:
        return hashlib.sha256(canon([x.model_dump(mode='json') for x in items]).encode()).hexdigest()

    def _signature(self, tenant, did, hash_, exp, policy_hash):
        payload=canon([tenant,did,hash_,exp,policy_hash])
        return hmac.new(self.db.receipt_key,payload.encode(),hashlib.sha256).hexdigest()

    # ---- learning state ---------------------------------------------------

    def mode(self, tenant: str, value: str):
        if value not in ("OFF","SHADOW","EXPERIMENT","ACTIVE"):
            raise Denied("INVALID_MODE")
        with self.db.tx() as c:
            current=c.execute("SELECT active_strategy FROM state WHERE tenant=?",(tenant,)).fetchone()
            if value=="ACTIVE" and (not current or current["active_strategy"]=="base"):
                raise Denied("NO_PROMOTED_STRATEGY")
            c.execute("INSERT INTO state(tenant,mode) VALUES(?,?) ON CONFLICT(tenant) DO UPDATE SET mode=excluded.mode",(tenant,value))
            self.db.audit(tenant,"MODE_CHANGED",{"mode":value})

    def _strategy(self,req:Request, pol:EffectivePolicy)->tuple[str,float]:
        with self.db.tx() as c:
            row=c.execute("SELECT mode,active_strategy FROM state WHERE tenant=?",(req.tenant_id,)).fetchone()
            if not row:return "base",1.0
            if not pol.experiment or pol.high_impact:return "base",1.0
            if row["mode"]=="EXPERIMENT":return learning.select_arm(c,req.tenant_id,req.segment,arms=self._arms())
            if row["mode"]=="ACTIVE":return row["active_strategy"],1.0
        return "base",1.0

    def serving_enabled(self, tenant:str)->bool:
        """False when the tenant or the global ("*") kill switch is off."""
        with self.db.tx() as c:
            row=c.execute("SELECT MAX(serving_disabled) AS off FROM state WHERE tenant IN (?,'*')",(tenant,)).fetchone()
        return not row["off"]

    def set_serving(self, tenant:str, enabled:bool):
        with self.db.tx() as c:
            c.execute("INSERT INTO state(tenant,serving_disabled) VALUES(?,?) ON CONFLICT(tenant) DO UPDATE SET serving_disabled=excluded.serving_disabled",(tenant,0 if enabled else 1))
            self.db.audit(tenant,"SERVING_SWITCH",{"enabled":enabled})

    # ---- serving ----------------------------------------------------------

    def _admit(self, items, source, req, pol, allow, seen, reasons, rejections) -> int:
        dropped=0
        batch=set()
        for candidate in items:
            if source=="fallback" and candidate.item_id in seen and candidate.item_id not in batch:
                continue  # already offered as a primary candidate; not a rejection
            reason=self._check(candidate,req,pol)
            if reason is None and candidate.item_id in seen:
                reason="DUPLICATE_ITEM"
            if reason:
                reasons[reason]+=1;dropped+=1
                rejections.append(Rejection(item_id=candidate.item_id,reason=reason,source=source))
            else:
                allow.append(candidate);seen.add(candidate.item_id);batch.add(candidate.item_id)
        return dropped

    def evaluate(self,req:Request)->Decision:
        # One transaction: kill switch, policy, strategy and the logged decision are consistent.
        with self.db.tx() as c:
            enabled=self.serving_enabled(req.tenant_id)
            pol=self._policy(req.tenant_id,req.purpose) if enabled else None
            reasons=Counter(); rejections=[]
            allow=[]; seen=set(); output=[]; repaired=False
            strategy,prob="none",1.0
            all_count=len(req.candidates)+len(req.fallback_candidates)
            if not enabled:reasons["SERVING_DISABLED"]+=1
            if pol:
                cap=min(req.k,pol.max_results)
                repaired=self._admit(req.candidates,"candidates",req,pol,allow,seen,reasons,rejections)>0
                if pol.min_results>cap:
                    reasons["IMPOSSIBLE_RESULT_MINIMUM"]+=1
                elif allow or req.fallback_candidates:
                    # Fallback-only output is base-ranked; never credit it to a bandit arm.
                    strategy,prob=self._strategy(req,pol) if allow else ("base",1.0)
                    if strategy not in self.STRATEGIES:
                        reasons["ACTIVE_STRATEGY_UNAVAILABLE"]+=1;strategy,prob="base",1.0
                    repaired|=self._fill(output,self._order(allow,strategy,reasons) if allow else [],cap,pol.max_per_category,
                                         reasons,rejections,"candidates")>0
                    if len(output)<cap and req.fallback_candidates:
                        backup=[]
                        self._admit(req.fallback_candidates,"fallback",req,pol,backup,seen,reasons,rejections)
                        before=len(output)
                        self._fill(output,self._rank(backup,"base",len(backup)),cap,pol.max_per_category,reasons,rejections,"fallback")
                        repaired|=len(output)>before
                    if len(output)<pol.min_results:output=[]
            elif enabled:
                reasons["NO_APPLICABLE_POLICY"]+=1
            if not output:
                status=DecisionState.BLOCKED;strategy,prob="none",1.0
                reasons["INSUFFICIENT_ELIGIBLE_ITEMS"]+=1
            else:
                # Truncating to k or reordering is normal ranking, not a repair.
                status=DecisionState.REPAIRED if repaired else DecisionState.PASS
            did=secrets.token_hex(16)
            exp=int(time.time())+self.receipt_ttl
            fp=pol.fingerprint if pol else "SERVING_DISABLED" if not enabled else "NO_POLICY"
            oh=self._hash_results(output)
            sig=self._signature(req.tenant_id,did,oh,exp,fp)
            codes=sorted(reasons)
            c.execute("""INSERT INTO decisions(id,tenant,request_id,purpose,segment,strategy,propensity,policy_hash,status,output_hash,receipt,exp,at,candidate_count,eligible_count,reasons)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(did,req.tenant_id,req.request_id,req.purpose,req.segment,strategy,prob,fp,status.value,oh,sig,exp,time.time(),all_count,len(seen),canon(codes)))
            self.db.audit(req.tenant_id,"DECISION",{"decision_id":did,"request_id":req.request_id,"status":status.value,"policy_fingerprint":fp,"reason_codes":codes,"strategy":strategy,"candidate_count":all_count,"eligible_count":len(seen),"result_count":len(output)})
        return Decision(decision_id=did,request_id=req.request_id,tenant_id=req.tenant_id,status=status,results=output,
                        strategy=strategy,propensity=prob,policy_fingerprint=fp,reason_codes=codes,receipt=sig,expires_at=exp,
                        rejections=rejections)

    def evaluate_many(self, requests:list[Request]) -> list[Decision]:
        return [self.evaluate(r) for r in requests]

    def verify(self,tenant:str,did:str,receipt:str,results:list[Candidate])->bool:
        if not isinstance(receipt,str) or not HEX64.match(receipt):return False
        with self.db.tx() as c:
            row=c.execute("SELECT * FROM decisions WHERE id=? AND tenant=?",(did,tenant)).fetchone()
            if not row or row["status"]=="BLOCKED" or row["exp"]<time.time():return False
            if not self.serving_enabled(tenant):return False
            current=self._policy(tenant,row["purpose"])
        if current is None or current.fingerprint != row["policy_hash"]:return False
        if len(results)!=len({x.item_id for x in results}):return False
        if any(x.tenant_id!=tenant for x in results):return False
        item_hash=self._hash_results(results)
        sig=self._signature(tenant,did,item_hash,row["exp"],row["policy_hash"])
        return hmac.compare_digest(sig,receipt) and hmac.compare_digest(sig,row["receipt"]) and item_hash==row["output_hash"]

    def presented(self,tenant:str,did:str,receipt:str,results:list[Candidate]):
        with self.db.tx() as c:
            if not self.verify(tenant,did,receipt,results):raise Denied("RECEIPT_MISMATCH_OR_EXPIRED")
            if c.execute("INSERT OR IGNORE INTO presentations(decision_id,tenant,at) VALUES(?,?,?)",(did,tenant,time.time())).rowcount:
                self.db.audit(tenant,"PRESENTED",{"decision_id":did,"item_count":len(results)})

    def event(self,event:Telemetry):
        with self.db.tx() as c:
            if event.decision_id:
                dec=c.execute("SELECT tenant FROM decisions WHERE id=?",(event.decision_id,)).fetchone()
                if not dec or dec["tenant"]!=event.tenant_id:raise Denied("UNKNOWN_OR_CROSS_TENANT_DECISION")
            try:
                c.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?,?)",(event.event_id,event.tenant_id,event.decision_id,event.event_type.value,event.latency_ms,event.token_count,event.cost_usd,time.time()))
            except sqlite3.IntegrityError:
                raise Denied("DUPLICATE_EVENT")
            self.db.audit(event.tenant_id,"TELEMETRY",{"event_id":event.event_id,"kind":event.event_type.value,"decision_id":event.decision_id})

    def outcome(self,outcome:Outcome):
        with self.db.tx() as c:
            d=c.execute("""SELECT d.* FROM decisions d JOIN presentations p ON d.id=p.decision_id
                           WHERE d.id=? AND d.tenant=?""",(outcome.decision_id,outcome.tenant_id)).fetchone()
            if not d or d["status"]=="BLOCKED":raise Denied("NO_VERIFIED_PRESENTATION")
            try:
                c.execute("INSERT INTO outcomes VALUES(?,?,?,?,?,?)",(outcome.outcome_id,outcome.tenant_id,outcome.decision_id,outcome.reward,outcome.outcome_type.value,time.time()))
            except sqlite3.IntegrityError:
                raise Denied("DUPLICATE_OR_ALREADY_REWARDED")
            self.db.audit(outcome.tenant_id,"TRUSTED_OUTCOME",{"decision_id":outcome.decision_id,"outcome_id":outcome.outcome_id,"outcome_type":outcome.outcome_type.value})

    # ---- promotion --------------------------------------------------------

    def _promotion_evidence(self, tenant:str, strategy:str):
        if strategy not in self.STRATEGIES:
            return {"approved":False,"reason":"UNKNOWN_STRATEGY"}
        with self.db.tx() as c:
            cohorts=c.execute("""SELECT DISTINCT d.purpose,d.policy_hash FROM decisions d
                JOIN outcomes o ON o.decision_id=d.id JOIN presentations p ON p.decision_id=d.id
                WHERE d.tenant=? AND d.propensity<1""",(tenant,)).fetchall()
            if len(cohorts)>1:
                return {"approved":False,"reason":"MIXED_POLICY_OR_PURPOSE_COHORT"}
            if cohorts:
                current=self._policy(tenant,cohorts[0]["purpose"])
                if current is None or current.fingerprint!=cohorts[0]["policy_hash"]:
                    return {"approved":False,"reason":"POLICY_CHANGED_SINCE_EXPERIMENT"}
                if not current.experiment or current.high_impact:
                    return {"approved":False,"reason":"CURRENT_POLICY_DISALLOWS_EXPERIMENT"}
            return learning.evaluate_promotion(c,tenant,strategy,arms=self.STRATEGIES)

    def assess_challenger(self,tenant:str,strategy:str):
        return self._promotion_evidence(tenant,strategy)

    def promote(self,tenant:str,strategy:str):
        with self.db.tx() as c:
            verdict=self._promotion_evidence(tenant,strategy)
            if not verdict.get("approved"):
                raise Denied(f"PROMOTION_DENIED:{verdict.get('reason')}")
            c.execute("INSERT INTO state(tenant,active_strategy,mode) VALUES(?,?,'ACTIVE') ON CONFLICT(tenant) DO UPDATE SET active_strategy=excluded.active_strategy,mode='ACTIVE'",(tenant,strategy))
            self.db.audit(tenant,"STRATEGY_PROMOTED",{"strategy":strategy,"evidence":verdict})
            return verdict

    def rollback(self,tenant:str):
        with self.db.tx() as c:
            c.execute("INSERT INTO state(tenant,active_strategy,mode) VALUES(?,'base','OFF') ON CONFLICT(tenant) DO UPDATE SET active_strategy='base',mode='OFF'",(tenant,))
            self.db.audit(tenant,"ROLLED_BACK",{"strategy":"base"})

    # ---- operations -------------------------------------------------------

    def purge(self, tenant:str, older_than_seconds:int) -> dict:
        if older_than_seconds<3600:raise Denied("RETENTION_WINDOW_TOO_SHORT")
        return self.db.purge(tenant,time.time()-older_than_seconds)

    def metrics(self,tenant:str,include_audit:bool=True)->dict:
        """Aggregated in SQL; `include_audit=False` skips the O(chain) audit verification."""
        with self.db.tx() as c:
            one=lambda q:c.execute(q,(tenant,)).fetchone()
            group=lambda q:{r[0]:r[1] for r in c.execute(q,(tenant,)).fetchall()}
            d=one("SELECT COUNT(*) n,SUM(eligible_count) e,SUM(candidate_count) cand FROM decisions WHERE tenant=?")
            statuses=group("SELECT status,COUNT(*) FROM decisions WHERE tenant=? GROUP BY status")
            strategies=group("SELECT strategy,COUNT(*) FROM decisions WHERE tenant=? GROUP BY strategy")
            reasons=group("SELECT j.value,COUNT(*) FROM decisions d,json_each(d.reasons) j WHERE d.tenant=? GROUP BY j.value")
            o=one("SELECT COUNT(*) n,AVG(reward) mean,SUM(kind='CONVERSION' AND reward>0) conv FROM outcomes WHERE tenant=?")
            presented=one("SELECT COUNT(*) n FROM presentations WHERE tenant=?")["n"]
            clicked=one("""SELECT COUNT(DISTINCT e.decision_id) n FROM events e JOIN presentations p
                           ON p.decision_id=e.decision_id WHERE e.tenant=? AND e.kind='CLICK'""")["n"]
            ev=one("SELECT COALESCE(SUM(cost_usd),0) cost,COALESCE(SUM(token_count),0) tokens FROM events WHERE tenant=?")
            event_kinds=group("SELECT kind,COUNT(*) FROM events WHERE tenant=? GROUP BY kind")
            lat=[r[0] for r in c.execute("SELECT latency_ms FROM events WHERE tenant=? AND latency_ms IS NOT NULL ORDER BY latency_ms",(tenant,))]
            reward_by_strategy={r[0]:{"sample_size":r[1],"observed_mean":round(r[2],4)} for r in c.execute(
                """SELECT d.strategy,COUNT(*),AVG(o.reward) FROM decisions d JOIN outcomes o ON o.decision_id=d.id
                   WHERE d.tenant=? GROUP BY d.strategy ORDER BY d.strategy""",(tenant,))}
        n=d["n"]; converted=o["conv"] or 0; costs=float(ev["cost"])
        return {"tenant_id":tenant,"decisions":n,"statuses":statuses,"strategies":strategies,
                "block_rate":round(statuses.get("BLOCKED",0)/n,4) if n else None,
                "repair_rate":round(statuses.get("REPAIRED",0)/n,4) if n else None,
                "eligibility_rate":round(d["e"]/d["cand"],4) if d["cand"] else None,
                "verified_presentations":presented,"outcomes":o["n"],
                "mean_reward":round(o["mean"],4) if o["n"] else None,
                "conversion_per_presented_decision":round(converted/presented,4) if presented else None,
                "observed_ctr":round(clicked/presented,4) if presented else None,
                "latency_ms_p50":lat[int((len(lat)-1)*0.50)] if lat else None,
                "latency_ms_p95":lat[int((len(lat)-1)*0.95)] if lat else None,
                "cost_usd_logged":round(costs,6),"token_count_logged":int(ev["tokens"]),
                "reason_counts":reasons,"reward_by_strategy":reward_by_strategy,
                "audit_chain_valid":self.db.audit_verify(tenant)["valid"] if include_audit else None,
                "cost_per_observed_conversion":round(costs/converted,6) if converted else None,
                "event_counts":event_kinds,
                "caveats":["CTR and conversion are observed rates; not causal lift without randomized evaluation.",
                           "Only trusted outcome events train the learner; telemetry never trains it.",
                           "Outcomes are potentially delayed or missing; reward metrics are not exposure-adjusted."]}
