"""RecGuard: portable policy/learning kernel for recommendation systems."""
from .contracts import Candidate, Request, Policy, Decision, Outcome, Rejection, Telemetry, review
from .core import RecGuard, Denied
from .client import RecGuardClient, RecGuardError, guard_local, wrap_recommender
from .policy_pack import PackError, PolicyPack, load_pack

__version__ = "0.2.0"
__all__ = ["Candidate", "Request", "Policy", "Decision", "Outcome", "Rejection", "Telemetry", "review", "RecGuard", "Denied",
           "RecGuardClient", "RecGuardError", "guard_local", "wrap_recommender",
           "PackError", "PolicyPack", "load_pack"]
