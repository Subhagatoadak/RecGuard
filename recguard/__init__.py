"""RecGuard: portable policy/learning kernel for recommendation systems."""
from .contracts import Candidate, Request, Policy, Decision, Outcome, Rejection, Telemetry
from .core import RecGuard, Denied
from .client import RecGuardClient, RecGuardError, guard_local, wrap_recommender

__version__ = "0.2.0"
__all__ = ["Candidate", "Request", "Policy", "Decision", "Outcome", "Rejection", "Telemetry", "RecGuard", "Denied",
           "RecGuardClient", "RecGuardError", "guard_local", "wrap_recommender"]
