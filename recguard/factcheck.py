"""Fact-check numeric claims in LLM-written prose against trusted facts.

The LLM returns its text plus structured claims, each quoting the exact span it rests on:

    {"subject": "youtube", "metric": "roi", "value": 4.55, "quote": "YouTube returns 4.55x"}

`check_text` verifies every claim (quote is verbatim in the text, the quote states the
value, the fact exists, the value matches within tolerance) and then requires that every
number in the text is covered by a verified claim's quote. Sentences with contradicted
or unsupported numbers are removed from `safe_text`. Pure function; no LLM calls.
"""
from __future__ import annotations
import hashlib, math, re
from typing import Any, Mapping
from pydantic import BaseModel, Field

NUMBER = re.compile(r"(?<![\w.])[-+]?(?:\d{1,3}(?:,\d{2,3})+|\d+)(?:\.\d+)?\s?%?")
SENTENCE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(₹$])")
CLAIMS_INSTRUCTION = (
    "Alongside your text, return `claims`: one entry for EVERY number you wrote, each with subject, metric, value "
    "(the number exactly as written, without units) and quote (the exact, verbatim span of your text that states it). "
    "Do not round differently in the text and the claim."
)


class Claim(BaseModel):
    subject: str = Field(max_length=200)
    metric: str = Field(max_length=200)
    value: float
    quote: str = Field(min_length=1, max_length=1000)


class ClaimVerdict(BaseModel):
    claim: Claim
    status: str        # VERIFIED | QUOTE_NOT_IN_TEXT | VALUE_NOT_IN_QUOTE | UNKNOWN_FACT | MISMATCH
    expected: Any = None


class SentenceVerdict(BaseModel):
    index: int
    text: str
    status: str        # VERIFIED | NO_NUMBERS | UNSUPPORTED_NUMBER | CONTRADICTED
    unsupported: list[str] = Field(default_factory=list)


class FactCheckReport(BaseModel):
    verdict: str       # PASS | FAIL
    claims: list[ClaimVerdict]
    sentences: list[SentenceVerdict]
    unsupported_numbers: list[str]
    safe_text: str     # only VERIFIED and NO_NUMBERS sentences

    @property
    def counts(self) -> dict:
        out: dict[str, int] = {}
        for c in self.claims:
            out[f"claim:{c.status}"] = out.get(f"claim:{c.status}", 0) + 1
        for s in self.sentences:
            out[f"sentence:{s.status}"] = out.get(f"sentence:{s.status}", 0) + 1
        return out


def _parse(token: str) -> tuple[float, int, bool]:
    """Number, decimals as written, and whether it was a percentage."""
    raw = token.strip()
    percent = raw.endswith("%")
    digits = raw.rstrip("%").strip().replace(",", "")
    decimals = len(digits.split(".")[1]) if "." in digits else 0
    return float(digits), decimals, percent


def _states(token: str, value: float) -> bool:
    """Does this written number state `value` (allowing for the rounding it was written with)?"""
    number, decimals, percent = _parse(token)
    half_unit = 0.5 * 10 ** -decimals + 1e-9
    return abs(number - value) <= half_unit or (percent and abs(number / 100 - value) <= half_unit / 100)


def _norm(text: str) -> str:
    return re.sub(r"[\s\-]+", "_", text.strip().lower())


def _lookup(facts: Mapping, subject: str, metric: str, aliases: Mapping[str, str]):
    subject_key = aliases.get(_norm(subject), _norm(subject))
    metric_key = aliases.get(_norm(metric), _norm(metric))
    row = facts.get(subject_key) if isinstance(facts, Mapping) else None
    if not isinstance(row, Mapping) or metric_key not in row:
        return None
    return row[metric_key]


def _spans(text: str, quote: str) -> list[tuple[int, int]]:
    out, start = [], 0
    while (i := text.find(quote, start)) != -1:
        out.append((i, i + len(quote)))
        start = i + 1
    return out


def check_text(text: str, claims: list[Claim | dict], facts: Mapping[str, Mapping[str, Any]], *,
               rel_tolerance: float = 0.05, abs_tolerance: float = 0.01, aliases: Mapping[str, str] | None = None,
               ignore: list[str] | None = None) -> FactCheckReport:
    """Verify claims against facts and require every number in `text` to be backed by a verified claim.

    `ignore` lists regexes for numbers that need no backing (e.g. r"^(19|20)\\d\\d$" for years).
    A claimed percentage may match a fact stored as a fraction (38% == 0.38).
    """
    aliases = {_norm(k): _norm(v) for k, v in (aliases or {}).items()}
    ignore_patterns = [re.compile(p) for p in (ignore or [])]
    verdicts, verified_spans, failed_spans = [], [], []
    for raw in claims:
        claim = raw if isinstance(raw, Claim) else Claim.model_validate(raw)
        spans = _spans(text, claim.quote)
        expected = None
        if not spans:
            status = "QUOTE_NOT_IN_TEXT"
        elif not any(_states(m.group(), claim.value) for m in NUMBER.finditer(claim.quote)):
            status = "VALUE_NOT_IN_QUOTE"
        else:
            expected = _lookup(facts, claim.subject, claim.metric, aliases)
            if not isinstance(expected, (int, float)) or isinstance(expected, bool) or not math.isfinite(expected):
                status, expected = "UNKNOWN_FACT", None
            else:
                tolerance = max(rel_tolerance * abs(expected), abs_tolerance)
                ok = abs(claim.value - expected) <= tolerance or abs(claim.value / 100 - expected) <= tolerance
                status = "VERIFIED" if ok else "MISMATCH"
        verdicts.append(ClaimVerdict(claim=claim, status=status, expected=expected))
        (verified_spans if status == "VERIFIED" else failed_spans).extend(spans)

    def covered(start, end, spans):
        return any(a <= start and end <= b for a, b in spans)

    sentences, unsupported_all, kept = [], [], []
    position = 0
    for index, sentence in enumerate(s for s in SENTENCE.split(text) if s.strip()):
        start = text.find(sentence, position)
        position = start + len(sentence)
        numbers = [(m.group().strip(), start + m.start(), start + m.end()) for m in NUMBER.finditer(sentence)]
        numbers = [n for n in numbers if not any(p.search(n[0].rstrip("%").strip()) for p in ignore_patterns)]
        contradicted = any(covered(a, b, failed_spans) and not covered(a, b, verified_spans) for _, a, b in numbers)
        unsupported = [n for n, a, b in numbers if not covered(a, b, verified_spans) and not covered(a, b, failed_spans)]
        if not numbers:
            status = "NO_NUMBERS"
        elif contradicted:
            status = "CONTRADICTED"
        elif unsupported:
            status = "UNSUPPORTED_NUMBER"
        else:
            status = "VERIFIED"
        sentences.append(SentenceVerdict(index=index, text=sentence, status=status, unsupported=unsupported))
        unsupported_all.extend(unsupported)
        if status in ("VERIFIED", "NO_NUMBERS"):
            kept.append(sentence)
    failed = any(v.status != "VERIFIED" for v in verdicts) or any(s.status in ("CONTRADICTED", "UNSUPPORTED_NUMBER") for s in sentences)
    return FactCheckReport(verdict="FAIL" if failed else "PASS", claims=verdicts, sentences=sentences,
                           unsupported_numbers=unsupported_all, safe_text=" ".join(kept))


def sentence_digest(sentence: str) -> str:
    return "sha256:" + hashlib.sha256(sentence.encode()).hexdigest()[:40]
