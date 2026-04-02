"""
Core prompt injection detection engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from .patterns import PATTERNS


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PatternMatch:
    """A single regex hit inside the analysed text."""

    category: str
    category_description: str
    severity: float
    explanation: str
    matched_text: str
    start: int
    end: int

    @property
    def risk_label(self) -> str:
        if self.severity >= 0.90:
            return "CRITICAL"
        if self.severity >= 0.75:
            return "HIGH"
        if self.severity >= 0.60:
            return "MEDIUM"
        return "LOW"


@dataclass
class AnalysisResult:
    """Full result returned by :func:`detect`."""

    input_text: str
    confidence: float
    risk_level: str
    matches: List[PatternMatch] = field(default_factory=list)
    categories_detected: List[str] = field(default_factory=list)
    summary: str = ""

    # Convenience -------------------------------------------------------

    @property
    def is_suspicious(self) -> bool:
        return self.confidence >= 0.30

    @property
    def is_high_risk(self) -> bool:
        return self.confidence >= 0.65

    def to_dict(self) -> dict:
        return {
            "confidence": round(self.confidence, 4),
            "risk_level": self.risk_level,
            "is_suspicious": self.is_suspicious,
            "categories_detected": self.categories_detected,
            "summary": self.summary,
            "matches": [
                {
                    "category": m.category,
                    "category_description": m.category_description,
                    "severity": m.severity,
                    "risk_label": m.risk_label,
                    "explanation": m.explanation,
                    "matched_text": m.matched_text,
                    "position": {"start": m.start, "end": m.end},
                }
                for m in self.matches
            ],
        }


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _compute_confidence(matches: List[PatternMatch]) -> float:
    """
    Combine per-match severities into a single 0–1 confidence score.

    Strategy:
      1. Within each category take the highest severity, then add a small
         bonus (×0.15) for each additional match (diminishing returns).
      2. Across categories combine with a probabilistic OR:
             score = 1 − ∏(1 − category_score)
         so each new category pushes the total higher without ever exceeding 1.
    """
    if not matches:
        return 0.0

    # Group by category
    by_category: dict[str, List[float]] = {}
    for m in matches:
        by_category.setdefault(m.category, []).append(m.severity)

    category_scores: List[float] = []
    for severities in by_category.values():
        severities.sort(reverse=True)
        base = severities[0]
        bonus = sum(s * 0.15 for s in severities[1:])
        category_scores.append(min(1.0, base + bonus))

    # Probabilistic combination
    combined = 1.0
    for s in category_scores:
        combined *= 1.0 - s
    return round(1.0 - combined, 4)


def _risk_level(confidence: float) -> str:
    if confidence >= 0.80:
        return "CRITICAL"
    if confidence >= 0.60:
        return "HIGH"
    if confidence >= 0.35:
        return "MEDIUM"
    if confidence >= 0.10:
        return "LOW"
    return "NONE"


def _build_summary(result_confidence: float, matches: List[PatternMatch], categories: List[str]) -> str:
    if not matches:
        return "No prompt injection patterns detected."

    n = len(matches)
    c = len(categories)
    level = _risk_level(result_confidence)

    cat_str = ", ".join(categories)
    plural_m = "pattern" if n == 1 else "patterns"
    plural_c = "category" if c == 1 else "categories"

    base = (
        f"{level} risk — {n} injection {plural_m} detected across "
        f"{c} {plural_c} ({cat_str})."
    )

    if result_confidence >= 0.80:
        advice = " This input strongly resembles a prompt injection attack and should be rejected or sandboxed."
    elif result_confidence >= 0.60:
        advice = " This input is likely a prompt injection attempt; treat with high suspicion."
    elif result_confidence >= 0.35:
        advice = " This input contains suspicious patterns; manual review is recommended."
    else:
        advice = " Low-confidence signal; may be a false positive — review context."

    return base + advice


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect(text: str, custom_patterns: Optional[dict] = None) -> AnalysisResult:
    """
    Analyse *text* for prompt injection patterns.

    Parameters
    ----------
    text:
        The user-supplied string to analyse.
    custom_patterns:
        Optional dict with the same structure as :data:`patterns.PATTERNS`
        to extend or override built-in rules.

    Returns
    -------
    AnalysisResult
    """
    pattern_bank = dict(PATTERNS)
    if custom_patterns:
        pattern_bank.update(custom_patterns)

    matches: List[PatternMatch] = []
    text_lower = text  # we use re.IGNORECASE, so no need to lower

    for category, meta in pattern_bank.items():
        severity: float = meta["severity"]
        description: str = meta["description"]

        for raw_pattern, explanation in meta["patterns"]:
            try:
                compiled = re.compile(raw_pattern, re.IGNORECASE | re.DOTALL)
            except re.error:
                continue  # skip malformed custom patterns

            for match in compiled.finditer(text_lower):
                matches.append(
                    PatternMatch(
                        category=category,
                        category_description=description,
                        severity=severity,
                        explanation=explanation,
                        matched_text=match.group(0),
                        start=match.start(),
                        end=match.end(),
                    )
                )

    # De-duplicate: if two patterns matched the *exact same span*, keep highest severity
    matches = _deduplicate(matches)

    # Sort by position, then severity descending
    matches.sort(key=lambda m: (m.start, -m.severity))

    confidence = _compute_confidence(matches)
    risk_level = _risk_level(confidence)

    # Unique categories in detection order
    seen: set[str] = set()
    categories: List[str] = []
    for m in sorted(matches, key=lambda x: -x.severity):
        if m.category_description not in seen:
            seen.add(m.category_description)
            categories.append(m.category_description)

    summary = _build_summary(confidence, matches, categories)

    return AnalysisResult(
        input_text=text,
        confidence=confidence,
        risk_level=risk_level,
        matches=matches,
        categories_detected=categories,
        summary=summary,
    )


def _deduplicate(matches: List[PatternMatch]) -> List[PatternMatch]:
    """Remove overlapping matches keeping the highest-severity hit per span."""
    unique: dict[tuple[int, int], PatternMatch] = {}
    for m in matches:
        span = (m.start, m.end)
        if span not in unique or m.severity > unique[span].severity:
            unique[span] = m
    return list(unique.values())
