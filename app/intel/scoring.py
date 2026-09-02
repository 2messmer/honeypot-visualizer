"""
scoring.py  (v2)
-----------------
Behavioral Danger Index v2: six independent sub-scores instead of four.

New additions vs. v1:
  - automation_score: regularity of inter-arrival timing (low CoV => bot)
  - persistence_score: historical event count from previous sessions
    (set externally by dashboard_view after a DB lookup)

Revised weights (must sum to 1.0):
  frequency   0.20
  diversity   0.20
  signature   0.25
  credential  0.18
  automation  0.10
  persistence 0.07

The two new dimensions deliberately get modest weights because they
require more data to be reliable (automation needs ≥4 timestamps,
persistence needs historical DB data). Their contribution grows naturally
as the attack matures.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import statistics
import time

from app.intel import signatures

WEIGHTS = {
    "frequency":   0.20,
    "diversity":   0.20,
    "signature":   0.25,
    "credential":  0.18,
    "automation":  0.10,
    "persistence": 0.07,
}

WINDOW_SECONDS = 300


def _saturating(value: float, half_point: float) -> float:
    if half_point <= 0:
        return 1.0 if value > 0 else 0.0
    return value / (value + half_point)


@dataclass
class ThreatProfile:
    ip: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    event_timestamps: list = field(default_factory=list)
    paths_seen: set = field(default_factory=set)
    services_seen: set = field(default_factory=set)
    signature_scores: list = field(default_factory=list)
    credential_pairs: set = field(default_factory=set)
    common_credential_hits: int = 0
    total_events: int = 0
    # Set by dashboard_view after a historical DB lookup:
    historical_events: int = 0
    # Cached attack technique tags (from payload dissector):
    technique_tags: set = field(default_factory=set)

    def register_event(self, *, service: str, path: str = "",
                        raw_text: str = "", username: str = None,
                        password: str = None, technique_tags: set = None):
        now = time.time()
        self.last_seen = now
        self.total_events += 1
        self.event_timestamps.append(now)
        self.services_seen.add(service)
        if path:
            self.paths_seen.add(path)
        if raw_text:
            self.signature_scores.append(signatures.suspicious_score(raw_text))
        if username is not None and password is not None:
            self.credential_pairs.add((username, password))
            if signatures.is_common_credential_pair(username, password):
                self.common_credential_hits += 1
        if technique_tags:
            self.technique_tags.update(technique_tags)
        self._prune(now)

    def _prune(self, now: float):
        cutoff = now - WINDOW_SECONDS
        self.event_timestamps = [t for t in self.event_timestamps if t >= cutoff]

    # --- sub-scores ---

    def frequency_score(self) -> float:
        rate_per_min = len(self.event_timestamps) / (WINDOW_SECONDS / 60)
        return _saturating(rate_per_min, half_point=4.0)

    def diversity_score(self) -> float:
        return _saturating(
            len(self.paths_seen) + len(self.services_seen), half_point=4.0
        )

    def signature_score(self) -> float:
        if not self.signature_scores:
            return 0.0
        return sum(self.signature_scores) / len(self.signature_scores)

    def credential_score(self) -> float:
        if not self.credential_pairs:
            return 0.0
        diversity = _saturating(len(self.credential_pairs), half_point=3.0)
        common_ratio = self.common_credential_hits / max(len(self.credential_pairs), 1)
        return min(1.0, 0.5 * diversity + 0.5 * common_ratio)

    def automation_score(self) -> float:
        """
        Coefficient of variation of inter-arrival times.
        Low CoV => very regular timing => likely automated => high score.
        """
        ts = sorted(self.event_timestamps)
        if len(ts) < 4:
            return 0.0
        intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
        mean_i = sum(intervals) / len(intervals)
        if mean_i < 0.001:
            return 1.0
        std_i = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        cv = std_i / mean_i
        return max(0.0, 1.0 - min(cv, 2.0) / 2.0)

    def persistence_score(self) -> float:
        """Based on historical events from previous sessions (loaded from DB)."""
        return _saturating(self.historical_events, half_point=20.0)

    def bdi(self) -> float:
        score = (
            WEIGHTS["frequency"]   * self.frequency_score()
            + WEIGHTS["diversity"] * self.diversity_score()
            + WEIGHTS["signature"] * self.signature_score()
            + WEIGHTS["credential"] * self.credential_score()
            + WEIGHTS["automation"] * self.automation_score()
            + WEIGHTS["persistence"] * self.persistence_score()
        )
        return round(min(score, 1.0) * 100, 1)

    def tier(self) -> str:
        b = self.bdi()
        if b >= 85:
            return "CRITICAL"
        if b >= 60:
            return "HIGH"
        if b >= 30:
            return "MEDIUM"
        return "LOW"


class ThreatRegistry:
    def __init__(self):
        self._profiles: dict[str, ThreatProfile] = {}

    def get_or_create(self, ip: str) -> ThreatProfile:
        if ip not in self._profiles:
            self._profiles[ip] = ThreatProfile(ip=ip)
        return self._profiles[ip]

    def all_profiles(self) -> list[ThreatProfile]:
        return list(self._profiles.values())

    def top_offenders(self, limit: int = 10) -> list[ThreatProfile]:
        return sorted(
            self._profiles.values(), key=lambda p: p.bdi(), reverse=True
        )[:limit]
