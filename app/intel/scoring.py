"""
scoring.py
-----------
The Behavioral Danger Index (BDI): a custom 0-100 score computed per
source IP from FOUR independent behavioral signals, instead of the usual
single-signal approaches (most honeypot dashboards just count hits).

    BDI = 100 * ( w_freq * frequency_score
                + w_div  * diversity_score
                + w_sig  * signature_score
                + w_cred * credential_stuffing_score )

- frequency_score   : how fast this IP is making requests (rate-based, saturating)
- diversity_score   : how many DIFFERENT paths/services it has probed
                      (recon/scanning behavior vs. one-off noise)
- signature_score   : average "known attack pattern" match strength (signatures.py)
- credential_score  : for SSH, how much its login attempts look like
                      credential-stuffing (many distinct pairs, common pairs)

Each sub-score is normalized to [0, 1] using a saturating curve so that a
handful of noisy requests never look as dangerous as sustained,
diverse, signature-matching, credential-stuffing behavior.

This weighting scheme is original to this project — there is no
"official" formula for this in the security literature. It is a
teaching heuristic, not a certified threat-scoring product.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import time

from app.intel import signatures

WEIGHTS = {
    "frequency": 0.25,
    "diversity": 0.25,
    "signature": 0.30,
    "credential": 0.20,
}

WINDOW_SECONDS = 300  # 5-minute rolling window for rate/diversity calculations


def _saturating(value: float, half_point: float) -> float:
    """Smooth 0->1 saturation curve: 0 at 0, 0.5 at `half_point`, approaches 1."""
    if half_point <= 0:
        return 1.0 if value > 0 else 0.0
    return value / (value + half_point)


@dataclass
class ThreatProfile:
    """Rolling behavioral profile for a single source IP."""
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

    def register_event(self, *, service: str, path: str = "", raw_text: str = "",
                        username: str = None, password: str = None):
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
        self._prune(now)

    def _prune(self, now: float):
        cutoff = now - WINDOW_SECONDS
        self.event_timestamps = [t for t in self.event_timestamps if t >= cutoff]

    # --- sub-scores -------------------------------------------------

    def frequency_score(self) -> float:
        rate_per_min = len(self.event_timestamps) / (WINDOW_SECONDS / 60)
        return _saturating(rate_per_min, half_point=4.0)  # 4 req/min => score 0.5

    def diversity_score(self) -> float:
        return _saturating(len(self.paths_seen) + len(self.services_seen), half_point=4.0)

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

    def bdi(self) -> float:
        """Final Behavioral Danger Index, 0-100."""
        score = (
            WEIGHTS["frequency"] * self.frequency_score()
            + WEIGHTS["diversity"] * self.diversity_score()
            + WEIGHTS["signature"] * self.signature_score()
            + WEIGHTS["credential"] * self.credential_score()
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
    """Keeps one ThreatProfile per source IP for the lifetime of the app."""

    def __init__(self):
        self._profiles: dict[str, ThreatProfile] = {}

    def get_or_create(self, ip: str) -> ThreatProfile:
        if ip not in self._profiles:
            self._profiles[ip] = ThreatProfile(ip=ip)
        return self._profiles[ip]

    def all_profiles(self) -> list[ThreatProfile]:
        return list(self._profiles.values())

    def top_offenders(self, limit: int = 10) -> list[ThreatProfile]:
        return sorted(self._profiles.values(), key=lambda p: p.bdi(), reverse=True)[:limit]
