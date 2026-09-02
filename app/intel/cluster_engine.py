"""
cluster_engine.py
------------------
Detects COORDINATED attacks: groups of distinct IPs from the same /24
subnet that generate events within a rolling 10-minute window.

Why this matters: a single aggressive IP scores high on BDI immediately.
But sophisticated botnets spread load across dozens of IPs (each staying
just below noise thresholds) specifically to evade per-IP scoring. This
engine catches that pattern by looking at subnet-level coordination.

When 3+ distinct IPs from the same /24 are active within 10 minutes, a
ClusterThreat is declared. Its combined danger score adds a coordination
bonus on top of the average member BDI — because coordinated attacks are
harder to stop and represent a deliberate, organized adversary.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.intel.scoring import ThreatProfile

CLUSTER_WINDOW_SECONDS = 600    # 10-minute rolling window
CLUSTER_MIN_MEMBERS = 3         # Minimum distinct IPs to declare a cluster
COORDINATION_BONUS = 0.15       # Added to cluster BDI per extra member above minimum


def subnet_24(ip: str) -> str:
    """Returns the /24 subnet prefix for an IP (first 3 octets)."""
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3])
    return ip


def _is_public(ip: str) -> bool:
    try:
        parts = list(map(int, ip.split(".")))
        if parts[0] in (10, 127, 172, 192):
            return False
        return True
    except Exception:
        return True


@dataclass
class ClusterThreat:
    """Represents a detected coordinated subnet-level attack."""
    subnet: str
    member_ips: set = field(default_factory=set)
    last_event_time: float = field(default_factory=time.time)
    event_count: int = 0

    @property
    def member_count(self) -> int:
        return len(self.member_ips)

    def cluster_bdi(self, profiles: dict) -> float:
        """
        Combined danger score: average BDI of members plus a coordination
        bonus scaled by how many IPs are cooperating.
        """
        member_scores = [
            profiles[ip].bdi()
            for ip in self.member_ips
            if ip in profiles
        ]
        if not member_scores:
            return 0.0
        avg_bdi = sum(member_scores) / len(member_scores)
        bonus = COORDINATION_BONUS * max(0, self.member_count - CLUSTER_MIN_MEMBERS)
        return min(100.0, avg_bdi * (1.0 + bonus))

    def tier(self, profiles: dict) -> str:
        b = self.cluster_bdi(profiles)
        if b >= 85:
            return "CRITICAL"
        if b >= 60:
            return "HIGH"
        if b >= 30:
            return "MEDIUM"
        return "LOW"


class ClusterEngine:
    """Tracks subnet-level attack coordination in real time."""

    def __init__(self):
        self._subnet_events: dict[str, list[tuple[str, float]]] = {}
        self._clusters: dict[str, ClusterThreat] = {}

    def register_event(self, ip: str):
        now = time.time()
        subnet = subnet_24(ip)
        if subnet not in self._subnet_events:
            self._subnet_events[subnet] = []
        self._subnet_events[subnet].append((ip, now))
        self._prune(subnet, now)
        self._evaluate_cluster(subnet, now)

    def _prune(self, subnet: str, now: float):
        cutoff = now - CLUSTER_WINDOW_SECONDS
        self._subnet_events[subnet] = [
            (ip, ts) for ip, ts in self._subnet_events[subnet] if ts >= cutoff
        ]

    def _evaluate_cluster(self, subnet: str, now: float):
        events = self._subnet_events.get(subnet, [])
        distinct_ips = {ip for ip, _ in events}
        if len(distinct_ips) >= CLUSTER_MIN_MEMBERS:
            if subnet not in self._clusters:
                self._clusters[subnet] = ClusterThreat(subnet=subnet)
            cluster = self._clusters[subnet]
            cluster.member_ips = distinct_ips
            cluster.last_event_time = now
            cluster.event_count += 1
        elif subnet in self._clusters:
            del self._clusters[subnet]

    def active_clusters(self) -> list[ClusterThreat]:
        now = time.time()
        stale_cutoff = now - CLUSTER_WINDOW_SECONDS
        return [
            c for c in self._clusters.values()
            if c.last_event_time >= stale_cutoff
        ]

    def all_profiles_map(self, registry) -> dict:
        return {p.ip: p for p in registry.all_profiles()}
