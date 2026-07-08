"""
geolocate.py
-------------
Provides an angular "bearing" (0-360 degrees) for a source IP, used to
place its blip around the Threat Proximity Radar.

Design choice (the visual innovation of this project): the radar does
NOT plot literal geographic position. Distance-from-center encodes the
Behavioral Danger Index (dangerous = close), not geographic distance —
so two attackers on opposite sides of the planet with the same score
sit on the same ring. Bearing (angle) is still derived from a real-world
signal so the display isn't arbitrary:

- OFFLINE MODE (default, no network calls): bearing is derived
  deterministically from a hash of the IP address. Same IP always lands
  on the same bearing, different IPs spread out around the dial. This
  works fully offline/instantly and is what the honeypot uses by default
  and what the attack simulator always uses.
- LIVE MODE (opt-in, requires internet): if enabled, a best-effort HTTP
  lookup against a public IP-geolocation API resolves real longitude,
  which is converted to bearing (-180..180 => 0..360). Any failure
  (no internet, rate limit, private/reserved IP) silently falls back
  to the offline hash-based bearing — the UI never breaks because of a
  network hiccup.
"""

from __future__ import annotations
import hashlib
import ipaddress
import json
import urllib.request

_cache: dict[str, float] = {}


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local)
    except ValueError:
        return False


def offline_bearing(ip: str) -> float:
    """Deterministic 0-360 degree bearing derived from a hash of the IP."""
    digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()
    return (int(digest[:8], 16) % 3600) / 10.0


def live_bearing(ip: str, timeout: float = 1.5) -> float | None:
    """
    Best-effort real bearing from IP geolocation. Returns None on any
    failure (offline, blocked, rate-limited, private IP) so the caller
    can fall back to `offline_bearing`.
    """
    if not is_public_ip(ip):
        return None
    try:
        url = f"http://ip-api.com/json/{ip}?fields=lon"
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        lon = data.get("lon")
        if lon is None:
            return None
        return (float(lon) + 180.0) % 360.0
    except Exception:
        return None


def bearing_for_ip(ip: str, use_live: bool = False) -> float:
    if ip in _cache:
        return _cache[ip]
    bearing = None
    if use_live:
        bearing = live_bearing(ip)
    if bearing is None:
        bearing = offline_bearing(ip)
    _cache[ip] = bearing
    return bearing
