"""geolocate.py — IP to radar bearing. Unchanged from v1."""
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
    digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()
    return (int(digest[:8], 16) % 3600) / 10.0


def live_bearing(ip: str, timeout: float = 1.5) -> float | None:
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
    bearing = live_bearing(ip) if use_live else None
    if bearing is None:
        bearing = offline_bearing(ip)
    _cache[ip] = bearing
    return bearing
