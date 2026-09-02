"""
dna_engine.py
--------------
Generates a 32-character "Threat DNA" string for each attacking IP,
encoded from 8 independent behavioral dimensions (4 hex chars each).

The DNA visualization in the UI renders this as a 32-cell color barcode:
each group of 4 cells shares a hue (one hue per dimension), with
brightness encoding the value within that dimension. The result is a
visual fingerprint that is:

  - UNIQUE per attacker: two IPs with different attack profiles get
    visually distinct barcodes immediately.
  - CONSISTENT for the same methodology: two IPs from the same botnet
    using the same credential list, timing pattern, and path strategy
    will produce similar (not necessarily identical) DNA strips.
  - ADAPTIVE: the DNA updates live as new events arrive, so you can
    watch a profile's barcode evolve from sparse to dense as an attack
    escalates.

The 8 dimensions:
  D0 (cells 0-3,  green)    Frequency       Request rate in the rolling window
  D1 (cells 4-7,  red)      Credentials     Credential-stuffing aggressiveness
  D2 (cells 8-11, blue)     Path diversity  Breadth of scanning coverage
  D3 (cells 12-15,orange)   Signatures      Known attack-pattern density
  D4 (cells 16-19,purple)   Services        HTTP-only / SSH-only / mixed
  D5 (cells 20-23,cyan)     Path identity   Which specific bait paths were hit
  D6 (cells 24-27,amber)    Persistence     Total event volume (size of attack)
  D7 (cells 28-31,magenta)  Automation      Regularity of timing (bot vs. human)

This concept is inspired by how malware analysts generate visual hashes
(imphash, ssdeep, tlsh) to spot related samples — applied here to live
behavioral telemetry instead of static binary structure.
"""

from __future__ import annotations
import hashlib
import statistics


# 8 hue triples (R, G, B) for each behavioral dimension at full brightness.
_HUES = [
    (0, 255, 65),     # D0 green  - frequency
    (255, 50, 50),    # D1 red    - credentials
    (50, 110, 255),   # D2 blue   - path diversity
    (255, 160, 0),    # D3 orange - signatures
    (160, 50, 255),   # D4 purple - services
    (0, 220, 220),    # D5 cyan   - path identity
    (255, 185, 0),    # D6 amber  - persistence
    (255, 40, 160),   # D7 magenta- automation
]

_MIN_BRIGHTNESS = 0.07   # dim cells are not invisible, just very dark


def _saturating(value: float, half_point: float) -> float:
    if half_point <= 0:
        return 1.0 if value > 0 else 0.0
    return value / (value + half_point)


def _automation_indicator(timestamps: list) -> float:
    """Low coefficient-of-variation in inter-arrival times => bot => high value."""
    if len(timestamps) < 4:
        return 0.0
    sorted_ts = sorted(timestamps)
    intervals = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]
    mean_i = sum(intervals) / len(intervals)
    if mean_i < 0.001:
        return 1.0
    std_i = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
    cv = std_i / mean_i
    return max(0.0, 1.0 - min(cv, 2.0) / 2.0)


def profile_to_dna(profile) -> str:
    """
    Returns a 32-character uppercase hex DNA string derived from the
    ThreatProfile's current behavioral state.
    """
    def _encode(value_0_1: float) -> str:
        v = max(0.0, min(value_0_1, 1.0))
        return f"{int(v * 0xFFFF):04X}"

    # D0: frequency
    d0 = _encode(profile.frequency_score())

    # D1: credentials
    d1 = _encode(profile.credential_score())

    # D2: path+service diversity
    d2 = _encode(profile.diversity_score())

    # D3: signature match strength
    d3 = _encode(profile.signature_score())

    # D4: service mix identity (hash-derived, stable for same mix)
    svc_str = ",".join(sorted(profile.services_seen)) if profile.services_seen else "none"
    svc_hash = int(hashlib.sha256(svc_str.encode()).hexdigest()[:4], 16) / 0xFFFF
    d4 = _encode(svc_hash)

    # D5: path pattern identity (which bait paths hit)
    top_paths = sorted(list(profile.paths_seen))[:6]
    path_str = ",".join(top_paths) if top_paths else "none"
    path_hash = int(hashlib.sha256(path_str.encode()).hexdigest()[:4], 16) / 0xFFFF
    d5 = _encode(path_hash)

    # D6: persistence (total events ever)
    d6 = _encode(_saturating(profile.total_events, 30.0))

    # D7: automation indicator
    d7 = _encode(_automation_indicator(profile.event_timestamps))

    return d0 + d1 + d2 + d3 + d4 + d5 + d6 + d7


def dna_cell_color(dna_string: str, cell_index: int) -> str:
    """
    Maps a single DNA cell (0..31) to a hex color string, using the
    dimension hue and cell value as brightness.
    """
    if cell_index >= len(dna_string):
        return "#0A0A0A"
    hex_char = dna_string[cell_index]
    value = int(hex_char, 16) / 15.0
    dimension = cell_index // 4
    r_b, g_b, b_b = _HUES[dimension]
    brightness = _MIN_BRIGHTNESS + (1.0 - _MIN_BRIGHTNESS) * value
    r = min(255, int(r_b * brightness))
    g = min(255, int(g_b * brightness))
    b = min(255, int(b_b * brightness))
    return f"#{r:02X}{g:02X}{b:02X}"


def dna_dimension_label(dimension_index: int) -> str:
    labels = [
        "FREQ", "CRED", "PATH", "SIG.",
        "SVC.", "PATT", "PERS", "AUTO",
    ]
    return labels[dimension_index] if dimension_index < 8 else "????"


DNA_HUES = _HUES  # exported for radar blip coloring
