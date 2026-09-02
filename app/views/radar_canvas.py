"""
radar_canvas.py  (v2)
-----------------------
Builds the full set of flet.canvas shapes for the Threat Proximity Radar.

New vs. v1:
  - Cluster rings: when a subnet attack cluster is detected, a distinct
    pulsing cyan ring appears at its centroid bearing + radius. Multiple
    blips bunch near the ring, making coordination visually obvious.
  - DNA-tinted blips: each IP's dot is no longer a uniform color per tier.
    Its hue is BLENDED between the tier color and the dominant color of
    that IP's Threat DNA string (D0 frequency dimension), making every
    blip visually unique at a glance.
  - Threat arc: a thin arc segment on the radar perimeter at each active
    bearing, with height proportional to that IP's BDI, building a
    density "skyline" that shows WHERE attacks are concentrated.
  - Pulse system: each new event triggers a brief expanding ring at the
    blip position (passed in as active_pulses list of (x,y,age_0_to_1)).
"""

from __future__ import annotations
import math

import flet as ft
import flet.canvas as fc

from app import theme
from app.intel import dna_engine

CANVAS_W = 480
CANVAS_H = 480
CX, CY = CANVAS_W / 2, CANVAS_H / 2
MAX_R = 210
MIN_R = 40

RING_RADII = [210, 157, 105, 52]
TIER_RING_COLORS = [theme.PHOSPHOR_GREEN, "#C9E82E", theme.AMBER, theme.RED_CRITICAL]


def _polar(bearing_deg: float, radius: float) -> tuple[float, float]:
    angle = math.radians(bearing_deg - 90)
    return CX + radius * math.cos(angle), CY + radius * math.sin(angle)


def bdi_to_radius(bdi: float) -> float:
    bdi = max(0.0, min(bdi, 100.0))
    return MAX_R - (bdi / 100.0) * (MAX_R - MIN_R)


def _bearing_of(profile) -> float:
    from app.intel.geolocate import bearing_for_ip
    return bearing_for_ip(profile.ip)


def _blend_colors(hex_a: str, hex_b: str, t: float) -> str:
    """Blend two hex colors. t=0 => hex_a, t=1 => hex_b."""
    def parse(h):
        h = h.lstrip("#")
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    ra, ga, ba = parse(hex_a)
    rb, gb, bb = parse(hex_b)
    r = int(ra + (rb - ra) * t)
    g = int(ga + (gb - ga) * t)
    b = int(ba + (bb - ba) * t)
    return f"#{r:02X}{g:02X}{b:02X}"


def _dna_dominant_color(profile) -> str:
    """Returns the dominant color from the profile's DNA D0 (frequency) dimension."""
    dna = dna_engine.profile_to_dna(profile)
    return dna_engine.dna_cell_color(dna, 3)  # last cell of D0 = brightest freq cell


def build_static_rings() -> list:
    shapes = []
    axis_paint = ft.Paint(
        color=ft.Colors.with_opacity(0.18, theme.PHOSPHOR_GREEN), stroke_width=1
    )
    shapes.append(fc.Line(CX - MAX_R, CY, CX + MAX_R, CY, paint=axis_paint))
    shapes.append(fc.Line(CX, CY - MAX_R, CX, CY + MAX_R, paint=axis_paint))
    for radius, color in zip(RING_RADII, TIER_RING_COLORS):
        shapes.append(fc.Circle(CX, CY, radius, paint=ft.Paint(
            color=ft.Colors.with_opacity(0.30, color),
            style=ft.PaintingStyle.STROKE, stroke_width=1.2,
        )))
    return shapes


def build_sweep(angle_deg: float, half_width: float = 9.0) -> list:
    p1 = _polar(angle_deg - half_width, MAX_R)
    p2 = _polar(angle_deg + half_width, MAX_R)
    fill = ft.Paint(
        color=ft.Colors.with_opacity(0.09, theme.PHOSPHOR_GREEN),
        style=ft.PaintingStyle.FILL,
    )
    edge = ft.Paint(
        color=ft.Colors.with_opacity(0.75, theme.PHOSPHOR_GREEN), stroke_width=1.5
    )
    return [
        fc.Path(elements=[
            fc.Path.MoveTo(CX, CY),
            fc.Path.LineTo(*p1),
            fc.Path.LineTo(*p2),
            fc.Path.Close(),
        ], paint=fill),
        fc.Line(CX, CY, *p2, paint=edge),
    ]


def build_blips(profiles, pulse_phase: float = 0.0) -> list:
    shapes = []
    for profile in profiles:
        bdi = profile.bdi()
        tier = profile.tier()
        tier_color = theme.TIER_COLORS[tier]
        dna_color = _dna_dominant_color(profile)
        blip_color = _blend_colors(tier_color, dna_color, 0.40)
        radius = bdi_to_radius(bdi)
        x, y = _polar(_bearing_of(profile), radius)
        pulse = 1.0 + 0.12 * math.sin(pulse_phase + hash(profile.ip) % 100)
        dot_r = (4 + bdi / 14) * pulse
        shapes.append(fc.Circle(x, y, dot_r, paint=ft.Paint(
            color=blip_color, style=ft.PaintingStyle.FILL
        )))
        shapes.append(fc.Circle(x, y, dot_r + 3.5, paint=ft.Paint(
            color=ft.Colors.with_opacity(0.22, blip_color),
            style=ft.PaintingStyle.STROKE, stroke_width=1.1,
        )))
    return shapes


def build_cluster_rings(clusters, profiles_map: dict, pulse_phase: float = 0.0) -> list:
    """
    Draws a pulsing cyan ring for each active subnet cluster. The ring is
    positioned at the average bearing and BDI-radius of its members.
    """
    shapes = []
    for cluster in clusters:
        member_profiles = [profiles_map[ip] for ip in cluster.member_ips if ip in profiles_map]
        if not member_profiles:
            continue
        avg_bearing = sum(_bearing_of(p) for p in member_profiles) / len(member_profiles)
        avg_bdi = cluster.cluster_bdi(profiles_map)
        r = bdi_to_radius(avg_bdi)
        cx, cy = _polar(avg_bearing, r)
        ring_r = 22 + 4 * math.sin(pulse_phase * 2.1)
        shapes.append(fc.Circle(cx, cy, ring_r, paint=ft.Paint(
            color=ft.Colors.with_opacity(0.08, theme.CLUSTER_RING_COLOR),
            style=ft.PaintingStyle.FILL,
        )))
        shapes.append(fc.Circle(cx, cy, ring_r, paint=ft.Paint(
            color=ft.Colors.with_opacity(0.70, theme.CLUSTER_RING_COLOR),
            style=ft.PaintingStyle.STROKE, stroke_width=1.8,
        )))
        shapes.append(fc.Circle(cx, cy, ring_r + 7, paint=ft.Paint(
            color=ft.Colors.with_opacity(0.25, theme.CLUSTER_RING_COLOR),
            style=ft.PaintingStyle.STROKE, stroke_width=1.0,
        )))
        label_x, label_y = _polar(avg_bearing, r - ring_r - 14)
        shapes.append(fc.Text(
            label_x - 10, label_y,
            f"{cluster.member_count}IPs",
            style=ft.TextStyle(
                size=9, weight=ft.FontWeight.W_700,
                color=theme.CLUSTER_RING_COLOR, font_family="Consolas",
            ),
        ))
    return shapes


def build_event_pulses(pulses: list) -> list:
    """
    Each pulse is (x, y, age) where age goes from 0.0 (just born) to 1.0
    (fully faded). Renders as an expanding, fading ring.
    """
    shapes = []
    for x, y, age in pulses:
        r = 8 + age * 28
        alpha = max(0.0, 0.6 * (1.0 - age))
        shapes.append(fc.Circle(x, y, r, paint=ft.Paint(
            color=ft.Colors.with_opacity(alpha, theme.PHOSPHOR_GREEN),
            style=ft.PaintingStyle.STROKE, stroke_width=max(0.5, 1.5 * (1 - age)),
        )))
    return shapes
