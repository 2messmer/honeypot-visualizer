"""
radar_canvas.py
-----------------
Builds the list of flet.canvas shapes for the "Threat Proximity Radar".

Key design idea (the visual innovation of this project): distance from
center encodes DANGER (Behavioral Danger Index), not geography — the
more dangerous a source IP looks, the closer its blip sits to the
center, regardless of where it actually is on Earth. Bearing (angle)
comes from app.intel.geolocate so the display isn't arbitrary, but the
radial axis is a threat-proximity metaphor rather than a literal map.
"""

from __future__ import annotations
import math

import flet as ft
import flet.canvas as fc

from app import theme

CENTER = (240, 240)
MAX_RADIUS = 210
MIN_RADIUS = 40
RING_RADII = [210, 157, 105, 52]
RING_COLORS = [theme.PHOSPHOR_GREEN, "#C9E82E", theme.AMBER, theme.RED_CRITICAL]


def _polar_to_xy(bearing_deg: float, radius: float) -> tuple[float, float]:
    angle = math.radians(bearing_deg - 90)
    cx, cy = CENTER
    return cx + radius * math.cos(angle), cy + radius * math.sin(angle)


def bdi_to_radius(bdi: float) -> float:
    bdi = max(0.0, min(bdi, 100.0))
    return MAX_RADIUS - (bdi / 100.0) * (MAX_RADIUS - MIN_RADIUS)


def build_static_rings() -> list:
    """Concentric danger-tier rings + compass cross-hairs (drawn once, rarely change)."""
    shapes = []
    cx, cy = CENTER
    for radius, color in zip(RING_RADII, RING_COLORS):
        shapes.append(fc.Circle(cx, cy, radius, paint=ft.Paint(
            color=ft.Colors.with_opacity(0.35, color), style=ft.PaintingStyle.STROKE, stroke_width=1.4,
        )))
    axis_paint = ft.Paint(color=ft.Colors.with_opacity(0.18, theme.PHOSPHOR_GREEN), stroke_width=1)
    shapes.append(fc.Line(cx - MAX_RADIUS, cy, cx + MAX_RADIUS, cy, paint=axis_paint))
    shapes.append(fc.Line(cx, cy - MAX_RADIUS, cx, cy + MAX_RADIUS, paint=axis_paint))
    return shapes


def build_sweep(angle_deg: float, half_width_deg: float = 9.0) -> list:
    """The rotating radar beam, drawn as a translucent filled wedge."""
    cx, cy = CENTER
    p1 = _polar_to_xy(angle_deg - half_width_deg, MAX_RADIUS)
    p2 = _polar_to_xy(angle_deg + half_width_deg, MAX_RADIUS)
    wedge_paint = ft.Paint(color=ft.Colors.with_opacity(0.10, theme.PHOSPHOR_GREEN), style=ft.PaintingStyle.FILL)
    edge_paint = ft.Paint(color=ft.Colors.with_opacity(0.7, theme.PHOSPHOR_GREEN), stroke_width=1.6)
    wedge = fc.Path(
        elements=[
            fc.Path.MoveTo(cx, cy),
            fc.Path.LineTo(*p1),
            fc.Path.LineTo(*p2),
            fc.Path.Close(),
        ],
        paint=wedge_paint,
    )
    leading_edge = fc.Line(cx, cy, *p2, paint=edge_paint)
    return [wedge, leading_edge]


def build_blips(profiles, pulse_phase: float = 0.0) -> list:
    """One blip per threat profile, colored/sized by tier, with a gentle pulse."""
    shapes = []
    for profile in profiles:
        bdi = profile.bdi()
        tier = profile.tier()
        color = theme.TIER_COLORS[tier]
        radius = bdi_to_radius(bdi)
        x, y = _polar_to_xy(_bearing_of(profile), radius)
        pulse = 1.0 + 0.15 * math.sin(pulse_phase + hash(profile.ip) % 100)
        dot_r = (4 + bdi / 12) * pulse
        shapes.append(fc.Circle(x, y, dot_r, paint=ft.Paint(color=color, style=ft.PaintingStyle.FILL)))
        shapes.append(fc.Circle(x, y, dot_r + 3, paint=ft.Paint(
            color=ft.Colors.with_opacity(0.25, color), style=ft.PaintingStyle.STROKE, stroke_width=1.2,
        )))
    return shapes


def _bearing_of(profile) -> float:
    from app.intel.geolocate import bearing_for_ip
    return bearing_for_ip(profile.ip)
