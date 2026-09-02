"""
timeline_view.py  (NEW in v2)
-------------------------------
Builds the canvas-based "Attack Timeline" panel.

Layout:
  - X axis: last WINDOW_SECONDS (5 min) from now, labeled every 60s
  - Y axis: top N source IPs sorted by BDI (one row each)
  - Each event: a colored circle at the right (time, ip-row) position
    colored by attack technique (SQL_INJECTION=red, PATH_TRAVERSAL=orange,
    CRED_STUFFING=green, SCANNER=cyan, other=grey)
  - Lines connect consecutive events from the same IP

Why this matters: the timeline exposes ESCALATION — an IP that starts
with a scan (cyan) then moves to SQLi (red) within minutes is following
a known kill-chain pattern. That progression is invisible in a radar dot
or a log list, but immediately obvious on a timeline.
"""

from __future__ import annotations
import time
import math

import flet as ft
import flet.canvas as fc

from app import theme

TIMELINE_W = 480
TIMELINE_H = 260
WINDOW_SECONDS = 300    # 5-minute window shown
MAX_IPS = 6             # IP rows visible
LEFT_MARGIN = 68        # space for IP labels on the left
BOTTOM_MARGIN = 24
ROW_H = (TIMELINE_H - BOTTOM_MARGIN) / MAX_IPS

TECHNIQUE_COLORS = {
    "SQL_INJECTION":   "#FF4136",
    "PATH_TRAVERSAL":  "#FF851B",
    "XSS":             "#FFDC00",
    "CMD_INJECTION":   "#FF4136",
    "FILE_DISCLOSURE": "#B10DC9",
    "RCE_ATTEMPT":     "#FF4136",
    "SCANNER":         "#7FDBFF",
    "CRED_STUFFING":   "#39FF7A",
}
_DEFAULT_COLOR = "#404A40"


def _technique_color(tags: set) -> str:
    if not tags:
        return _DEFAULT_COLOR
    priority = [
        "RCE_ATTEMPT", "CMD_INJECTION", "SQL_INJECTION",
        "FILE_DISCLOSURE", "PATH_TRAVERSAL", "XSS",
        "CRED_STUFFING", "SCANNER",
    ]
    for tag in priority:
        if tag in tags:
            return TECHNIQUE_COLORS[tag]
    return _DEFAULT_COLOR


def _time_to_x(event_ts: float, now: float) -> float:
    """Maps an event timestamp to an X pixel position."""
    elapsed = now - event_ts
    if elapsed > WINDOW_SECONDS:
        return LEFT_MARGIN
    frac = 1.0 - elapsed / WINDOW_SECONDS
    return LEFT_MARGIN + frac * (TIMELINE_W - LEFT_MARGIN - 4)


def _row_to_y(row_index: int) -> float:
    return (row_index + 0.5) * ROW_H


def build_timeline_shapes(profiles, all_events: list) -> list:
    """
    profiles: top N ThreatProfile objects (sorted by BDI desc)
    all_events: list of HoneypotEvent objects (most recent session)
    """
    shapes = []
    now = time.time()

    ip_to_row = {p.ip: i for i, p in enumerate(profiles[:MAX_IPS])}

    # Background grid
    axis_paint = ft.Paint(
        color=ft.Colors.with_opacity(0.12, theme.PHOSPHOR_GREEN), stroke_width=1,
    )
    for sec_offset in range(0, WINDOW_SECONDS + 1, 60):
        x = LEFT_MARGIN + (sec_offset / WINDOW_SECONDS) * (TIMELINE_W - LEFT_MARGIN - 4)
        shapes.append(fc.Line(x, 0, x, TIMELINE_H - BOTTOM_MARGIN, paint=axis_paint))

    # X axis labels (time markers)
    for sec_offset in range(0, WINDOW_SECONDS + 1, 60):
        x = LEFT_MARGIN + (sec_offset / WINDOW_SECONDS) * (TIMELINE_W - LEFT_MARGIN - 4)
        label = f"-{(WINDOW_SECONDS - sec_offset) // 60}m"
        if sec_offset == WINDOW_SECONDS:
            label = "now"
        shapes.append(fc.Text(
            x - 8, TIMELINE_H - BOTTOM_MARGIN + 4, label,
            style=ft.TextStyle(size=9, color=theme.TEXT_MUTED, font_family="Consolas"),
        ))

    # IP row labels
    for ip, row in ip_to_row.items():
        y = _row_to_y(row)
        short = ip.split(".")[-1]
        shapes.append(fc.Text(
            2, y - 6, f"...{short}",
            style=ft.TextStyle(size=9, color=theme.PHOSPHOR_GREEN, font_family="Consolas"),
        ))
        shapes.append(fc.Line(
            LEFT_MARGIN, y, TIMELINE_W - 4, y,
            paint=ft.Paint(
                color=ft.Colors.with_opacity(0.06, theme.PHOSPHOR_GREEN), stroke_width=1,
            ),
        ))

    # Filter events within the time window and for known IPs
    cutoff = now - WINDOW_SECONDS
    visible = [
        ev for ev in all_events
        if ev.timestamp >= cutoff and ev.ip in ip_to_row
    ]

    # Draw connections between consecutive events per IP
    from collections import defaultdict
    events_by_ip: dict[str, list] = defaultdict(list)
    for ev in sorted(visible, key=lambda e: e.timestamp):
        events_by_ip[ev.ip].append(ev)

    line_paint = ft.Paint(
        color=ft.Colors.with_opacity(0.15, theme.PHOSPHOR_GREEN), stroke_width=1
    )
    for ip, evs in events_by_ip.items():
        row = ip_to_row[ip]
        prev_x = None
        for ev in evs:
            ex = _time_to_x(ev.timestamp, now)
            ey = _row_to_y(row)
            if prev_x is not None:
                shapes.append(fc.Line(prev_x, ey, ex, ey, paint=line_paint))
            prev_x = ex

    # Draw event dots
    for ev in visible:
        row = ip_to_row[ev.ip]
        ex = _time_to_x(ev.timestamp, now)
        ey = _row_to_y(row)
        color = _technique_color(ev.technique_tags)
        shapes.append(fc.Circle(ex, ey, 4.5, paint=ft.Paint(
            color=color, style=ft.PaintingStyle.FILL
        )))
        shapes.append(fc.Circle(ex, ey, 6.5, paint=ft.Paint(
            color=ft.Colors.with_opacity(0.28, color),
            style=ft.PaintingStyle.STROKE, stroke_width=1.0,
        )))

    return shapes
