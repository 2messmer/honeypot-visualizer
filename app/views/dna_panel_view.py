"""
dna_panel_view.py  (NEW in v2)
--------------------------------
Builds the "Threat DNA Gallery" canvas showing a 32-cell color barcode
for each of the top-5 attackers by BDI. The panel updates live as new
events arrive and refine each profile's behavioral fingerprint.

Reading the gallery:
  - Each row = one source IP
  - Each row has 32 colored cells grouped into 8 blocks of 4
  - Block colors use 8 distinct hues (one per behavioral dimension)
  - Cell brightness = value within that dimension (dim = near-zero, bright = high)
  - Two IPs with similar methodology produce visually similar DNA strips
  - A strip that is ALL dark = low activity (no threat)
  - A strip bright in blocks 0+3+7 = fast, signature-matching, automated bot
  - A strip bright in block 1 only = pure credential stuffer

The dimension legend is printed once at the bottom.
"""

from __future__ import annotations
import flet as ft
import flet.canvas as fc

from app import theme
from app.intel import dna_engine

CELL_W = 12
CELL_H = 26
GAP = 2
GROUP_GAP = 5          # extra gap between the 8 blocks of 4
LABEL_W = 70
CANVAS_H = 60          # per IP row
LEGEND_H = 28


def _row_shapes(profile, y_offset: float) -> list:
    shapes = []
    dna = dna_engine.profile_to_dna(profile)
    x = LABEL_W
    for i in range(32):
        color = dna_engine.dna_cell_color(dna, i)
        if i > 0 and i % 4 == 0:
            x += GROUP_GAP
        shapes.append(fc.Rect(
            x=x, y=y_offset + 6,
            width=CELL_W, height=CELL_H,
            border_radius=ft.border_radius.all(3),
            paint=ft.Paint(color=color, style=ft.PaintingStyle.FILL),
        ))
        x += CELL_W + GAP
    # IP label
    short_ip = ".".join(profile.ip.split(".")[-2:])
    tier_color = theme.TIER_COLORS[profile.tier()]
    shapes.append(fc.Text(
        2, y_offset + 8,
        f"{profile.bdi():.0f}",
        style=ft.TextStyle(
            size=12, weight=ft.FontWeight.W_800,
            color=tier_color, font_family="Consolas",
        ),
    ))
    shapes.append(fc.Text(
        2, y_offset + 24,
        f"*.{short_ip}",
        style=ft.TextStyle(size=9, color=theme.TEXT_MUTED, font_family="Consolas"),
    ))
    return shapes


def _legend_shapes(y_offset: float) -> list:
    shapes = []
    x = LABEL_W
    for dim in range(8):
        # Sample cell: mid-brightness
        sample_dna = "0000" * dim + "8888" + "0000" * (7 - dim)
        color = dna_engine.dna_cell_color(sample_dna, dim * 4 + 2)
        for i in range(4):
            if i > 0 or dim > 0:
                pass
            if dim > 0 and i == 0:
                x += GROUP_GAP
            shapes.append(fc.Rect(
                x=x, y=y_offset + 4,
                width=CELL_W, height=8,
                border_radius=ft.border_radius.all(2),
                paint=ft.Paint(color=color, style=ft.PaintingStyle.FILL),
            ))
            x += CELL_W + GAP
        shapes.append(fc.Text(
            LABEL_W + dim * (4 * (CELL_W + GAP) + GROUP_GAP) + 1,
            y_offset + 14,
            dna_engine.dna_dimension_label(dim),
            style=ft.TextStyle(size=7, color=theme.TEXT_MUTED, font_family="Consolas"),
        ))
    return shapes


def build_dna_canvas_shapes(profiles) -> tuple[list, float]:
    """
    Returns (shapes, total_height).
    profiles: top-5 ThreatProfiles by BDI.
    """
    shapes = []
    top5 = profiles[:5]
    for i, profile in enumerate(top5):
        y = i * (CELL_H + 18)
        shapes += _row_shapes(profile, y)
    total_h = len(top5) * (CELL_H + 18) + LEGEND_H + 8
    shapes += _legend_shapes(len(top5) * (CELL_H + 18))
    return shapes, max(total_h, 60)
