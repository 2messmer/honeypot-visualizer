"""theme.py — dark "radar console" visual identity."""

import flet as ft

BG_DARK = "#050B08"
BG_PANEL = "#0B1710"
BG_PANEL_ALT = "#10221A"
BORDER_SOFT = "#1E3A2A"

PHOSPHOR_GREEN = "#39FF7A"
AMBER = "#FFB020"
RED_CRITICAL = "#FF4136"
TEXT_PRIMARY = "#E7FFEF"
TEXT_MUTED = "#6FA084"

TIER_COLORS = {
    "LOW": PHOSPHOR_GREEN,
    "MEDIUM": "#C9E82E",
    "HIGH": AMBER,
    "CRITICAL": RED_CRITICAL,
}

HEADLINE_STYLE = ft.TextStyle(size=26, weight=ft.FontWeight.W_800, color=TEXT_PRIMARY, font_family="Consolas")
SUBHEAD_STYLE = ft.TextStyle(size=13, color=TEXT_MUTED)
MONO_LABEL_STYLE = ft.TextStyle(size=13, weight=ft.FontWeight.W_600, color=PHOSPHOR_GREEN, font_family="Consolas")


def app_background_gradient() -> ft.LinearGradient:
    return ft.LinearGradient(
        begin=ft.Alignment.TOP_LEFT, end=ft.Alignment.BOTTOM_RIGHT,
        colors=[BG_DARK, "#081410", BG_DARK],
    )


def panel(content: ft.Control, *, padding: int = 18, expand=None) -> ft.Container:
    return ft.Container(
        content=content, padding=padding, bgcolor=BG_PANEL,
        border=ft.Border.all(1, BORDER_SOFT), border_radius=ft.border_radius.all(12), expand=expand,
    )


def section_title(text: str, icon=None) -> ft.Row:
    controls = []
    if icon is not None:
        controls.append(ft.Icon(icon, color=PHOSPHOR_GREEN, size=18))
    controls.append(ft.Text(text, style=MONO_LABEL_STYLE))
    return ft.Row(controls, spacing=8)


def build_theme() -> ft.Theme:
    return ft.Theme(color_scheme_seed=PHOSPHOR_GREEN, use_material3=True)
