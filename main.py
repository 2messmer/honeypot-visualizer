"""
Honeypot Visualizer — decoy SSH/HTTP services + a custom Behavioral
Danger Index, displayed on a live "threat proximity" radar.

Run with:  python main.py
Requires:  flet==0.84.0, paramiko>=3 (see requirements.txt)

SAFETY: only run the real honeypot listeners on infrastructure you own
or are explicitly authorized to monitor. Use the built-in demo traffic
simulator if you just want to showcase the dashboard.
"""

import flet as ft

from app import theme
from app.views import dashboard_view


def main(page: ft.Page):
    page.title = "Honeypot Visualizer — Behavioral Danger Radar"
    page.theme_mode = ft.ThemeMode.DARK
    page.theme = theme.build_theme()
    page.decoration = ft.BoxDecoration(gradient=theme.app_background_gradient())
    page.padding = 0
    page.window.width = 1280
    page.window.height = 860
    page.window.min_width = 1000
    page.window.min_height = 700
    page.scroll = ft.ScrollMode.AUTO

    page.add(dashboard_view.build(page))


if __name__ == "__main__":
    ft.run(main)
