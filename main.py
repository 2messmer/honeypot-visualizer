"""
Honeypot Visualizer v2
BDI v2 | Threat DNA Fingerprinting | Subnet Cluster Detection | Attack Timeline

Run:  python main.py
Req:  flet==0.84.0  paramiko>=3.4
"""
import flet as ft
from app import theme
from app.views import dashboard_view


def main(page: ft.Page):
    page.title = "Honeypot Visualizer v2 | Threat DNA + Cluster Radar"
    page.theme_mode = ft.ThemeMode.DARK
    page.theme = theme.build_theme()
    page.decoration = ft.BoxDecoration(gradient=theme.app_background_gradient())
    page.padding = 0
    page.window.width = 1320
    page.window.height = 900
    page.window.min_width = 1050
    page.window.min_height = 720
    page.scroll = ft.ScrollMode.AUTO
    page.add(dashboard_view.build(page))


if __name__ == "__main__":
    ft.run(main)
