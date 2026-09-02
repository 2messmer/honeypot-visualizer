





"""
demo_run.py
-----------
Lance l'app en mode demo. Utilise ce fichier au lieu de main.py
le jour de l'enregistrement de la video.
"""


import flet as ft
from app import theme
from app.views import dashboard_view
from app.capture.event_bus import bus


CYAN  = "\033[96m"
GREEN = "\033[92m"
AMBER = "\033[93m"
RESET = "\033[0m"
BOLD  = "\033[1m"


def _print_demo_instructions():
    print()
    print(BOLD + CYAN + "=" * 60 + RESET)
    print(BOLD + "  HONEYPOT VISUALIZER v2 -- DEMO MODE" + RESET)
    print(CYAN + "=" * 60 + RESET)
    print()
    print(BOLD + AMBER + "  ATTACKS tab -- paste these one by one:" + RESET)
    print()
    print(f"  {GREEN}1.{RESET} curl -s -o /dev/null -w \"HTTP %{'{http_code}'}\" http://127.0.0.1:8080/wp-login.php")
    print(f"  {GREEN}2.{RESET} curl -s -o /dev/null -w \"HTTP %{'{http_code}'}\" http://127.0.0.1:8080/.env")
    print(f"  {GREEN}3.{RESET} curl -s -o /dev/null -w \"HTTP %{'{http_code}'}\" \"http://127.0.0.1:8080/search?id=1'+UNION+SELECT+1,2,3--\"")
    print(f"  {GREEN}4.{RESET} curl -s -o /dev/null -w \"HTTP %{'{http_code}'}\" \"http://127.0.0.1:8080/index.php?file=../../../../etc/passwd\"")
    print(f"  {GREEN}5.{RESET} curl -s -o /dev/null -w \"HTTP %{'{http_code}'}\" -H \"User-Agent: Nmap Scripting Engine\" http://127.0.0.1:8080/admin")
    print(f"  {GREEN}6.{RESET} ssh root@127.0.0.1 -p 2222 -o StrictHostKeyChecking=no")
    print(f"           (mot de passe : toor)")
    print()
    print(BOLD + AMBER + "  CLUSTER-SIM tab -- lance la simulation coordonnee:" + RESET)
    print()
    print(f"  {GREEN}7.{RESET} python demo_cluster_attack.py")
    print()
    print(CYAN + "=" * 60 + RESET)
    print(BOLD + GREEN + "  App is starting..." + RESET)
    print(CYAN + "=" * 60 + RESET)
    print()


def main(page: ft.Page):
    page.title = "Honeypot Visualizer v2 | DEMO MODE"
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
    _print_demo_instructions()
    ft.run(main)