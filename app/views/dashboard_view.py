"""
dashboard_view.py — the single persistent screen of Honeypot Visualizer.

Unlike Cipher Forge's multi-page navigation, this is ONE continuously
running dashboard: the honeypots and simulator run in background threads
regardless of what you're looking at, so there is no "module" to
navigate away from and lose state.
"""

from __future__ import annotations
import asyncio
import time

import flet as ft
import flet.canvas as fc

from app import theme
from app.capture.event_bus import bus
from app.capture.event_store import EventStore
from app.capture.http_honeypot import HttpHoneypot
from app.capture.ssh_honeypot import SshHoneypot
from app.simulate.attack_simulator import AttackSimulator
from app.intel.scoring import ThreatRegistry
from app.views import radar_canvas

MAX_LOG_ROWS = 60


def build(page: ft.Page) -> ft.Control:
    store = EventStore()
    registry = ThreatRegistry()
    http_honeypot = HttpHoneypot(port=8080)
    ssh_honeypot = SshHoneypot(port=2222)
    simulator = AttackSimulator()

    state = {
        "start_time": time.time(),
        "total_events": 0,
        "sweep_angle": 0.0,
        "log_rows": [],  # list[ft.Row], most recent first
    }

    # ---- Controls ----------------------------------------------------

    http_port_field = ft.TextField(value="8080", width=90, label="HTTP port",
                                    border_color=theme.BORDER_SOFT, color=theme.TEXT_PRIMARY)
    ssh_port_field = ft.TextField(value="2222", width=90, label="SSH port",
                                   border_color=theme.BORDER_SOFT, color=theme.TEXT_PRIMARY)

    http_status_dot = ft.Container(width=10, height=10, border_radius=ft.border_radius.all(5),
                                    bgcolor=theme.TEXT_MUTED)
    ssh_status_dot = ft.Container(width=10, height=10, border_radius=ft.border_radius.all(5),
                                   bgcolor=theme.TEXT_MUTED)
    sim_status_dot = ft.Container(width=10, height=10, border_radius=ft.border_radius.all(5),
                                   bgcolor=theme.TEXT_MUTED)

    http_status_text = ft.Text("stopped", size=12, color=theme.TEXT_MUTED)
    ssh_status_text = ft.Text("stopped", size=12, color=theme.TEXT_MUTED)
    sim_status_text = ft.Text("stopped", size=12, color=theme.TEXT_MUTED)

    events_counter = ft.Text("0", size=22, weight=ft.FontWeight.W_800, color=theme.PHOSPHOR_GREEN)
    ips_counter = ft.Text("0", size=22, weight=ft.FontWeight.W_800, color=theme.PHOSPHOR_GREEN)
    uptime_text = ft.Text("00:00:00", size=22, weight=ft.FontWeight.W_800, color=theme.PHOSPHOR_GREEN)

    canvas = fc.Canvas(shapes=radar_canvas.build_static_rings(), width=480, height=480)
    log_column = ft.Column([], spacing=4, scroll=ft.ScrollMode.AUTO, height=360)
    leaderboard_column = ft.Column([], spacing=6)

    def set_status(dot: ft.Container, text_ctl: ft.Text, running: bool, refresh=True):
        dot.bgcolor = theme.PHOSPHOR_GREEN if running else theme.TEXT_MUTED
        text_ctl.value = "running" if running else "stopped"
        text_ctl.color = theme.PHOSPHOR_GREEN if running else theme.TEXT_MUTED
        if refresh:
            dot.update()
            text_ctl.update()

    # ---- Start/stop handlers ------------------------------------------

    def toggle_http(e):
        if http_honeypot.is_running:
            http_honeypot.stop()
        else:
            try:
                port = int(http_port_field.value or 8080)
                http_honeypot.port = port
                http_honeypot.start()
            except OSError as ex:
                _flash_error(f"Could not start HTTP honeypot: {ex}")
                return
        set_status(http_status_dot, http_status_text, http_honeypot.is_running)

    def toggle_ssh(e):
        if ssh_honeypot.is_running:
            ssh_honeypot.stop()
        else:
            try:
                port = int(ssh_port_field.value or 2222)
                ssh_honeypot.port = port
                ssh_honeypot.start()
            except OSError as ex:
                _flash_error(f"Could not start SSH honeypot: {ex}")
                return
        set_status(ssh_status_dot, ssh_status_text, ssh_honeypot.is_running)

    def toggle_sim(e):
        if simulator.is_running:
            simulator.stop()
        else:
            simulator.start()
        set_status(sim_status_dot, sim_status_text, simulator.is_running)

    error_banner = ft.Text("", size=12, color=theme.RED_CRITICAL)

    def _flash_error(msg: str):
        error_banner.value = msg
        error_banner.update()

    http_button = ft.Button(content="Start / Stop", icon=ft.Icons.DNS_ROUNDED, on_click=toggle_http)
    ssh_button = ft.Button(content="Start / Stop", icon=ft.Icons.TERMINAL_ROUNDED, on_click=toggle_ssh)
    sim_button = ft.OutlinedButton(content="Start / Stop demo traffic", icon=ft.Icons.SCIENCE_ROUNDED,
                                    on_click=toggle_sim)

    # ---- Rendering helpers ---------------------------------------------

    def render_log_row(ev) -> ft.Row:
        tstr = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
        service_color = theme.PHOSPHOR_GREEN if ev.service == "http" else theme.AMBER
        detail = ev.path if ev.service == "http" else f"user={ev.username} pass={ev.password}"
        return ft.Row(
            [
                ft.Text(tstr, size=11, color=theme.TEXT_MUTED, width=70, font_family="Consolas"),
                ft.Container(content=ft.Text(ev.service.upper(), size=10, weight=ft.FontWeight.W_700,
                                              color=theme.BG_DARK), bgcolor=service_color,
                             padding=ft.padding.symmetric(horizontal=6, vertical=1),
                             border_radius=ft.border_radius.all(4), width=48, alignment=ft.Alignment.CENTER),
                ft.Text(ev.ip, size=11, color=theme.TEXT_PRIMARY, width=110, font_family="Consolas"),
                ft.Text(detail[:48], size=11, color=theme.TEXT_MUTED, font_family="Consolas", expand=True),
            ],
            spacing=8,
        )

    def render_leaderboard():
        rows = []
        for profile in registry.top_offenders(6):
            color = theme.TIER_COLORS[profile.tier()]
            rows.append(
                ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Text(profile.ip, size=12, color=theme.TEXT_PRIMARY, font_family="Consolas"),
                                ft.Text(f"{profile.bdi():.0f}", size=12, weight=ft.FontWeight.W_700, color=color),
                            ],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                        ft.Container(
                            content=ft.Container(
                                bgcolor=color, border_radius=ft.border_radius.all(3), height=6,
                                width=max(4, 2.4 * profile.bdi()),
                            ),
                            bgcolor=theme.BG_PANEL_ALT, border_radius=ft.border_radius.all(3), height=6, width=240,
                        ),
                    ],
                    spacing=3,
                )
            )
        leaderboard_column.controls = rows

    # ---- Main animation / ingestion loop --------------------------------

    async def loop():
        while True:
            new_events = bus.drain()
            if new_events:
                for ev in new_events:
                    store.save(ev)
                    profile = registry.get_or_create(ev.ip)
                    profile.register_event(
                        service=ev.service, path=ev.path, raw_text=ev.raw_text,
                        username=ev.username, password=ev.password,
                    )
                    state["log_rows"].insert(0, render_log_row(ev))
                state["log_rows"] = state["log_rows"][:MAX_LOG_ROWS]
                state["total_events"] += len(new_events)
                log_column.controls = state["log_rows"]
                events_counter.value = str(state["total_events"])
                ips_counter.value = str(len(registry.all_profiles()))
                render_leaderboard()

            state["sweep_angle"] = (state["sweep_angle"] + 6) % 360
            shapes = radar_canvas.build_static_rings()
            shapes += radar_canvas.build_sweep(state["sweep_angle"])
            shapes += radar_canvas.build_blips(registry.all_profiles(), pulse_phase=time.time())
            canvas.shapes = shapes

            elapsed = int(time.time() - state["start_time"])
            uptime_text.value = f"{elapsed // 3600:02d}:{(elapsed % 3600) // 60:02d}:{elapsed % 60:02d}"

            canvas.update()
            log_column.update()
            leaderboard_column.update()
            events_counter.update()
            ips_counter.update()
            uptime_text.update()

            await asyncio.sleep(0.3)

    page.run_task(loop)

    # ---- Layout ----------------------------------------------------------

    control_panel = theme.panel(
        ft.Column(
            [
                theme.section_title("Honeypot control", ft.Icons.SETTINGS_ETHERNET_ROUNDED),
                ft.Row([http_port_field, http_button, http_status_dot, http_status_text], spacing=10),
                ft.Row([ssh_port_field, ssh_button, ssh_status_dot, ssh_status_text], spacing=10),
                ft.Divider(color=theme.BORDER_SOFT),
                ft.Row([sim_button, sim_status_dot, sim_status_text], spacing=10),
                error_banner,
                ft.Container(height=4),
                ft.Container(
                    content=ft.Row(
                        [
                            ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=theme.AMBER, size=18),
                            ft.Text(
                                "Only run this on infrastructure you own or are explicitly authorized to "
                                "monitor. Do NOT forward these ports on a home router without understanding "
                                "the exposure that creates for your network. Prefer an isolated VM/cloud box.",
                                size=11, color=theme.TEXT_MUTED, expand=True,
                            ),
                        ],
                        spacing=8,
                    ),
                    bgcolor=theme.BG_PANEL_ALT, padding=10, border_radius=ft.border_radius.all(8),
                ),
            ],
            spacing=10,
        )
    )

    stats_panel = theme.panel(
        ft.Row(
            [
                ft.Column([ft.Text("EVENTS", size=11, color=theme.TEXT_MUTED), events_counter]),
                ft.Column([ft.Text("UNIQUE IPS", size=11, color=theme.TEXT_MUTED), ips_counter]),
                ft.Column([ft.Text("UPTIME", size=11, color=theme.TEXT_MUTED), uptime_text]),
            ],
            alignment=ft.MainAxisAlignment.SPACE_AROUND,
        )
    )

    radar_panel = theme.panel(
        ft.Column(
            [theme.section_title("Threat proximity radar", ft.Icons.RADAR_ROUNDED),
             ft.Text("Distance = danger (closer is worse). Bearing = source signal.",
                     size=10, color=theme.TEXT_MUTED),
             ft.Container(content=canvas, alignment=ft.Alignment.CENTER)],
            spacing=8,
        ),
        expand=True,
    )

    leaderboard_panel = theme.panel(
        ft.Column(
            [theme.section_title("Top offenders (Behavioral Danger Index)", ft.Icons.LEADERBOARD_ROUNDED),
             leaderboard_column],
            spacing=10,
        )
    )

    log_panel = theme.panel(
        ft.Column(
            [theme.section_title("Live event log", ft.Icons.LIST_ALT_ROUNDED), log_column],
            spacing=8,
        ),
        expand=True,
    )

    left_column = ft.Column([control_panel, stats_panel, leaderboard_panel], spacing=18, width=380)
    right_column = ft.Column([radar_panel, log_panel], spacing=18, expand=True)

    return ft.Container(
        content=ft.Column(
            [
                ft.Text("HONEYPOT VISUALIZER", style=theme.HEADLINE_STYLE),
                ft.Text("Live decoy SSH/HTTP services, scored by a custom Behavioral Danger Index.",
                        style=theme.SUBHEAD_STYLE),
                ft.Container(height=8),
                ft.Row([left_column, right_column], spacing=18, alignment=ft.MainAxisAlignment.START,
                       vertical_alignment=ft.CrossAxisAlignment.START),
            ],
            scroll=ft.ScrollMode.AUTO,
        ),
        padding=30,
        expand=True,
    )
