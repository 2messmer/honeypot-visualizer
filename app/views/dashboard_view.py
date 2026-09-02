"""
dashboard_view.py  (v2)
------------------------
The single live dashboard screen. Integrates all v2 additions:
  - Threat DNA Gallery panel (right column, middle)
  - Attack Timeline panel (right column, bottom)
  - Cluster panel (left column, below leaderboard)
  - Enhanced log with technique badges
  - BDI v2 scores (6 sub-scores)
  - Event pulse animation on the radar
  - Automation score indicator in leaderboard
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
from app.intel.cluster_engine import ClusterEngine
from app.intel import signatures as sig_module
from app.views import radar_canvas, timeline_view, dna_panel_view

MAX_LOG = 60
PULSE_LIFETIME = 1.0    # seconds a pulse ring lives


def build(page: ft.Page) -> ft.Control:
    store = EventStore()
    registry = ThreatRegistry()
    cluster_engine = ClusterEngine()
    http_hp = HttpHoneypot(port=8080)
    ssh_hp = SshHoneypot(port=2222)
    simulator = AttackSimulator()

    state = {
        "start_time": time.time(),
        "total_events": 0,
        "sweep_angle": 0.0,
        "log_rows": [],
        "session_events": [],    # all HoneypotEvent objects this session (for timeline)
        "pulses": [],            # list of [x, y, birth_time]
    }

    # ---- Static controls ----

    http_port_field = ft.TextField(
        value="8080", width=86, label="HTTP",
        border_color=theme.BORDER_SOFT, color=theme.TEXT_PRIMARY,
    )
    ssh_port_field = ft.TextField(
        value="2222", width=86, label="SSH",
        border_color=theme.BORDER_SOFT, color=theme.TEXT_PRIMARY,
    )
    http_dot = ft.Container(
        width=9, height=9, bgcolor=theme.TEXT_MUTED,
        border_radius=ft.border_radius.all(5),
    )
    ssh_dot = ft.Container(
        width=9, height=9, bgcolor=theme.TEXT_MUTED,
        border_radius=ft.border_radius.all(5),
    )
    sim_dot = ft.Container(
        width=9, height=9, bgcolor=theme.TEXT_MUTED,
        border_radius=ft.border_radius.all(5),
    )
    http_txt = ft.Text("stopped", size=11, color=theme.TEXT_MUTED)
    ssh_txt = ft.Text("stopped", size=11, color=theme.TEXT_MUTED)
    sim_txt = ft.Text("stopped", size=11, color=theme.TEXT_MUTED)

    events_ctr = ft.Text("0", size=22, weight=ft.FontWeight.W_800, color=theme.PHOSPHOR_GREEN)
    ips_ctr = ft.Text("0", size=22, weight=ft.FontWeight.W_800, color=theme.PHOSPHOR_GREEN)
    clusters_ctr = ft.Text("0", size=22, weight=ft.FontWeight.W_800, color=theme.CLUSTER_RING_COLOR)
    uptime_txt = ft.Text("00:00:00", size=18, weight=ft.FontWeight.W_800, color=theme.PHOSPHOR_GREEN)

    # Canvases
    radar_canvas_ctl = fc.Canvas(shapes=radar_canvas.build_static_rings(), width=480, height=480)
    timeline_canvas_ctl = fc.Canvas(shapes=[], width=480, height=260)
    dna_canvas_ctl = fc.Canvas(shapes=[], width=480, height=200)

    log_col = ft.Column([], spacing=3, scroll=ft.ScrollMode.AUTO, height=200)
    leaderboard_col = ft.Column([], spacing=5)
    cluster_col = ft.Column([], spacing=4)
    error_banner = ft.Text("", size=11, color=theme.RED_CRITICAL)

    def _set_status(dot, txt, running):
        dot.bgcolor = theme.PHOSPHOR_GREEN if running else theme.TEXT_MUTED
        txt.value = "running" if running else "stopped"
        txt.color = theme.PHOSPHOR_GREEN if running else theme.TEXT_MUTED
        dot.update(); txt.update()

    # ---- Honeypot controls ----

    def toggle_http(e):
        if http_hp.is_running:
            http_hp.stop()
        else:
            try:
                http_hp.port = int(http_port_field.value or 8080)
                http_hp.start()
            except OSError as ex:
                error_banner.value = str(ex); error_banner.update(); return
        _set_status(http_dot, http_txt, http_hp.is_running)

    def toggle_ssh(e):
        if ssh_hp.is_running:
            ssh_hp.stop()
        else:
            try:
                ssh_hp.port = int(ssh_port_field.value or 2222)
                ssh_hp.start()
            except OSError as ex:
                error_banner.value = str(ex); error_banner.update(); return
        _set_status(ssh_dot, ssh_txt, ssh_hp.is_running)

    def toggle_sim(e):
        if simulator.is_running:
            simulator.stop()
        else:
            simulator.start()
        _set_status(sim_dot, sim_txt, simulator.is_running)

    # ---- Rendering helpers ----

    def _technique_badges(tags: set) -> list[ft.Control]:
        badges = []
        for tag in sorted(tags)[:3]:
            color = sig_module.TECHNIQUE_COLORS.get(tag, "#444")
            badges.append(ft.Container(
                content=ft.Text(tag[:6], size=8, weight=ft.FontWeight.W_700, color=theme.BG_DARK),
                bgcolor=color, padding=ft.padding.symmetric(horizontal=4, vertical=1),
                border_radius=ft.border_radius.all(3),
            ))
        return badges

    def _log_row(ev) -> ft.Row:
        tstr = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
        svc_color = theme.PHOSPHOR_GREEN if ev.service == "http" else theme.AMBER
        detail = ev.path if ev.service == "http" else f"{ev.username}/{ev.password}"
        badges = _technique_badges(ev.technique_tags or set())
        return ft.Row(
            [
                ft.Text(tstr, size=10, color=theme.TEXT_MUTED, width=60, font_family="Consolas"),
                ft.Container(
                    content=ft.Text(ev.service.upper(), size=9, weight=ft.FontWeight.W_700, color=theme.BG_DARK),
                    bgcolor=svc_color, padding=ft.padding.symmetric(horizontal=5, vertical=1),
                    border_radius=ft.border_radius.all(3), width=40, alignment=ft.Alignment.CENTER,
                ),
                ft.Text(ev.ip, size=10, color=theme.TEXT_PRIMARY, width=100, font_family="Consolas"),
                ft.Text(detail[:36], size=10, color=theme.TEXT_MUTED, font_family="Consolas", expand=True),
                *badges,
            ],
            spacing=6,
        )

    def _render_leaderboard():
        rows = []
        for p in registry.top_offenders(6):
            color = theme.TIER_COLORS[p.tier()]
            auto = p.automation_score()
            auto_label = "BOT" if auto > 0.6 else ("MIX" if auto > 0.3 else "HUM")
            auto_color = theme.RED_CRITICAL if auto > 0.6 else (theme.AMBER if auto > 0.3 else theme.PHOSPHOR_GREEN)
            rows.append(ft.Column([
                ft.Row([
                    ft.Text(p.ip, size=11, color=theme.TEXT_PRIMARY, font_family="Consolas"),
                    ft.Row([
                        ft.Text(f"{p.bdi():.0f}", size=11, weight=ft.FontWeight.W_700, color=color),
                        ft.Container(
                            content=ft.Text(auto_label, size=8, weight=ft.FontWeight.W_700, color=theme.BG_DARK),
                            bgcolor=auto_color, padding=ft.padding.symmetric(horizontal=4, vertical=1),
                            border_radius=ft.border_radius.all(3),
                        ),
                    ], spacing=4),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Container(
                    content=ft.Container(
                        bgcolor=color, border_radius=ft.border_radius.all(3),
                        height=5, width=max(4, 2.2 * p.bdi()),
                    ),
                    bgcolor=theme.BG_PANEL_ALT,
                    border_radius=ft.border_radius.all(3), height=5, width=230,
                ),
            ], spacing=3))
        leaderboard_col.controls = rows

    def _render_cluster_panel(clusters, profiles_map):
        rows = []
        for c in clusters:
            bdi = c.cluster_bdi(profiles_map)
            tier = c.tier(profiles_map)
            color = theme.TIER_COLORS[tier]
            rows.append(ft.Row([
                ft.Icon(ft.Icons.HUB_ROUNDED, color=theme.CLUSTER_RING_COLOR, size=16),
                ft.Text(f"{c.subnet}.0/24", size=11, color=theme.TEXT_PRIMARY, font_family="Consolas"),
                ft.Text(f"{c.member_count} IPs", size=10, color=theme.TEXT_MUTED),
                ft.Text(f"BDI {bdi:.0f}", size=11, weight=ft.FontWeight.W_700, color=color),
            ], spacing=6))
        cluster_col.controls = rows if rows else [ft.Text("No clusters detected", size=11, color=theme.TEXT_MUTED)]

    # ---- Main async loop ----

    async def loop():
        while True:
            new_events = bus.drain()
            now = time.time()

            if new_events:
                for ev in new_events:
                    store.save(ev)
                    cluster_engine.register_event(ev.ip)
                    profile = registry.get_or_create(ev.ip)
                    if profile.total_events == 0:
                        profile.historical_events = store.count_for_ip(ev.ip)
                    profile.register_event(
                        service=ev.service, path=ev.path, raw_text=ev.raw_text,
                        username=ev.username, password=ev.password,
                        technique_tags=ev.technique_tags,
                    )
                    state["session_events"].append(ev)
                    state["log_rows"].insert(0, _log_row(ev))

                    # Spawn a pulse on the radar at this IP's position
                    bdi = profile.bdi()
                    from app.intel.geolocate import bearing_for_ip
                    bearing = bearing_for_ip(ev.ip)
                    r = radar_canvas.bdi_to_radius(bdi)
                    px, py = radar_canvas._polar(bearing, r)
                    state["pulses"].append([px, py, now])

                state["session_events"] = state["session_events"][-2000:]
                state["log_rows"] = state["log_rows"][:MAX_LOG]
                state["total_events"] += len(new_events)
                log_col.controls = state["log_rows"]
                events_ctr.value = str(state["total_events"])
                ips_ctr.value = str(len(registry.all_profiles()))

            # Age out dead pulses
            state["pulses"] = [[x, y, bt] for x, y, bt in state["pulses"] if now - bt < PULSE_LIFETIME]
            active_pulses = [(x, y, (now - bt) / PULSE_LIFETIME) for x, y, bt in state["pulses"]]

            # Radar
            state["sweep_angle"] = (state["sweep_angle"] + 5) % 360
            profiles_map = cluster_engine.all_profiles_map(registry)
            active_clusters = cluster_engine.active_clusters()
            shapes = (
                radar_canvas.build_static_rings()
                + radar_canvas.build_sweep(state["sweep_angle"])
                + radar_canvas.build_cluster_rings(active_clusters, profiles_map, now)
                + radar_canvas.build_blips(registry.all_profiles(), now)
                + radar_canvas.build_event_pulses(active_pulses)
            )
            radar_canvas_ctl.shapes = shapes

            # Timeline
            top_profiles = registry.top_offenders(6)
            timeline_canvas_ctl.shapes = timeline_view.build_timeline_shapes(
                top_profiles, state["session_events"]
            )

            # DNA gallery
            dna_shapes, dna_h = dna_panel_view.build_dna_canvas_shapes(top_profiles)
            dna_canvas_ctl.shapes = dna_shapes
            dna_canvas_ctl.height = dna_h

            # Clusters panel
            _render_cluster_panel(active_clusters, profiles_map)
            clusters_ctr.value = str(len(active_clusters))

            # Leaderboard
            _render_leaderboard()

            # Uptime
            e = int(now - state["start_time"])
            uptime_txt.value = f"{e//3600:02d}:{(e%3600)//60:02d}:{e%60:02d}"

            # Batch update
            for ctl in [
                radar_canvas_ctl, timeline_canvas_ctl, dna_canvas_ctl,
                log_col, leaderboard_col, cluster_col,
                events_ctr, ips_ctr, clusters_ctr, uptime_txt,
            ]:
                ctl.update()

            await asyncio.sleep(0.3)

    page.run_task(loop)

    # ---- Layout ----

    ctrl_panel = theme.panel(ft.Column([
        theme.section_title("Honeypot control", ft.Icons.SETTINGS_ETHERNET_ROUNDED),
        ft.Row([http_port_field, ft.Button(content="HTTP", icon=ft.Icons.DNS_ROUNDED, on_click=toggle_http),
                http_dot, http_txt], spacing=8),
        ft.Row([ssh_port_field, ft.Button(content="SSH", icon=ft.Icons.TERMINAL_ROUNDED, on_click=toggle_ssh),
                ssh_dot, ssh_txt], spacing=8),
        ft.Divider(color=theme.BORDER_SOFT),
        ft.Row([ft.OutlinedButton(content="Demo traffic", icon=ft.Icons.SCIENCE_ROUNDED, on_click=toggle_sim),
                sim_dot, sim_txt], spacing=8),
        error_banner,
        ft.Container(height=2),
        ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color=theme.AMBER, size=14),
                ft.Text("Only run on infrastructure you own or are authorized to monitor.",
                        size=10, color=theme.TEXT_MUTED, expand=True),
            ], spacing=6),
            bgcolor=theme.BG_PANEL_ALT, padding=8, border_radius=ft.border_radius.all(7),
        ),
    ], spacing=9))

    stats_panel = theme.panel(ft.Row([
        ft.Column([ft.Text("EVENTS", size=10, color=theme.TEXT_MUTED), events_ctr]),
        ft.Column([ft.Text("UNIQUE IPS", size=10, color=theme.TEXT_MUTED), ips_ctr]),
        ft.Column([ft.Text("CLUSTERS", size=10, color=theme.TEXT_MUTED), clusters_ctr]),
        ft.Column([ft.Text("UPTIME", size=10, color=theme.TEXT_MUTED), uptime_txt]),
    ], alignment=ft.MainAxisAlignment.SPACE_AROUND))

    leader_panel = theme.panel(ft.Column([
        theme.section_title("Top offenders  BDI v2", ft.Icons.LEADERBOARD_ROUNDED),
        leaderboard_col,
    ], spacing=8))

    cluster_panel = theme.panel(ft.Column([
        theme.section_title("Active subnet clusters", ft.Icons.HUB_ROUNDED),
        cluster_col,
    ], spacing=8))

    radar_panel = theme.panel(ft.Column([
        theme.section_title("Threat proximity radar  v2", ft.Icons.RADAR_ROUNDED),
        ft.Text("Distance = danger  |  Cyan rings = coordinated subnet clusters",
                size=9, color=theme.TEXT_MUTED),
        ft.Container(content=radar_canvas_ctl, alignment=ft.Alignment.CENTER),
    ], spacing=6))

    dna_panel = theme.panel(ft.Column([
        theme.section_title("Threat DNA fingerprints", ft.Icons.FINGERPRINT_ROUNDED),
        ft.Text("32-cell behavioral barcode per attacker  |  8 dimensions  |  updates live",
                size=9, color=theme.TEXT_MUTED),
        ft.Container(content=dna_canvas_ctl),
    ], spacing=6))

    timeline_panel = theme.panel(ft.Column([
        theme.section_title("Attack timeline", ft.Icons.TIMELINE_ROUNDED),
        ft.Text("Last 5 min  |  rows = top IPs by BDI  |  colors = technique",
                size=9, color=theme.TEXT_MUTED),
        ft.Container(content=timeline_canvas_ctl),
    ], spacing=6))

    log_panel = theme.panel(
        ft.Column([
            theme.section_title("Live event log  (with technique tags)", ft.Icons.LIST_ALT_ROUNDED),
            log_col,
        ], spacing=6),
        expand=True,
    )

    left_col = ft.Column([ctrl_panel, stats_panel, leader_panel, cluster_panel],
                          spacing=16, width=370)
    right_col = ft.Column([radar_panel, dna_panel, timeline_panel], spacing=16, expand=True)

    return ft.Container(
        content=ft.Column([
            ft.Text("HONEYPOT VISUALIZER  v2", style=theme.HEADLINE_STYLE),
            ft.Text("BDI v2  |  Threat DNA fingerprinting  |  Subnet cluster detection  |  Attack timeline",
                    style=theme.SUBHEAD_STYLE),
            ft.Container(height=6),
            ft.Row([left_col, right_col], spacing=16,
                   alignment=ft.MainAxisAlignment.START,
                   vertical_alignment=ft.CrossAxisAlignment.START),
            ft.Container(height=10),
            log_panel,
        ], scroll=ft.ScrollMode.AUTO),
        padding=28, expand=True,
    )
