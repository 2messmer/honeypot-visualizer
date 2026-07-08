# Honeypot Visualizer

**Decoy SSH/HTTP services, scored by a custom Behavioral Danger Index, displayed on a live threat-proximity radar.**

Most honeypot dashboards just plot attacker IPs on a literal world map and
count hits. This one does two things differently:

1. **A custom scoring algorithm** — the *Behavioral Danger Index (BDI)* —
   combines four independent signals (request frequency, path/service
   diversity, known-attack-signature matching, and credential-stuffing
   behavior) into a single 0-100 score per source IP. There's no
   "official" formula for this; it's an original heuristic built for
   this project (see `app/intel/scoring.py`).
2. **A threat-proximity radar, not a map** — distance from center encodes
   *danger* (BDI), not geography. Two attackers on opposite sides of the
   planet with the same score sit on the same ring. Bearing (angle)
   still comes from a real signal (a deterministic hash of the IP, or
   optionally live geolocation), so the display isn't arbitrary — it's
   just reorganized around what actually matters operationally.

## What's inside

| Component | What it does |
|---|---|
| **HTTP honeypot** | A decoy web server that answers common bait paths (`/wp-login.php`, `/.env`, `/phpmyadmin/`, ...) and logs every request. Never executes anything a visitor sends. |
| **SSH honeypot** | A decoy SSH server (via `paramiko`) that completes the handshake, logs every username/password or public-key attempt, and **always rejects authentication** — no real access is ever granted, by construction. |
| **Behavioral Danger Index** | Custom 0-100 threat score per IP, recomputed live as new events arrive. |
| **Threat Proximity Radar** | A military-radar-style live visualization: rotating sweep, danger-tier rings, pulsing blips. |
| **Demo traffic simulator** | Generates realistic synthetic events so you can showcase/screenshot the dashboard without exposing a real port to the internet. |

## ⚠️ Safety first — read before running for real

- Only run the real honeypot listeners on infrastructure **you own or are
  explicitly authorized to monitor**.
- **Do not** forward these ports from your home router to try to attract
  real internet traffic — that exposes your home network. Run this on an
  isolated VM or a cheap cloud instance if you want real-world traffic.
- The SSH honeypot **never grants real authentication**, by design —
  verified in `tests/test_honeypot_core.py`.
- If you just want to see the dashboard working, use the built-in
  **"Start demo traffic"** button — no real network exposure needed.

## Getting started

```bash
git clone https://github.com/<your-username>/honeypot-visualizer.git
cd honeypot-visualizer
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Then, in the app:
1. Click **"Start / Stop demo traffic"** to see the radar come alive safely, or
2. Set a port and click **Start / Stop** next to HTTP / SSH to run the real decoy services locally, then attack your own machine from another terminal to test it (see below).

## Project structure

```
honeypot-visualizer/
├── main.py
├── requirements.txt
├── app/
│   ├── theme.py
│   ├── capture/
│   │   ├── http_honeypot.py     # decoy HTTP server
│   │   ├── ssh_honeypot.py      # decoy SSH server (paramiko)
│   │   ├── event_bus.py         # thread-safe queue -> UI bridge
│   │   └── event_store.py       # SQLite persistence
│   ├── intel/
│   │   ├── signatures.py        # known attack-pattern reference data
│   │   ├── scoring.py           # the Behavioral Danger Index algorithm
│   │   └── geolocate.py         # IP -> radar bearing
│   ├── simulate/
│   │   └── attack_simulator.py  # safe synthetic demo traffic
│   └── views/
│       ├── radar_canvas.py      # radar drawing math
│       └── dashboard_view.py    # the single live dashboard screen
└── tests/
    └── test_honeypot_core.py    # incl. full socket-level end-to-end tests
```

## Testing it against yourself (optional, local only)

```bash
python main.py
# in the app: set HTTP port to 8080 and click Start

# in another terminal:
curl http://127.0.0.1:8080/wp-login.php
curl http://127.0.0.1:8080/.env

# for SSH (set SSH port to 2222 and click Start):
ssh root@127.0.0.1 -p 2222   # will always be rejected — that's the point
```

## Running the tests

```bash
python -m pytest tests/ -v
```

## License

MIT — see [LICENSE](LICENSE).
