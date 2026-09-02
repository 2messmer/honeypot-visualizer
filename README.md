# Honeypot Visualizer v2

**BDI v2 | Threat DNA Fingerprinting | Subnet Cluster Detection | Attack Timeline**

> A major update to [Honeypot Visualizer v1](https://github.com/2messmer/honeypot-visualizer).
> Every new feature in v2 was designed around a specific limitation of v1.

## What is new in v2

| v1 limitation | v2 answer |
|---|---|
| Per-IP BDI with 4 sub-scores misses coordinated multi-IP attacks | **Subnet Cluster Engine** groups IPs by /24 and declares a cluster when 3+ IPs from the same subnet are active within 10 minutes |
| Every radar blip looks the same (only tier color varies) | **Threat DNA Fingerprinting** gives each IP a unique 32-cell color barcode from 8 behavioral dimensions |
| No way to see attack escalation (scan then exploit) | **Attack Timeline** canvas shows IP rows vs. time, with technique-colored dots revealing kill-chain progression |
| BDI could not distinguish bots from humans | **Automation sub-score** uses coefficient-of-variation of inter-arrival times |
| Log rows showed raw text only | **Technique badge system** tags each HTTP event with SQL_INJECTION, PATH_TRAVERSAL, RCE_ATTEMPT, etc. |
| BDI ignored repeat offenders from past sessions | **Persistence sub-score** reads historical event count from SQLite |

## Threat DNA Fingerprinting

The most original addition: instead of a uniform dot on the radar, every attacker IP gets a **32-cell behavioral barcode** derived from 8 independent dimensions of its attack behavior.

8 dimensions x 4 hex chars each = 32-char DNA string. Rendered as 32 colored rectangles in the DNA Gallery panel, where brightness encodes the value and hue encodes the dimension (green=frequency, red=credentials, blue=path diversity...).

Two IPs from the same botnet using the same credential list, path strategy, and timing pattern produce visually similar DNA strips. A human and a bot are visually distinct at a glance, even before BDI is computed.

Inspired by behavioral hashing in malware analysis (imphash, ssdeep), applied here to live honeypot telemetry.

## BDI v2 formula

```
BDI = 100 * (
    0.20 * frequency_score    +   # request rate (saturating curve)
    0.20 * diversity_score    +   # paths + services probed
    0.25 * signature_score    +   # known-attack-pattern density
    0.18 * credential_score   +   # credential-stuffing behavior
    0.10 * automation_score   +   # CoV of inter-arrival times (NEW)
    0.07 * persistence_score      # historical DB event count (NEW)
)
```

## Getting started

```bash
git clone https://github.com/2messmer/honeypot-visualizer.git
cd honeypot-visualizer
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/ -v   # 9 tests
python main.py
```

Click **Demo traffic** to see the radar, DNA gallery, and timeline populate safely without exposing real ports.

## Project structure

```
honeypot-visualizer/
├── main.py
├── app/
│   ├── theme.py
│   ├── capture/                    (event_bus, event_store, http/ssh honeypots)
│   ├── intel/
│   │   ├── scoring.py              BDI v2, 6 sub-scores
│   │   ├── cluster_engine.py       NEW: subnet cluster detection
│   │   ├── dna_engine.py           NEW: Threat DNA fingerprinting
│   │   ├── signatures.py           updated: payload technique classification
│   │   └── geolocate.py
│   ├── simulate/
│   │   └── attack_simulator.py     updated: realistic clusters + technique tags
│   └── views/
│       ├── radar_canvas.py         updated: cluster rings, DNA blips, pulses
│       ├── timeline_view.py        NEW: attack timeline canvas
│       ├── dna_panel_view.py       NEW: Threat DNA gallery canvas
│       └── dashboard_view.py       major update
└── tests/
    └── test_v2.py                  9 tests including real socket-level tests
```

## Safety

Only run the real honeypot listeners on infrastructure you own or are explicitly authorized to monitor. The SSH honeypot **never grants real authentication** (verified by test). Use the built-in simulator for demos.

## License

MIT
