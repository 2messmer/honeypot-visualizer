"""
signatures.py
--------------
Reference lists used to recognize common attack patterns in HTTP paths,
query strings, and request bodies hitting the honeypot. These are widely
published, defensive fingerprints (the same category of data used by
WAFs, IDS rulesets, and honeypots like Cowrie/Dionaea) — recognizing a
pattern is not the same as exploiting one.
"""

# Paths commonly probed by mass-scanning bots looking for exposed secrets,
# admin panels, or vulnerable software versions.
BAIT_PATHS = [
    "/",
    "/admin",
    "/admin/login",
    "/wp-login.php",
    "/wp-admin/",
    "/.env",
    "/.git/config",
    "/config.php",
    "/phpmyadmin/",
    "/api/v1/users",
    "/console/",
    "/actuator/health",
    "/.aws/credentials",
    "/server-status",
    "/xmlrpc.php",
]

# Substrings that, if present in a path/query/body, suggest a scripted
# exploitation attempt rather than a benign request.
SUSPICIOUS_SUBSTRINGS = [
    "../", "..%2f", "union select", "select * from", "' or '1'='1",
    "<script>", "onerror=", "etc/passwd", "cmd.exe", "/bin/sh",
    "wget ", "curl ", "base64_decode", "eval(", "phpinfo(",
    "..\\", "%00", "sleep(5)", "benchmark(",
]

# Usernames/passwords so commonly tried by SSH credential-stuffing bots
# that trying them is itself a strong signal (independent of whether they
# "work" — our honeypot never grants real access).
COMMON_CREDENTIAL_PAIRS = {
    ("root", "root"), ("root", "123456"), ("root", "toor"),
    ("admin", "admin"), ("admin", "password"), ("user", "user"),
    ("pi", "raspberry"), ("ubuntu", "ubuntu"), ("test", "test"),
    ("oracle", "oracle"), ("postgres", "postgres"),
}


def matches_bait_path(path: str) -> bool:
    return path.rstrip("/") in {p.rstrip("/") for p in BAIT_PATHS} or path == "/"


def suspicious_score(text: str) -> float:
    """
    Returns a 0.0-1.0 score based on how many known-suspicious substrings
    appear in `text` (path + query + body combined), capped at 1.0.
    """
    if not text:
        return 0.0
    lowered = text.lower()
    hits = sum(1 for pattern in SUSPICIOUS_SUBSTRINGS if pattern in lowered)
    return min(hits / 3.0, 1.0)


def is_common_credential_pair(username: str, password: str) -> bool:
    return (username.strip().lower(), password.strip().lower()) in COMMON_CREDENTIAL_PAIRS
