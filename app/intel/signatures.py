"""
signatures.py  (v2)
--------------------
Extends v1 with PAYLOAD TECHNIQUE CLASSIFICATION: for each HTTP request,
`classify_techniques(raw_text)` returns a set of short attack-technique
tags (SQL_INJECTION, PATH_TRAVERSAL, etc.) that the dashboard displays
as colored badges on log rows. This makes the log immediately actionable
instead of just showing raw strings.
"""

from __future__ import annotations
import re

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

BAIT_PATHS = [
    "/", "/admin", "/admin/login", "/wp-login.php", "/wp-admin/",
    "/.env", "/.git/config", "/config.php", "/phpmyadmin/",
    "/api/v1/users", "/console/", "/actuator/health",
    "/.aws/credentials", "/server-status", "/xmlrpc.php",
]

SUSPICIOUS_SUBSTRINGS = [
    "../", "..%2f", "union select", "select * from", "' or '1'='1",
    "<script>", "onerror=", "etc/passwd", "cmd.exe", "/bin/sh",
    "wget ", "curl ", "base64_decode", "eval(", "phpinfo(",
    "..\\", "%00", "sleep(5)", "benchmark(",
]

COMMON_CREDENTIAL_PAIRS = {
    ("root", "root"), ("root", "123456"), ("root", "toor"),
    ("admin", "admin"), ("admin", "password"), ("user", "user"),
    ("pi", "raspberry"), ("ubuntu", "ubuntu"), ("test", "test"),
    ("oracle", "oracle"), ("postgres", "postgres"),
}

# Technique classification rules:  (tag, list-of-pattern-regexes)
_TECHNIQUE_RULES: list[tuple[str, list[str]]] = [
    ("SQL_INJECTION",   [r"union\s+select", r"'\s*or\s*'1'\s*=\s*'1", r"sleep\s*\(", r"benchmark\s*\("]),
    ("PATH_TRAVERSAL",  [r"\.\./", r"\.\.%2f", r"etc/passwd", r"%00"]),
    ("XSS",             [r"<script", r"onerror\s*=", r"javascript:"]),
    ("CMD_INJECTION",   [r"/bin/sh", r"cmd\.exe", r";\s*ls\s", r";\s*id\s", r";\s*whoami"]),
    ("FILE_DISCLOSURE", [r"\.env", r"\.git/", r"\.aws/", r"config\.php", r"wp-config\.php"]),
    ("RCE_ATTEMPT",     [r"base64_decode", r"eval\s*\(", r"phpinfo\s*\(", r"wget\s+http", r"curl\s+http"]),
    ("SCANNER",         [r"nmap", r"masscan", r"zgrab", r"nuclei", r"nikto", r"sqlmap"]),
]

TECHNIQUE_COLORS = {
    "SQL_INJECTION":   "#FF4136",
    "PATH_TRAVERSAL":  "#FF851B",
    "XSS":             "#FFDC00",
    "CMD_INJECTION":   "#FF4136",
    "FILE_DISCLOSURE": "#B10DC9",
    "RCE_ATTEMPT":     "#FF4136",
    "SCANNER":         "#7FDBFF",
    "CRED_STUFFING":   "#01FF70",
}


def classify_techniques(raw_text: str) -> set[str]:
    """Returns a set of attack technique tags present in raw_text."""
    if not raw_text:
        return set()
    lowered = raw_text.lower()
    tags = set()
    for tag, patterns in _TECHNIQUE_RULES:
        for pat in patterns:
            if re.search(pat, lowered):
                tags.add(tag)
                break
    return tags


def matches_bait_path(path: str) -> bool:
    return path.rstrip("/") in {p.rstrip("/") for p in BAIT_PATHS} or path == "/"


def suspicious_score(text: str) -> float:
    if not text:
        return 0.0
    lowered = text.lower()
    hits = sum(1 for pattern in SUSPICIOUS_SUBSTRINGS if pattern in lowered)
    return min(hits / 3.0, 1.0)


def is_common_credential_pair(username: str, password: str) -> bool:
    return (username.strip().lower(), password.strip().lower()) in COMMON_CREDENTIAL_PAIRS
