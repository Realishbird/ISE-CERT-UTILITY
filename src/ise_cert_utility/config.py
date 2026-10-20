"""Settings, secrets and input validation.

Non-secret settings live in config.json. Credentials live in secrets.json and
are never returned to the browser. Both files are mode 0600 and owned by the
service account.
"""
import re
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import paths, store

KEY_TYPES = {
    "rsa2048": ("rsa", "2048"),
    "rsa3072": ("rsa", "3072"),
    "rsa4096": ("rsa", "4096"),
    "ecdsa256": ("ecdsa", "secp256r1"),
    "ecdsa384": ("ecdsa", "secp384r1"),
}
WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
NOTIFY_LEVELS = ("never", "failure", "always")

DEFAULTS = {
    # Certificate
    "domain": "",
    "acme_email": "",
    "key_type": "rsa2048",
    "renew_days": 30,
    "dns_propagation": 30,
    # ISE
    "ise_host": "",
    "ise_port": 443,
    "node": "",
    "username": "",
    "deploy_admin": True,
    "deploy_portal": True,
    "portal_tag": "Default Portal Certificate Group",
    "eap_fingerprint": "",
    "verify_minutes": 30,
    "remove_superseded": False,
    # Schedule
    "schedule_enabled": False,
    "timezone": "UTC",
    "window_start": "02:00",
    "window_end": "04:00",
    "weekdays": [0, 1, 2, 3, 4, 5, 6],
    "retry_minutes": 30,
    "max_attempts": 3,
    # Notifications
    "notify_on": "failure",
}
SECRET_KEYS = ("ise_password", "cloudflare_token", "webhook_url")

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(rf"(?:{_LABEL}\.)+{_LABEL}")
_TIME = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]")


def load():
    data = {**DEFAULTS, **store.read_json(paths.CONFIG)}
    return data


def save(values):
    current = store.read_json(paths.CONFIG)
    current.update(values)
    store.write_json(paths.CONFIG, current)


def secrets():
    return store.read_json(paths.SECRETS)


def save_secrets(values):
    current = secrets()
    current.update({k: v for k, v in values.items() if k in SECRET_KEYS})
    store.write_json(paths.SECRETS, current)
    if "cloudflare_token" in values:
        write_cloudflare_ini(values["cloudflare_token"])


def write_cloudflare_ini(token):
    store.write_private(paths.CLOUDFLARE_INI, f"dns_cloudflare_api_token = {token}\n")


def ise_host(cfg):
    return cfg.get("ise_host") or cfg.get("domain")


def missing(cfg=None, secret=None):
    """Return human-readable names of settings required before automation can run."""
    cfg = cfg or load()
    secret = secret if secret is not None else secrets()
    required = [
        ("domain", "Certificate hostname"),
        ("acme_email", "ACME account email"),
        ("node", "ISE node name"),
        ("username", "ISE API username"),
    ]
    out = [label for key, label in required if not cfg.get(key)]
    if not secret.get("ise_password"):
        out.append("ISE API password")
    if not secret.get("cloudflare_token"):
        out.append("Cloudflare API token")
    return out


# Validation. Each function accepts a form-like mapping and returns clean values
# or raises ValueError with a message suitable for display.

def _text(form, key, limit=128, required=True, label=None):
    value = (form.get(key) or "").strip()
    if required and not value:
        raise ValueError(f"{label or key} is required.")
    if len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError(f"{label or key} contains unsupported characters or is too long.")
    return value


def _int(form, key, low, high, label):
    try:
        value = int(form.get(key, ""))
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a whole number.") from None
    if not low <= value <= high:
        raise ValueError(f"{label} must be between {low} and {high}.")
    return value


def _flag(form, key):
    return str(form.get(key, "")).lower() in ("1", "on", "true", "yes")


def hostname(value, label="Hostname"):
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or not _HOSTNAME.fullmatch(value):
        raise ValueError(f"{label} must be a fully qualified DNS name without a scheme or port.")
    return value


def fingerprint(value):
    value = re.sub(r"[\s:]", "", value or "").lower()
    if value and not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("SHA-256 fingerprints contain 64 hexadecimal characters.")
    return value


def validate_certificate(form):
    email = _text(form, "acme_email", 254, label="ACME account email")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter a valid ACME account email.")
    key_type = form.get("key_type", "rsa2048")
    if key_type not in KEY_TYPES:
        raise ValueError("Choose a supported key type.")
    clean = {
        "domain": hostname(_text(form, "domain", 253, label="Certificate hostname"), "Certificate hostname"),
        "acme_email": email,
        "key_type": key_type,
        "renew_days": _int(form, "renew_days", 7, 60, "Renewal threshold"),
        "dns_propagation": _int(form, "dns_propagation", 10, 600, "DNS propagation wait"),
    }
    token = (form.get("cloudflare_token") or "").strip()
    if token and not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", token):
        raise ValueError("The Cloudflare API token format is not recognised.")
    return clean, ({"cloudflare_token": token} if token else {})


def validate_ise(form):
    host = (form.get("ise_host") or "").strip()
    node = _text(form, "node", 63, label="ISE node name")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", node):
        raise ValueError("ISE node name may contain letters, digits, dots, hyphens and underscores.")
    username = _text(form, "username", 128, label="API username")
    if ":" in username:
        raise ValueError("API username cannot contain a colon.")
    clean = {
        "ise_host": hostname(host, "ISE API host") if host else "",
        "ise_port": _int(form, "ise_port", 1, 65535, "ISE API port"),
        "node": node,
        "username": username,
        "deploy_admin": _flag(form, "deploy_admin"),
        "deploy_portal": _flag(form, "deploy_portal"),
        "portal_tag": _text(form, "portal_tag", 128, required=_flag(form, "deploy_portal"), label="Portal group tag"),
        "eap_fingerprint": fingerprint(form.get("eap_fingerprint", "")),
        "verify_minutes": _int(form, "verify_minutes", 5, 90, "Verification timeout"),
        "remove_superseded": _flag(form, "remove_superseded"),
    }
    if not (clean["deploy_admin"] or clean["deploy_portal"]):
        raise ValueError("Select at least one ISE role to deploy.")
    secret = {}
    password = form.get("ise_password") or ""
    if password:
        if len(password) > 256 or "\x00" in password:
            raise ValueError("ISE API password is too long.")
        secret["ise_password"] = password
    ca_pem = (form.get("ise_ca_pem") or "").strip()
    if ca_pem and "-----BEGIN CERTIFICATE-----" not in ca_pem:
        raise ValueError("Trusted CA must be one or more PEM certificates.")
    return clean, secret, ca_pem


def validate_schedule(form):
    tz = _text(form, "timezone", 64, label="Timezone")
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError("Use an IANA timezone such as America/Chicago or Europe/London.") from None
    start, end = form.get("window_start", ""), form.get("window_end", "")
    if not (_TIME.fullmatch(start) and _TIME.fullmatch(end)):
        raise ValueError("Window times use 24-hour HH:MM format.")
    if start == end:
        raise ValueError("Window start and end must differ.")
    getter = getattr(form, "getlist", None)
    raw_days = getter("weekdays") if getter else form.get("weekdays", [])
    try:
        days = sorted({int(d) for d in raw_days})
    except (TypeError, ValueError):
        raise ValueError("Invalid weekday selection.") from None
    if not days or any(d not in range(7) for d in days):
        raise ValueError("Select at least one day for the maintenance window.")
    return {
        "schedule_enabled": _flag(form, "schedule_enabled"),
        "timezone": tz,
        "window_start": start,
        "window_end": end,
        "weekdays": days,
        "retry_minutes": _int(form, "retry_minutes", 10, 240, "Retry interval"),
        "max_attempts": _int(form, "max_attempts", 1, 10, "Attempts per window"),
    }


def validate_notifications(form):
    level = form.get("notify_on", "failure")
    if level not in NOTIFY_LEVELS:
        raise ValueError("Choose when to send notifications.")
    secret = {}
    url = (form.get("webhook_url") or "").strip()
    if url:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or len(url) > 2048:
            raise ValueError("The webhook URL must be an https:// address.")
        secret["webhook_url"] = url
    if _flag(form, "clear_webhook"):
        secret["webhook_url"] = ""
    return {"notify_on": level}, secret
