"""Let's Encrypt issuance through Certbot with the Cloudflare DNS-01 plugin."""
import json
import os
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import certs, config, paths

CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"


def certbot_binary():
    override = os.environ.get("ISE_CERT_UTILITY_CERTBOT")
    if override:
        return override
    bundled = Path(sys.executable).with_name("certbot")
    return str(bundled) if bundled.exists() else (shutil.which("certbot") or "certbot")


def certbot_args(cfg, force=False, dry_run=False):
    key_type, key_param = config.KEY_TYPES[cfg["key_type"]]
    args = [
        certbot_binary(), "certonly",
        "--non-interactive", "--agree-tos",
        "--email", cfg["acme_email"],
        "--config-dir", str(paths.ACME / "config"),
        "--work-dir", str(paths.ACME / "work"),
        "--logs-dir", str(paths.ACME / "logs"),
        "--dns-cloudflare",
        "--dns-cloudflare-credentials", str(paths.CLOUDFLARE_INI),
        "--dns-cloudflare-propagation-seconds", str(cfg["dns_propagation"]),
        "--cert-name", cfg["domain"],
        "-d", cfg["domain"],
        "--key-type", key_type,
    ]
    args += ["--rsa-key-size", key_param] if key_type == "rsa" else ["--elliptic-curve", key_param]
    if dry_run:
        args.append("--dry-run")
    elif force:
        args.append("--force-renewal")
    else:
        args.append("--keep-until-expiring")
    return args


def renewal_decision(cfg, force=False):
    """Return (should_run, force_flag, reason)."""
    current = certs.info(cfg["domain"])
    if not current.get("present"):
        return True, False, "No certificate is present; requesting a new one."
    if current.get("error"):
        return True, True, "The existing certificate is unreadable; requesting a replacement."
    if force:
        return True, True, "Renewal forced by operator."
    key_type, key_param = config.KEY_TYPES[cfg["key_type"]]
    wanted = f"RSA {key_param}" if key_type == "rsa" else f"ECDSA {key_param}"
    if current["key"] != wanted:
        return True, True, f"Key type changed from {current['key']} to {wanted}; replacing the certificate."
    if current["days"] <= cfg["renew_days"]:
        return True, True, f"Certificate expires in {current['days']} days (threshold {cfg['renew_days']})."
    return False, False, f"Certificate is valid for {current['days']} more days; renewal not due."


def _cloudflare(path, token):
    request = urllib.request.Request(CLOUDFLARE_API + path, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read())
            detail = "; ".join(e.get("message", "") for e in body.get("errors", []))
        except (ValueError, AttributeError):
            detail = ""
        raise RuntimeError(f"Cloudflare returned HTTP {exc.code}{': ' + detail if detail else ''}") from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not reach the Cloudflare API: {getattr(exc, 'reason', exc)}") from None


def test_cloudflare(token, domain):
    """Verify the token is active and can see the zone that hosts domain."""
    result = _cloudflare("/user/tokens/verify", token)
    if not result.get("success") or result.get("result", {}).get("status") != "active":
        raise RuntimeError("Cloudflare reports the token is not active.")
    if not domain:
        return "Token is active. Save a certificate hostname to check zone access."
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        zones = _cloudflare("/zones?" + urllib.parse.urlencode({"name": candidate}), token)
        if zones.get("result"):
            return f"Token is active and can access the zone {candidate}."
    raise RuntimeError(f"Token is active but no Cloudflare zone for {domain} is visible to it. "
                       "Grant Zone:DNS:Edit and Zone:Zone:Read on that zone.")
