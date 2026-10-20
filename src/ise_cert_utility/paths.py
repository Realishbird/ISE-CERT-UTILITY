"""Filesystem layout. Both roots can be overridden for development and tests."""
import os
from pathlib import Path

ETC = Path(os.environ.get("ISE_CERT_UTILITY_ETC", "/etc/ise-cert-utility"))
VAR = Path(os.environ.get("ISE_CERT_UTILITY_VAR", "/var/lib/ise-cert-utility"))

# Configuration (ConfigurationDirectory=)
CONFIG = ETC / "config.json"
SECRETS = ETC / "secrets.json"
CLOUDFLARE_INI = ETC / "cloudflare.ini"
ISE_CA = ETC / "ise-trusted-ca.pem"
TLS_CERT = ETC / "tls" / "console.crt"
TLS_KEY = ETC / "tls" / "console.key"
WEB_SECRET = ETC / "web-secret"
AUTH = ETC / "auth.json"

# Runtime state (StateDirectory=)
ACME = VAR / "acme"
JOB = VAR / "job.json"
JOB_LOG = VAR / "job.log"
HISTORY = VAR / "history.json"
ATTEMPTS = VAR / "login-attempts.json"
SCHEDULER = VAR / "scheduler.json"
PENDING = VAR / "pending-import.json"
ISE_STATE = VAR / "ise-state.json"
CHAIN_EXPORT = VAR / "ca-chain"
LOCK = VAR / "control.lock"
DEPLOY_LOCK = VAR / "deploy.lock"

SYSTEM_CA_BUNDLE = Path(os.environ.get("ISE_CERT_UTILITY_SYSTEM_CA", "/etc/ssl/certs/ca-certificates.crt"))


def live_dir(domain):
    return ACME / "config" / "live" / domain
