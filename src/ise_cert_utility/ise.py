"""Cisco ISE OpenAPI client and deployment workflow.

Only the documented certificate endpoints under /api/v1/certs are used. The
OpenAPI service must be enabled on the PAN (Administration > System >
Settings > API Settings).
"""
import base64
import json
import os
import re
import secrets
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

from . import certs, config, paths, store

NAME_PREFIX = "ise-cert-utility "
LEGACY_PREFIXES = ("ACME Admin Portal ",)
SAFE_MESSAGE = re.compile(r"[A-Za-z0-9 .,;:()'/_-]{1,300}")


class ApiRejected(RuntimeError):
    """ISE refused the request (HTTP 4xx); nothing was changed."""


class Client:
    def __init__(self, host, port, username, password, ca_file=None, timeout=90):
        self.base = f"https://{host}" + ("" if port == 443 else f":{port}")
        self.timeout = timeout
        self.auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.context = ssl.create_default_context()
        if ca_file and os.path.exists(ca_file):
            self.context.load_verify_locations(cafile=ca_file)

    @classmethod
    def from_config(cls, cfg, secret):
        from .config import ise_host
        return cls(ise_host(cfg), cfg["ise_port"], cfg["username"], secret.get("ise_password", ""),
                   ca_file=str(paths.ISE_CA))

    def request(self, method, path, body=None):
        req = urllib.request.Request(self.base + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": self.auth, "Accept": "application/json",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.context) as response:
                data = response.read()
                return json.loads(data) if data else {}
        except urllib.error.HTTPError as exc:
            # Only short, plain messages are surfaced; bodies may echo submitted data.
            message = ""
            try:
                candidate = json.loads(exc.read()).get("response", {}).get("message", "")
                if isinstance(candidate, str) and SAFE_MESSAGE.fullmatch(candidate):
                    message = f": {candidate}"
            except (ValueError, AttributeError, TypeError):
                pass
            if exc.code == 401:
                raise ApiRejected("ISE rejected the API credentials (HTTP 401). The account needs the "
                                  "ERS Admin or Super Admin role and OpenAPI must be enabled.") from None
            if 400 <= exc.code < 500:
                raise ApiRejected(f"ISE rejected the request: HTTP {exc.code}{message}") from None
            raise RuntimeError(f"ISE returned HTTP {exc.code}{message}; check the ISE API audit log.") from None
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise RuntimeError(f"Could not verify the ISE API certificate ({reason.verify_message}). Add the "
                                   "CA that issued the current ISE admin certificate under ISE connection "
                                   "settings.") from None
            raise RuntimeError(f"Could not reach the ISE API at {self.base}: {reason}") from None
        except TimeoutError:
            raise RuntimeError(f"The ISE API at {self.base} did not respond within {self.timeout} seconds.") from None

    def paged(self, path, size=100, limit=50):
        rows = []
        for page in range(1, limit + 1):
            sep = "&" if "?" in path else "?"
            result = self.request("GET", f"{path}{sep}page={page}&size={size}")
            batch = result.get("response")
            if not isinstance(batch, list):
                raise RuntimeError("Unexpected ISE API response: expected a list of certificates.")
            rows.extend(batch)
            if not result.get("nextPage") or not batch:
                return rows
        raise RuntimeError("ISE returned more pages than expected; aborting to avoid an unbounded loop.")

    def system_certificates(self, node):
        return self.paged("/api/v1/certs/system-certificate/" + urllib.parse.quote(node, safe=""))

    def trusted_certificates(self):
        return self.paged("/api/v1/certs/trusted-certificate")


def roles(row):
    return {r.strip() for r in (row.get("usedBy") or "").split(",") if r.strip() and r.strip() != "Not in use"}


def wanted_roles(cfg):
    return ({"Admin"} if cfg["deploy_admin"] else set()) | ({"Portal"} if cfg["deploy_portal"] else set())


def row_fingerprint(row):
    return certs.clean_fingerprint(row.get("sha256Fingerprint", ""))


def eap_fingerprints(rows):
    return sorted(row_fingerprint(r) for r in rows if "EAP Authentication" in roles(r))


def assigned(cfg, rows, fingerprint):
    for row in rows:
        if row_fingerprint(row) != fingerprint or not wanted_roles(cfg) <= roles(row):
            continue
        if cfg["deploy_portal"] and row.get("groupTag") != cfg["portal_tag"]:
            continue
        return True
    return False


def record_state(cfg, rows, fingerprint):
    admin = [row_fingerprint(r) for r in rows if "Admin" in roles(r)]
    store.write_json(paths.ISE_STATE, {
        "checked_at": time.time(),
        "node": cfg["node"],
        "deployed": assigned(cfg, rows, fingerprint),
        "admin_fingerprint": admin[0] if admin else "",
        "eap_fingerprints": eap_fingerprints(rows),
    })


def preflight(cfg, client, log, import_chain=False):
    """Validate the local certificate and the ISE side. Read-only unless import_chain."""
    names = config.cert_names(cfg)
    leaf, intermediates, root = certs.verify_lineage(cfg["domain"], names=names)
    fingerprint = certs.fingerprint(leaf)
    extra = f" (+{len(names) - 1} more {'name' if len(names) == 2 else 'names'})" if len(names) > 1 else ""
    log(f"Local certificate OK: {cfg['domain']}{extra}, SHA-256 {fingerprint[:16]}..., "
        f"expires {leaf.not_valid_after_utc:%Y-%m-%d}.")
    _export_chain(intermediates, root)

    rows = client.system_certificates(cfg["node"])
    log(f"Connected to ISE API; node {cfg['node']} has {len(rows)} system certificates.")
    eap = eap_fingerprints(rows)
    if cfg.get("eap_fingerprint") and eap != [cfg["eap_fingerprint"]]:
        raise RuntimeError("The EAP certificate on ISE does not match the pinned fingerprint. "
                           "Review the EAP assignment before deploying.")
    _ensure_chain(client, intermediates + [root], import_chain, log)
    record_state(cfg, rows, fingerprint)
    return leaf, rows


def _export_chain(intermediates, root):
    paths.CHAIN_EXPORT.mkdir(mode=0o700, parents=True, exist_ok=True)
    for i, cert in enumerate(intermediates, 1):
        store.write_private(paths.CHAIN_EXPORT / f"intermediate-{i}.pem", certs.to_pem(cert))
    store.write_private(paths.CHAIN_EXPORT / "root.pem", certs.to_pem(root))


def _ensure_chain(client, cas, import_chain, log):
    known = {row_fingerprint(r) for r in client.trusted_certificates()}
    missing = [c for c in reversed(cas) if certs.fingerprint(c) not in known]
    if not missing:
        log("ISE already trusts the issuing CA chain.")
        return
    names = ", ".join(certs.describe(c)["subject"] for c in missing)
    if not import_chain:
        raise RuntimeError(f"ISE does not trust: {names}. Run 'Import CA chain' first.")
    for cert in missing:
        if not certs.is_ca(cert):
            raise RuntimeError("Refusing to import a certificate that is not a CA.")
        fp = certs.fingerprint(cert)
        log(f"Importing trusted CA {certs.describe(cert)['subject']} (SHA-256 {fp[:16]}...).")
        client.request("POST", "/api/v1/certs/trusted-certificate/import", {
            "name": f"{NAME_PREFIX}CA {fp[:16]}",
            "description": "Public CA chain imported by ise-cert-utility",
            "data": certs.to_pem(cert),
            "allowBasicConstraintCAFalse": False, "allowOutOfDateCert": False,
            "allowSHA1Certificates": False, "validateCertificateExtensions": True,
            "trustForIseAuth": True, "trustForClientAuth": False,
            "trustForCertificateBasedAdminAuth": False, "trustForCiscoServicesAuth": False,
        })
    known = {row_fingerprint(r): r for r in client.trusted_certificates()}
    for cert in missing:
        row = known.get(certs.fingerprint(cert))
        if not row or row.get("status", "Enabled") != "Enabled":
            raise RuntimeError("A CA import could not be verified; check the ISE API audit log.")
    log("CA chain imported and verified. No system certificate assignments changed.")


def _encrypted_key(domain, password):
    # PKCS#8 with PBES2/AES-256-CBC, the format ISE accepts for system certificate import.
    return subprocess.run(
        ["openssl", "pkcs8", "-topk8", "-v2", "aes-256-cbc",
         "-in", str(paths.live_dir(domain) / "privkey.pem"), "-passout", "env:ISE_KEY_PASSWORD"],
        env={**os.environ, "ISE_KEY_PASSWORD": password},
        capture_output=True, check=True, timeout=30).stdout.decode()


def deploy(cfg, client, log, may_import=lambda: True, poll_seconds=30):
    """Import the current certificate for the configured roles and verify the result."""
    leaf, rows = preflight(cfg, client, log, import_chain=True)
    fingerprint = certs.fingerprint(leaf)
    if assigned(cfg, rows, fingerprint):
        paths.PENDING.unlink(missing_ok=True)
        log("ISE already serves the current certificate. No import or restart needed.")
        return "unchanged"
    pending = store.read_json(paths.PENDING)
    if pending:
        raise RuntimeError("A previous import was never verified. Confirm the certificate state in ISE, "
                           "then clear the pending import from the Operations page.")
    if not may_import():
        log("The maintenance window closed before the import step. Deployment deferred.")
        return "deferred"

    eap_before = eap_fingerprints(rows)
    key_password = secrets.token_urlsafe(24)
    role_names = " + ".join(sorted(wanted_roles(cfg)))
    body = {
        "admin": cfg["deploy_admin"], "portal": cfg["deploy_portal"],
        "eap": False, "ims": False, "pxgrid": False, "radius": False, "saml": False,
        "name": f"{NAME_PREFIX}{fingerprint[:16]}",
        "data": certs.to_pem(leaf),
        "privateKeyData": _encrypted_key(cfg["domain"], key_password),
        "password": key_password,
        "allowOutOfDateCert": False, "allowSHA1Certificates": False, "allowExtendedValidity": False,
        "allowWildCardCertificates": False, "allowReplacementOfCertificates": True,
        "allowRoleTransferForSameSubject": False, "allowPortalTagTransferForSameSubject": False,
        # Hostname, dates, serverAuth and the chain were verified locally. ISE's optional
        # extension validator rejects serverAuth-only public certificates.
        "validateCertificateExtensions": False,
    }
    if cfg["deploy_portal"]:
        body["portalGroupTag"] = cfg["portal_tag"]
        body["allowReplacementOfPortalGroupTag"] = True

    store.write_json(paths.PENDING, {"fingerprint": fingerprint, "started": time.time(), "roles": role_names})
    restart = " ISE application services will restart." if cfg["deploy_admin"] else ""
    log(f"Importing certificate for {role_names}.{restart}")
    try:
        client.request("POST", "/api/v1/certs/system-certificate/import", body)
    except ApiRejected:
        paths.PENDING.unlink(missing_ok=True)
        raise
    except Exception as exc:  # noqa: BLE001 - a restart can cut off a successful response
        log(f"The import response was interrupted ({type(exc).__name__}); verifying before any retry.")

    # Never POST twice: an Admin import restarts ISE and can drop a successful response.
    deadline = time.monotonic() + cfg["verify_minutes"] * 60
    while time.monotonic() < deadline:
        time.sleep(poll_seconds)
        try:
            rows = client.system_certificates(cfg["node"])
        except (ApiRejected, RuntimeError, OSError) as exc:
            log(f"ISE not ready yet ({str(exc)[:80]}); waiting.")
            continue
        if not assigned(cfg, rows, fingerprint):
            continue
        if eap_fingerprints(rows) != eap_before:
            raise RuntimeError("The new certificate is installed but the EAP assignment changed. Review ISE now.")
        paths.PENDING.unlink(missing_ok=True)
        record_state(cfg, rows, fingerprint)
        log(f"Verified: ISE serves the new certificate for {role_names}; EAP assignment unchanged.")
        if cfg.get("remove_superseded"):
            remove_superseded(cfg, client, rows, fingerprint, log)
        return "deployed"
    raise RuntimeError(f"The import was not verified within {cfg['verify_minutes']} minutes. "
                       "The pending marker is kept; check ISE before retrying.")


def remove_superseded(cfg, client, rows, fingerprint, log):
    """Delete unused system certificates this utility imported earlier on this node."""
    for row in rows:
        name = row.get("friendlyName") or ""
        if not name.startswith((NAME_PREFIX,) + LEGACY_PREFIXES):
            continue
        if row_fingerprint(row) == fingerprint or roles(row) or not row.get("id"):
            continue
        try:
            client.request("DELETE", "/api/v1/certs/system-certificate/"
                           f"{urllib.parse.quote(cfg['node'], safe='')}/{urllib.parse.quote(row['id'], safe='')}")
            log(f"Removed superseded certificate '{name}'.")
        except (ApiRejected, RuntimeError) as exc:
            log(f"Could not remove '{name}': {exc}")
