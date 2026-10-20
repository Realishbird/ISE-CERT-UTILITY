"""Cisco ISE OpenAPI client and deployment workflow.

Only the documented certificate endpoints under /api/v1/certs, plus the
deployment node list, are used. The OpenAPI service must be enabled
(Administration > System > Settings > API Settings).

ISE has no API to import a system certificate onto another node: the import
lands on the node that receives the request. Each node is therefore reached on
its own API host, one at a time, with the Primary Admin Node last.
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
        self.host, self.port = host, port
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

    def for_host(self, host):
        """A client for another node in the same deployment, with the same credentials and trust."""
        if host.lower() == self.host.lower():
            return self
        other = object.__new__(Client)
        other.__dict__.update(self.__dict__, host=host,
                              base=f"https://{host}" + ("" if self.port == 443 else f":{self.port}"))
        return other

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


def _node_record(cfg, node, rows, fingerprint):
    admin = [row_fingerprint(r) for r in rows if "Admin" in roles(r)]
    return {
        "name": node["name"], "host": node["host"], "roles": node.get("roles", []),
        "services": node.get("services", []), "checked_at": time.time(), "error": "",
        "deployed": bool(fingerprint) and assigned(cfg, rows, fingerprint),
        "admin_fingerprint": admin[0] if admin else "",
        "eap_fingerprints": eap_fingerprints(rows),
    }


def record_state(nodes, trusted=None, update=False):
    """Save per-node results. With update, merge into the nodes recorded by the last check."""
    state = store.read_json(paths.ISE_STATE)
    if trusted is None:
        trusted = state.get("trusted_fingerprints", [])
    known = {n["name"]: n for n in state.get("nodes", [])} if update else {}
    order = [n["name"] for n in state.get("nodes", [])] if update else []
    for record in nodes:
        known[record["name"]] = record
        if record["name"] not in order:
            order.append(record["name"])
    records = [known[name] for name in order]
    store.write_json(paths.ISE_STATE, {
        "checked_at": time.time(),
        "nodes": records,
        "deployed": bool(records) and all(r["deployed"] for r in records),
        "trusted_fingerprints": sorted(trusted),
        # Single-node fields kept for status consumers written against 2.0.
        "node": records[0]["name"] if records else "",
        "admin_fingerprint": records[0]["admin_fingerprint"] if records else "",
        "eap_fingerprints": records[0]["eap_fingerprints"] if records else [],
    })


def _report_intermediates(cfg, trusted, log):
    family = config.KEY_TYPES[cfg["key_type"]][0]
    missing = [i["name"] for i in certs.letsencrypt_intermediates(family)
               if i["status"] == "active" and i["fingerprint"] not in trusted]
    if missing:
        log(f"ISE does not trust Let's Encrypt {', '.join(missing)}. A renewal signed by "
            f"{'it' if len(missing) == 1 else 'one of them'} cannot deploy until it is imported; "
            "download it from the Certificate page.")


# Lower ranks are updated first, so the Primary Admin Node, which runs the API and
# coordinates the deployment, restarts last and only after every other node is verified.
def _rank(node):
    found = set(node.get("roles") or [])
    if "PrimaryAdmin" in found:
        return 3
    if "SecondaryAdmin" in found:
        return 2
    if found & {"PrimaryMonitoring", "SecondaryMonitoring"} and "Session" not in (node.get("services") or []):
        return 1
    return 0


def deployment_nodes(client):
    """Nodes registered in the deployment, as reported by the PAN."""
    result = client.request("GET", "/api/v1/deployment/node")
    rows = result.get("response") if isinstance(result, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError("Unexpected ISE API response: expected a list of deployment nodes.")
    nodes = []
    for row in rows:
        name = row.get("hostname") if isinstance(row, dict) else None
        if not isinstance(name, str) or not name:
            continue
        nodes.append({"name": name, "fqdn": str(row.get("fqdn") or "").lower(),
                      "roles": [r for r in row.get("roles") or [] if isinstance(r, str)],
                      "services": [s for s in row.get("services") or [] if isinstance(s, str)],
                      "status": str(row.get("nodeStatus") or "")})
    if not nodes:
        raise RuntimeError("ISE reported no nodes in the deployment.")
    return nodes


def resolve_nodes(cfg, client, log):
    """Return the nodes to update, in update order, each with the API host used to reach it."""
    listed = config.node_list(cfg)
    every = cfg.get("node_mode") == "all"
    discovered = {}
    if every or len(listed) > 1:
        try:
            discovered = {n["name"].lower(): n for n in deployment_nodes(client)}
        except (ApiRejected, RuntimeError) as exc:
            if every:
                raise RuntimeError(f"Could not read the ISE deployment ({exc}). The API account needs read access "
                                   "to Administration > Deployment, or list the nodes in Settings instead.") from None
            log(f"Could not read node roles from ISE ({str(exc)[:80]}); updating nodes in the listed order.")
    overrides = {n["name"].lower(): n["host"] for n in listed}
    if every:
        chosen = [{"name": n["name"], "host": overrides.get(key, "")} for key, n in discovered.items()]
    else:
        chosen = listed
        if discovered:
            unknown = [n["name"] for n in listed if n["name"].lower() not in discovered]
            if unknown:
                raise RuntimeError(f"ISE has no node named {', '.join(unknown)}. Use the names shown under "
                                   "Administration > System > Deployment.")
    nodes = []
    for entry in chosen:
        info = discovered.get(entry["name"].lower(), {})
        if info.get("status") and info["status"].lower() != "connected":
            raise RuntimeError(f"Node {entry['name']} is {info['status']} in the ISE deployment. "
                               "Resolve that before deploying, or remove it from the node list.")
        primary = "PrimaryAdmin" in info.get("roles", []) or len(chosen) == 1
        host = entry["host"] or (config.ise_host(cfg) if primary else "") or info.get("fqdn", "")
        if not host:
            raise RuntimeError(f"No API host is known for node {entry['name']}. Add it after the node name "
                               "in Settings, for example: psn-02 psn-02.example.com")
        nodes.append({"name": info.get("name", entry["name"]), "host": host,
                      "roles": info.get("roles", []), "services": info.get("services", [])})
    nodes.sort(key=_rank)
    if len(nodes) > 1:
        log(f"Nodes in update order: {', '.join(n['name'] for n in nodes)}.")
    return nodes


def _connect(client, node):
    return client.for_host(node["host"])


def _check_node(cfg, client, node, names, fingerprint, log):
    """Read one node's system certificates and apply the per-node safety checks."""
    node["client"] = _connect(client, node)
    rows = node["client"].system_certificates(node["name"])
    node["rows"] = rows
    log(f"Connected to ISE API; node {node['name']} has {len(rows)} system certificates.")
    _check_eap_pin(cfg, rows, node["name"])
    if fingerprint and cfg["deploy_admin"] and not config.covers(names, node["host"]):
        raise RuntimeError(f"The certificate does not include {node['host']}, so node {node['name']} cannot "
                           "use it for the Admin role. Add the name under Additional names and renew.")
    return _node_record(cfg, node, rows, fingerprint)


def preflight(cfg, client, log, import_chain=False, allow_missing=False):
    """Validate the local certificate and every target node. Read-only unless import_chain.

    Returns (leaf, nodes) with nodes in update order; each carries its API client and system certificate rows.
    With allow_missing and no certificate issued yet, checks API access and the EAP pin and returns (None, nodes).
    """
    names = config.cert_names(cfg)
    leaf = None
    fingerprint = ""
    if certs.info(cfg["domain"])["present"]:
        leaf, intermediates, root = certs.verify_lineage(cfg["domain"], names=names)
        fingerprint = certs.fingerprint(leaf)
        extra = f" (+{len(names) - 1} more {'name' if len(names) == 2 else 'names'})" if len(names) > 1 else ""
        log(f"Local certificate OK: {cfg['domain']}{extra}, SHA-256 {fingerprint[:16]}..., "
            f"expires {leaf.not_valid_after_utc:%Y-%m-%d}.")
        _export_chain(intermediates, root)
    elif not allow_missing:
        raise RuntimeError("No certificate has been issued yet. Run Renew and deploy to issue one.")

    nodes = resolve_nodes(cfg, client, log)
    records, failures = [], []
    for node in nodes:
        try:
            records.append(_check_node(cfg, client, node, names, fingerprint, log))
        except (ApiRejected, RuntimeError, OSError) as exc:
            failures.append(f"{node['name']}: {exc}")
            log(f"Node {node['name']} failed its check: {exc}")
            records.append({**_node_record(cfg, node, [], ""), "error": str(exc)[:300]})
    if leaf is None:
        trusted = {row_fingerprint(r) for r in client.trusted_certificates()}
    else:
        try:
            trusted = _ensure_chain(client, intermediates + [root], import_chain, log)
        except Exception:
            record_state(records)
            raise
    _report_intermediates(cfg, trusted, log)
    record_state(records, trusted)
    if failures:
        if len(failures) == 1 and len(nodes) == 1:
            raise RuntimeError(failures[0].split(": ", 1)[1])
        raise RuntimeError(f"{len(failures)} of {len(nodes)} nodes failed their checks, so nothing was imported. "
                           + " ".join(failures))
    if leaf is None:
        log("No certificate has been issued yet, so the issuing chain cannot be checked.")
    return leaf, nodes


def _check_eap_pin(cfg, rows, node):
    pins = config.eap_pins(cfg)
    found = eap_fingerprints(rows)
    if pins and not (len(found) == 1 and found[0] in pins):
        raise RuntimeError(f"The EAP certificate on node {node} does not match a pinned fingerprint. "
                           "Review the EAP assignment before deploying.")


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
        return known
    names = ", ".join(certs.describe(c)["subject"] for c in missing)
    if not import_chain:
        raise RuntimeError(f"ISE does not trust: {names}. Run 'Import CA chain' first.")
    for cert in missing:
        if not certs.is_ca(cert):
            raise RuntimeError("Refusing to import a certificate that is not a CA.")
        fp = certs.fingerprint(cert)
        subject = certs.describe(cert)["subject"]
        log(f"Importing trusted CA {subject} (SHA-256 {fp[:16]}...).")
        try:
            _import_trusted(client, cert, fp)
        except ApiRejected as exc:
            if "Security Check Failed" not in str(exc):
                raise
            # ISE's request filter flags the apostrophe in "Let's Encrypt"; the admin portal accepts the same file.
            raise ApiRejected(
                f"ISE's API refused to import {subject} (Security Check Failed), a known ISE false positive for "
                "names such as \"Let's Encrypt\". Download it from the Certificate page, import it in "
                "ISE under Administration > System > Certificates > Trusted Certificates with \"Trust for "
                "authentication within ISE\", then run Deploy.") from None
    known = {row_fingerprint(r): r for r in client.trusted_certificates()}
    for cert in missing:
        row = known.get(certs.fingerprint(cert))
        if not row or row.get("status", "Enabled") != "Enabled":
            raise RuntimeError("A CA import could not be verified; check the ISE API audit log.")
    log("CA chain imported and verified. No system certificate assignments changed.")
    return set(known)


def _import_trusted(client, cert, fp):
    client.request("POST", "/api/v1/certs/trusted-certificate/import", {
        "name": f"{NAME_PREFIX}CA {fp[:16]}",
        "description": "Public CA chain imported by ise-cert-utility",
        "data": certs.to_pem(cert),
        "allowBasicConstraintCAFalse": False, "allowOutOfDateCert": False,
        "allowSHA1Certificates": False, "validateCertificateExtensions": True,
        "trustForIseAuth": True, "trustForClientAuth": False,
        "trustForCertificateBasedAdminAuth": False, "trustForCiscoServicesAuth": False,
    })


def _encrypted_key(domain, password):
    # PKCS#8 with PBES2/AES-256-CBC, the format ISE accepts for system certificate import.
    return subprocess.run(
        ["openssl", "pkcs8", "-topk8", "-v2", "aes-256-cbc",
         "-in", str(paths.live_dir(domain) / "privkey.pem"), "-passout", "env:ISE_KEY_PASSWORD"],
        env={**os.environ, "ISE_KEY_PASSWORD": password},
        capture_output=True, check=True, timeout=30).stdout.decode()


def _pending():
    """Unverified imports keyed by node name. 2.0 recorded a single import without a node."""
    pending = store.read_json(paths.PENDING)
    if pending.get("fingerprint"):
        return {"": pending}
    return pending.get("nodes", {})


def _save_pending(pending):
    if pending:
        store.write_json(paths.PENDING, {"nodes": pending})
    else:
        paths.PENDING.unlink(missing_ok=True)


def deploy(cfg, client, log, may_import=lambda: True, poll_seconds=30):
    """Import the current certificate on every target node, one node at a time, verifying each."""
    leaf, nodes = preflight(cfg, client, log, import_chain=True)
    fingerprint = certs.fingerprint(leaf)
    pending = _pending()
    todo = []
    for node in nodes:
        if assigned(cfg, node["rows"], fingerprint):
            pending.pop(node["name"], None)
        else:
            todo.append(node)
    if "" in pending and len(nodes) == 1 and not todo:
        pending.pop("")
    _save_pending(pending)
    if not todo:
        log("ISE already serves the current certificate"
            + (f" on all {len(nodes)} nodes." if len(nodes) > 1 else ".") + " No import or restart needed.")
        return "unchanged"
    blocked = [n["name"] for n in todo if n["name"] in pending] or (["the configured node"] if "" in pending else [])
    if blocked:
        raise RuntimeError(f"A previous import on {', '.join(blocked)} was never verified. Confirm the certificate "
                           "state in ISE, then clear the pending import from the Operations page.")
    if len(nodes) > 1:
        current = len(nodes) - len(todo)
        log(f"{len(todo)} of {len(nodes)} nodes need the new certificate"
            + (f"; {current} already serve it." if current else "."))

    done = []
    for node in todo:
        if not may_import():
            log("The maintenance window closed before the next import. "
                + (f"Updated {', '.join(done)}; the remaining nodes follow in the next window."
                   if done else "Deployment deferred."))
            return "deferred"
        try:
            _deploy_node(cfg, node, leaf, fingerprint, log, poll_seconds)
        except Exception as exc:
            if done:
                log(f"Stopped after {node['name']} failed. Already updated: {', '.join(done)}. "
                    "Later nodes were not touched.")
                if type(exc) in (RuntimeError, ApiRejected):
                    raise type(exc)(f"{exc} Already updated: {', '.join(done)}.") from None
            raise
        done.append(node["name"])
    if cfg.get("remove_superseded"):
        for node in nodes:
            remove_superseded(cfg, node["client"], node["rows"], fingerprint, log, node["name"])
    return "deployed"


def _deploy_node(cfg, node, leaf, fingerprint, log, poll_seconds):
    client, name = node["client"], node["name"]
    eap_before = eap_fingerprints(node["rows"])
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

    # The import API has no node parameter: ISE installs the certificate on the node that receives the request.
    pending = _pending()
    pending[name] = {"fingerprint": fingerprint, "started": time.time(), "roles": role_names, "host": node["host"]}
    _save_pending(pending)
    restart = f" Application services on {name} will restart." if cfg["deploy_admin"] else ""
    log(f"Importing certificate on {name} ({node['host']}) for {role_names}.{restart}")
    try:
        client.request("POST", "/api/v1/certs/system-certificate/import", body)
    except ApiRejected:
        pending.pop(name, None)
        _save_pending(pending)
        raise
    except Exception as exc:  # noqa: BLE001 - a restart can cut off a successful response
        log(f"The import response from {name} was interrupted ({type(exc).__name__}); verifying before any retry.")

    # Never POST twice: an Admin import restarts the node and can drop a successful response.
    deadline = time.monotonic() + cfg["verify_minutes"] * 60
    while time.monotonic() < deadline:
        time.sleep(poll_seconds)
        try:
            rows = client.system_certificates(name)
        except (ApiRejected, RuntimeError, OSError) as exc:
            log(f"{name} not ready yet ({str(exc)[:80]}); waiting.")
            continue
        if not assigned(cfg, rows, fingerprint):
            continue
        if eap_fingerprints(rows) != eap_before:
            raise RuntimeError(f"The new certificate is installed on {name} but its EAP assignment changed. "
                               "Review ISE now.")
        pending = _pending()
        pending.pop(name, None)
        _save_pending(pending)
        node["rows"] = rows
        record_state([_node_record(cfg, node, rows, fingerprint)], update=True)
        log(f"Verified: {name} serves the new certificate for {role_names}; EAP assignment unchanged.")
        return
    raise RuntimeError(f"The import on {name} was not verified within {cfg['verify_minutes']} minutes. "
                       "The pending marker is kept; check ISE before retrying.")


def remove_superseded(cfg, client, rows, fingerprint, log, node):
    """Delete unused system certificates this utility imported earlier on a node."""
    for row in rows:
        name = row.get("friendlyName") or ""
        if not name.startswith((NAME_PREFIX,) + LEGACY_PREFIXES):
            continue
        if row_fingerprint(row) == fingerprint or roles(row) or not row.get("id"):
            continue
        try:
            client.request("DELETE", "/api/v1/certs/system-certificate/"
                           f"{urllib.parse.quote(node, safe='')}/{urllib.parse.quote(row['id'], safe='')}")
            log(f"Removed superseded certificate '{name}' from {node}.")
        except (ApiRejected, RuntimeError) as exc:
            log(f"Could not remove '{name}' from {node}: {exc}")
