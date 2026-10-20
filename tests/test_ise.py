import pytest

from ise_cert_utility import certs, config, ise, paths, store

EAP_FP = "e" * 64


class FakeIse:
    """In-memory stand-in for the ISE OpenAPI certificate endpoints."""

    def __init__(self, trusted=(), fail_import=None, eap_after=None, page_size=2, host="ise.example.net",
                 deployment=None):
        self.host = host
        self.deployment = deployment
        self.peers = {host: self}
        self.imports = []  # shared across peers: (host, fingerprint) in import order
        self.system = [
            {"id": "1", "friendlyName": "Default self-signed", "sha256Fingerprint": "a" * 64,
             "usedBy": "Admin, Portal", "groupTag": "Default Portal Certificate Group"},
            {"id": "2", "friendlyName": "EAP", "sha256Fingerprint": EAP_FP, "usedBy": "EAP Authentication"},
            {"id": "3", "friendlyName": "ise-cert-utility 0123456789abcdef", "sha256Fingerprint": "b" * 64,
             "usedBy": "Not in use"},
        ]
        self.trusted = [{"sha256Fingerprint": fp, "status": "Enabled"} for fp in trusted]
        self.fail_import = fail_import
        self.eap_after = eap_after
        self.page_size = page_size
        self.calls = []

    def _page(self, rows, path):
        page = int(path.split("page=")[1].split("&")[0])
        chunk = rows[(page - 1) * self.page_size: page * self.page_size]
        more = page * self.page_size < len(rows)
        return {"response": chunk, **({"nextPage": {"href": "next"}} if more else {})}

    def for_host(self, host):
        if len(self.peers) == 1:
            return self
        if host not in self.peers:
            raise AssertionError(f"unexpected host {host}")
        return self.peers[host]

    def add_peer(self, host, **kwargs):
        peer = FakeIse(host=host, **kwargs)
        peer.peers = self.peers
        peer.imports = self.imports
        peer.trusted = self.trusted  # trusted certificates replicate across the deployment
        self.peers[host] = peer
        return peer

    def request(self, method, path, body=None):
        self.calls.append((method, path.split("?")[0]))
        if path == "/api/v1/deployment/node":
            if self.deployment is None:
                raise ise.ApiRejected("ISE rejected the request: HTTP 403")
            return {"response": self.deployment}
        if method == "GET" and "/system-certificate/" in path:
            return self._page(self.system, path)
        if method == "GET" and "/trusted-certificate" in path:
            return self._page(self.trusted, path)
        if path.endswith("/trusted-certificate/import"):
            fp = certs.fingerprint(certs.load_pems(body["data"].encode())[0])
            self.trusted.append({"sha256Fingerprint": fp, "status": "Enabled"})
            return {}
        if path.endswith("/system-certificate/import"):
            if self.fail_import:
                raise self.fail_import
            fp = certs.fingerprint(certs.load_pems(body["data"].encode())[0])
            self.imports.append((self.host, fp))
            for row in self.system:
                if "Admin" in row["usedBy"]:
                    row["usedBy"] = "Not in use"
            self.system.append({"id": "9", "friendlyName": body["name"], "sha256Fingerprint": fp,
                                "usedBy": "Admin, Portal", "groupTag": body["portalGroupTag"]})
            if self.eap_after:
                self.system[1]["sha256Fingerprint"] = self.eap_after
            return {"response": {"status": "ok"}}
        if method == "DELETE":
            self.system = [r for r in self.system if not path.endswith("/" + r["id"])]
            return {}
        raise AssertionError(f"unexpected call {method} {path}")

    paged = ise.Client.paged
    system_certificates = ise.Client.system_certificates
    trusted_certificates = ise.Client.trusted_certificates


@pytest.fixture(autouse=True)
def fake_key_encryption(monkeypatch):
    monkeypatch.setattr(ise, "_encrypted_key", lambda domain, password: "ENCRYPTED KEY")


def chain_fps(cfg):
    return [certs.fingerprint(cfg["intermediate"]), certs.fingerprint(cfg["root"])]


def test_pagination_collects_all_rows(configured):
    client = FakeIse(page_size=1)
    assert len(client.system_certificates("ise-01")) == 3


def test_check_requires_trusted_chain(configured):
    with pytest.raises(RuntimeError, match="does not trust"):
        ise.preflight(configured, FakeIse(), print)


def test_trust_chain_imports_root_and_intermediate(configured):
    client = FakeIse()
    ise.preflight(configured, client, print, import_chain=True)
    assert {r["sha256Fingerprint"] for r in client.trusted} == set(chain_fps(configured))


def test_deploy_imports_once_and_verifies(configured):
    client = FakeIse(trusted=chain_fps(configured))
    assert ise.deploy(configured, client, print, poll_seconds=0) == "deployed"
    imports = [c for c in client.calls if c[1].endswith("/system-certificate/import")]
    assert len(imports) == 1
    assert not paths.PENDING.exists()
    assert store.read_json(paths.ISE_STATE)["deployed"]
    # Second run is a no-op.
    assert ise.deploy(configured, client, print, poll_seconds=0) == "unchanged"


def test_interrupted_response_is_verified_not_retried(configured):
    client = FakeIse(trusted=chain_fps(configured), fail_import=ConnectionResetError())
    client_import = client.request

    def import_then_drop(method, path, body=None):
        if path.endswith("/system-certificate/import"):
            client.fail_import = None
            client_import(method, path, body)
            raise ConnectionResetError()
        return client_import(method, path, body)

    client.request = import_then_drop
    assert ise.deploy(configured, client, print, poll_seconds=0) == "deployed"


def test_rejected_import_clears_pending(configured):
    client = FakeIse(trusted=chain_fps(configured), fail_import=ise.ApiRejected("HTTP 400"))
    with pytest.raises(ise.ApiRejected):
        ise.deploy(configured, client, print, poll_seconds=0)
    assert not paths.PENDING.exists()


def test_pending_marker_blocks_second_import(configured):
    store.write_json(paths.PENDING, {"fingerprint": "x"})
    with pytest.raises(RuntimeError, match="never verified"):
        ise.deploy(configured, FakeIse(trusted=chain_fps(configured)), print, poll_seconds=0)


def test_eap_change_is_detected(configured):
    client = FakeIse(trusted=chain_fps(configured), eap_after="f" * 64)
    with pytest.raises(RuntimeError, match="EAP assignment changed"):
        ise.deploy(configured, client, print, poll_seconds=0)


def test_eap_pin_mismatch_stops_preflight(configured):
    cfg = {**configured, "eap_fingerprint": "c" * 64}
    with pytest.raises(RuntimeError, match="pinned"):
        ise.preflight(cfg, FakeIse(trusted=chain_fps(configured)), print)


def test_security_check_rejection_explains_manual_import(configured):
    class Filtered(FakeIse):
        def request(self, method, path, body=None):
            if path.endswith("/trusted-certificate/import"):
                raise ise.ApiRejected("ISE rejected the request: HTTP 400: Security Check Failed")
            return super().request(method, path, body)

    with pytest.raises(ise.ApiRejected, match="Trusted Certificates"):
        ise.preflight(configured, Filtered(), print, import_chain=True)


def test_check_before_first_issue(configured):
    cfg = {**configured, "domain": "new.example.net"}
    leaf, nodes = ise.preflight(cfg, FakeIse(), print, allow_missing=True)
    assert leaf is None and len(nodes[0]["rows"]) == 3
    with pytest.raises(RuntimeError, match="pinned"):
        ise.preflight({**cfg, "eap_fingerprints": ["c" * 64]}, FakeIse(), print, allow_missing=True)
    with pytest.raises(RuntimeError, match="No certificate"):
        ise.preflight(cfg, FakeIse(), print, import_chain=True)


def test_window_guard_defers_import(configured):
    client = FakeIse(trusted=chain_fps(configured))
    assert ise.deploy(configured, client, print, may_import=lambda: False) == "deferred"
    assert not any(c[1].endswith("/system-certificate/import") for c in client.calls)


def test_superseded_cleanup_only_removes_own_unused(configured):
    cfg = {**configured, "remove_superseded": True}
    client = FakeIse(trusted=chain_fps(configured))
    ise.deploy(cfg, client, print, poll_seconds=0)
    names = {r["friendlyName"] for r in client.system}
    assert "ise-cert-utility 0123456789abcdef" not in names
    assert "Default self-signed" in names and "EAP" in names


def test_bundled_intermediates_match_known_fingerprints():
    rsa = {i["name"]: i for i in certs.letsencrypt_intermediates("rsa")}
    assert [n for n, i in rsa.items() if i["status"] == "active"] == ["YR1", "YR2"]
    assert rsa["YR1"]["fingerprint"].startswith("13949634d99cd6fd")
    assert rsa["YR2"]["fingerprint"].startswith("238b85a0099c65b9")
    assert len(certs.letsencrypt_intermediates("ecdsa")) == 3


def test_check_records_trust_and_warns_about_missing_intermediates(configured):
    logged = []
    ise.preflight(configured, FakeIse(trusted=chain_fps(configured)), logged.append)
    state = store.read_json(paths.ISE_STATE)
    assert set(chain_fps(configured)) <= set(state["trusted_fingerprints"])
    assert any("does not trust Let's Encrypt YR1, YR2" in line for line in logged)


def test_legacy_pending_marker_still_blocks(configured):
    store.write_json(paths.PENDING, {"fingerprint": "x", "started": 1, "roles": "Admin"})
    with pytest.raises(RuntimeError, match="never verified"):
        ise.deploy(configured, FakeIse(trusted=chain_fps(configured)), print, poll_seconds=0)


# Multi-node deployments

SAN = ["ise.example.net", "*.nodes.example.net"]
DEPLOYMENT = [
    {"hostname": "pan-01", "fqdn": "pan-01.nodes.example.net", "roles": ["PrimaryAdmin", "PrimaryMonitoring"],
     "services": ["Session"], "nodeStatus": "Connected"},
    {"hostname": "psn-01", "fqdn": "psn-01.nodes.example.net", "roles": [], "services": ["Session", "Profiler"],
     "nodeStatus": "Connected"},
    {"hostname": "pan-02", "fqdn": "pan-02.nodes.example.net", "roles": ["SecondaryAdmin", "SecondaryMonitoring"],
     "services": ["Session"], "nodeStatus": "Connected"},
    {"hostname": "psn-02", "fqdn": "psn-02.nodes.example.net", "roles": [], "services": ["Session"],
     "nodeStatus": "Connected"},
]


@pytest.fixture
def cluster():
    from conftest import write_lineage
    issued = write_lineage("ise.example.net", sans=SAN)
    cfg = {**config.DEFAULTS, "domain": "ise.example.net", "extra_names": SAN[1:], "acme_email": "pki@example.net",
           "username": "api", "node_mode": "all", "key_type": "ecdsa256", **issued}
    trusted = [certs.fingerprint(issued["intermediate"]), certs.fingerprint(issued["root"])]
    pan = FakeIse(trusted=trusted, host="ise.example.net", deployment=DEPLOYMENT)
    for node in DEPLOYMENT[1:]:
        pan.add_peer(node["fqdn"])
    return cfg, pan


def test_all_nodes_updated_one_at_a_time_with_pan_last(cluster):
    cfg, pan = cluster
    logged = []
    assert ise.deploy(cfg, pan, logged.append, poll_seconds=0) == "deployed"
    order = [host for host, _ in pan.imports]
    # PSNs first in deployment order, then the secondary PAN, then the PAN through the configured API host.
    assert order == ["psn-01.nodes.example.net", "psn-02.nodes.example.net", "pan-02.nodes.example.net",
                     "ise.example.net"]
    assert any("Nodes in update order: psn-01, psn-02, pan-02, pan-01" in line for line in logged)
    state = store.read_json(paths.ISE_STATE)
    assert state["deployed"] and [n["name"] for n in state["nodes"]] == ["psn-01", "psn-02", "pan-02", "pan-01"]
    assert not paths.PENDING.exists()
    assert ise.deploy(cfg, pan, print, poll_seconds=0) == "unchanged"
    assert len(pan.imports) == 4


def test_node_list_follows_listed_names_and_host_overrides(cluster):
    cfg, pan = cluster
    pan.add_peer("psn-01.mgmt.example.net")
    cfg = {**cfg, "node_mode": "list", "extra_names": ["*.nodes.example.net", "psn-01.mgmt.example.net"],
           "nodes": [{"name": "pan-01", "host": ""}, {"name": "psn-01", "host": "psn-01.mgmt.example.net"}]}
    from conftest import write_lineage
    issued = write_lineage("ise.example.net", sans=[*SAN, "psn-01.mgmt.example.net"])
    pan.trusted[:] = [{"sha256Fingerprint": certs.fingerprint(issued[k]), "status": "Enabled"}
                      for k in ("intermediate", "root")]
    assert ise.deploy(cfg, pan, print, poll_seconds=0) == "deployed"
    assert [host for host, _ in pan.imports] == ["psn-01.mgmt.example.net", "ise.example.net"]


def test_unknown_listed_node_is_rejected(cluster):
    cfg, pan = cluster
    cfg = {**cfg, "node_mode": "list", "nodes": [{"name": "pan-01", "host": ""}, {"name": "psn-09", "host": ""}]}
    with pytest.raises(RuntimeError, match="no node named psn-09"):
        ise.preflight(cfg, pan, print)


def test_every_node_must_pass_checks_before_any_import(cluster):
    cfg, pan = cluster
    pan.peers["pan-02.nodes.example.net"].system[1]["sha256Fingerprint"] = "d" * 64
    cfg = {**cfg, "eap_fingerprints": [EAP_FP]}
    with pytest.raises(RuntimeError, match="1 of 4 nodes failed"):
        ise.deploy(cfg, pan, print, poll_seconds=0)
    assert pan.imports == []
    nodes = {n["name"]: n for n in store.read_json(paths.ISE_STATE)["nodes"]}
    assert "pinned" in nodes["pan-02"]["error"] and not nodes["psn-01"]["error"]


def test_per_node_eap_pins(cluster):
    cfg, pan = cluster
    pan.peers["psn-02.nodes.example.net"].system[1]["sha256Fingerprint"] = "d" * 64
    cfg = {**cfg, "eap_fingerprints": [EAP_FP, "d" * 64]}
    assert ise.deploy(cfg, pan, print, poll_seconds=0) == "deployed"


def test_admin_role_needs_node_host_on_certificate(cluster):
    cfg, pan = cluster
    from conftest import write_lineage
    issued = write_lineage("ise.example.net")
    pan.trusted[:] = [{"sha256Fingerprint": certs.fingerprint(issued[k]), "status": "Enabled"}
                      for k in ("intermediate", "root")]
    with pytest.raises(RuntimeError, match="does not include psn-01.nodes.example.net"):
        ise.deploy({**cfg, "extra_names": []}, pan, print, poll_seconds=0)
    assert pan.imports == []
    # Portal-only deployments do not need node names on the certificate.
    assert ise.deploy({**cfg, "extra_names": [], "deploy_admin": False}, pan, print, poll_seconds=0) == "deployed"


def test_failure_on_one_node_stops_before_the_pan(cluster):
    cfg, pan = cluster
    pan.peers["psn-02.nodes.example.net"].fail_import = ise.ApiRejected("ISE rejected the request: HTTP 400")
    with pytest.raises(ise.ApiRejected):
        ise.deploy(cfg, pan, print, poll_seconds=0)
    assert [host for host, _ in pan.imports] == ["psn-01.nodes.example.net"]
    state = {n["name"]: n for n in store.read_json(paths.ISE_STATE)["nodes"]}
    assert state["psn-01"]["deployed"] and not state["pan-01"]["deployed"]
    # The next run resumes with the nodes that still need the certificate.
    pan.peers["psn-02.nodes.example.net"].fail_import = None
    assert ise.deploy(cfg, pan, print, poll_seconds=0) == "deployed"
    assert [host for host, _ in pan.imports][1:] == ["psn-02.nodes.example.net", "pan-02.nodes.example.net",
                                                    "ise.example.net"]


def test_unverified_node_keeps_its_pending_marker(cluster):
    cfg, pan = cluster
    # The response is lost and the import never lands, so the node cannot be verified.
    pan.peers["psn-01.nodes.example.net"].fail_import = ConnectionResetError()
    with pytest.raises(RuntimeError, match="psn-01 was not verified"):
        ise.deploy({**cfg, "verify_minutes": 0}, pan, print, poll_seconds=0)
    assert set(store.read_json(paths.PENDING)["nodes"]) == {"psn-01"}
    assert pan.imports == []
    with pytest.raises(RuntimeError, match="previous import on psn-01 was never verified"):
        ise.deploy(cfg, pan, print, poll_seconds=0)
    assert pan.imports == []


def test_window_closing_between_nodes_defers_the_rest(cluster):
    cfg, pan = cluster
    budget = iter([True, True])
    assert ise.deploy(cfg, pan, print, may_import=lambda: next(budget, False), poll_seconds=0) == "deferred"
    assert len(pan.imports) == 2
    assert ise.deploy(cfg, pan, print, poll_seconds=0) == "deployed"
    assert len(pan.imports) == 4


def test_all_nodes_mode_needs_deployment_access(cluster):
    cfg, pan = cluster
    pan.deployment = None
    with pytest.raises(RuntimeError, match="Could not read the ISE deployment"):
        ise.preflight(cfg, pan, print)


def test_disconnected_node_blocks_deployment(cluster):
    cfg, pan = cluster
    pan.deployment = [*DEPLOYMENT[:3], {**DEPLOYMENT[3], "nodeStatus": "Disconnected"}]
    with pytest.raises(RuntimeError, match="psn-02 is Disconnected"):
        ise.preflight(cfg, pan, print)


def test_superseded_cleanup_runs_on_every_node(cluster):
    cfg, pan = cluster
    ise.deploy({**cfg, "remove_superseded": True}, pan, print, poll_seconds=0)
    for peer in pan.peers.values():
        assert "ise-cert-utility 0123456789abcdef" not in {r["friendlyName"] for r in peer.system}
