import pytest

from ise_cert_utility import certs, ise, paths, store

EAP_FP = "e" * 64


class FakeIse:
    """In-memory stand-in for the ISE OpenAPI certificate endpoints."""

    def __init__(self, trusted=(), fail_import=None, eap_after=None, page_size=2):
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

    def request(self, method, path, body=None):
        self.calls.append((method, path.split("?")[0]))
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


def test_check_before_first_issue(configured):
    cfg = {**configured, "domain": "new.example.net"}
    leaf, rows = ise.preflight(cfg, FakeIse(), print, allow_missing=True)
    assert leaf is None and len(rows) == 3
    with pytest.raises(RuntimeError, match="pinned"):
        ise.preflight({**cfg, "eap_fingerprint": "c" * 64}, FakeIse(), print, allow_missing=True)
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
