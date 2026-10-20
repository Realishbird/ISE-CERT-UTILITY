"""Additional DNS names (subject alternative names) on the issued certificate."""
import pytest
from conftest import write_lineage
from test_jobs_web import csrf, login

from ise_cert_utility import acme, certs, config, jobs

PRIMARY = "ise.example.net"


def test_extra_names_are_normalised():
    names = config.extra_names("Guest.Example.NET.\n sponsor.example.net, *.portal.example.org", PRIMARY)
    assert names == ["guest.example.net", "sponsor.example.net", "*.portal.example.org"]
    assert config.extra_names("", PRIMARY) == []


@pytest.mark.parametrize("value, message", [
    ("ise.example.net", "already the certificate hostname"),
    ("guest.example.net\nGUEST.example.net", "more than once"),
    ("*.example.net", "covered by"),
    ("*.portal.example.net a.portal.example.net", "covered by"),
    ("https://guest.example.net", "fully qualified"),
    ("guest", "fully qualified"),
    ("*", "fully qualified"),
    ("a.*.example.net", "fully qualified"),
])
def test_extra_names_rejected(value, message):
    with pytest.raises(ValueError, match=message):
        config.extra_names(value, PRIMARY)


def test_extra_names_limit():
    config.extra_names([f"n{i}.example.net" for i in range(config.MAX_NAMES - 1)], PRIMARY)
    with pytest.raises(ValueError, match="at most"):
        config.extra_names([f"n{i}.example.net" for i in range(config.MAX_NAMES)], PRIMARY)


def test_wildcard_apex_is_not_redundant():
    assert config.extra_names("*.example.net\nexample.net", "ise.corp.example.org") == ["*.example.net",
                                                                                          "example.net"]


def test_primary_hostname_cannot_be_wildcard():
    with pytest.raises(ValueError):
        config.validate_certificate({"domain": "*.example.net", "acme_email": "a@b.co", "key_type": "rsa2048",
                                     "renew_days": "30", "dns_propagation": "30"})


def test_validate_certificate_includes_names():
    clean, _ = config.validate_certificate({
        "domain": PRIMARY, "extra_names": "guest.example.net", "acme_email": "a@b.co", "key_type": "rsa2048",
        "renew_days": "30", "dns_propagation": "30"})
    assert clean["extra_names"] == ["guest.example.net"]
    assert config.cert_names(clean) == [PRIMARY, "guest.example.net"]
    assert config.cert_names({"domain": "", "extra_names": ["x.example.net"]}) == []


def test_certbot_requests_every_name(configured):
    cfg = {**configured, "extra_names": ["guest.example.net", "*.portal.example.net"]}
    args = acme.certbot_args(cfg)
    requested = [args[i + 1] for i, a in enumerate(args) if a == "-d"]
    assert requested == [PRIMARY, "guest.example.net", "*.portal.example.net"]
    assert args[args.index("--cert-name") + 1] == PRIMARY


def test_name_change_forces_replacement(configured):
    cfg = {**configured, "key_type": "ecdsa256"}
    run, force, reason = acme.renewal_decision({**cfg, "extra_names": ["guest.example.net"]})
    assert run and force and "adding guest.example.net" in reason
    write_lineage(PRIMARY, [PRIMARY, "guest.example.net"])
    assert not acme.renewal_decision({**cfg, "extra_names": ["guest.example.net"]})[0]
    run, _, reason = acme.renewal_decision(cfg)
    assert run and "removing guest.example.net" in reason


def test_lineage_must_include_configured_names(configured):
    with pytest.raises(RuntimeError, match="does not include guest.example.net"):
        certs.verify_lineage(PRIMARY, names=[PRIMARY, "guest.example.net"])
    write_lineage(PRIMARY, [PRIMARY, "guest.example.net"])
    leaf, _, _ = certs.verify_lineage(PRIMARY, names=[PRIMARY, "guest.example.net"])
    assert certs.describe(leaf)["sans"] == [PRIMARY, "guest.example.net"]


@pytest.fixture
def cloudflare(monkeypatch):
    zones = {"example.net", "example.org"}
    calls = []

    def fake(path, token):
        calls.append(path)
        if path == "/user/tokens/verify":
            return {"success": True, "result": {"status": "active"}}
        name = path.split("name=", 1)[1]
        return {"result": [{"name": name}] if name in zones else []}

    monkeypatch.setattr(acme, "_cloudflare", fake)
    return calls


def test_zones_resolved_for_each_name(cloudflare):
    zones = acme.check_zones("t", [PRIMARY, "guest.example.net", "*.lab.example.org"])
    assert zones == {PRIMARY: "example.net", "guest.example.net": "example.net", "*.lab.example.org": "example.org"}
    assert cloudflare.count("/zones?name=example.net") == 1  # looked up once, then cached


def test_names_outside_cloudflare_are_reported(cloudflare):
    with pytest.raises(RuntimeError, match="other.com, x.other.com"):
        acme.check_zones("t", [PRIMARY, "other.com", "x.other.com"])
    message = acme.test_cloudflare("t", [PRIMARY, "guest.example.org"])
    assert "all 2 names" in message and "example.net, example.org" in message


def test_test_renewal_stops_when_a_zone_is_missing(configured, cloudflare, monkeypatch):
    config.save({"extra_names": ["guest.other.com"]})
    monkeypatch.setenv("ISE_CERT_UTILITY_CERTBOT", "/bin/false")
    job = jobs.work(jobs.start("test-renewal", spawn=False)["id"])
    assert job["state"] == "failed" and "guest.other.com" in job["message"]
    assert "exited with status" not in job["message"]  # stopped before Certbot ran


def test_console_saves_and_shows_names(client):
    login(client)
    token = csrf(client, "/settings")
    response = client.post("/api/settings/certificate", base_url="https://localhost",
                           headers={"X-CSRF-Token": token},
                           data={"domain": PRIMARY, "extra_names": "guest.example.net\nsponsor.example.net",
                                 "acme_email": "pki@example.net", "key_type": "ecdsa256", "renew_days": "30",
                                 "dns_propagation": "30"})
    assert response.status_code == 200, response.get_json()
    assert config.load()["extra_names"] == ["guest.example.net", "sponsor.example.net"]

    settings = client.get("/settings", base_url="https://localhost").get_data(as_text=True)
    assert "guest.example.net\nsponsor.example.net</textarea>" in settings
    overview = client.get("/", base_url="https://localhost").get_data(as_text=True)
    assert "also covering guest.example.net, sponsor.example.net." in overview
    page = client.get("/certificate", base_url="https://localhost").get_data(as_text=True)
    assert "Not yet included: guest.example.net, sponsor.example.net." in page
    status = client.get("/api/status", base_url="https://localhost").get_json()
    assert status["names"] == [PRIMARY, "guest.example.net", "sponsor.example.net"]


def test_console_rejects_invalid_names(client):
    login(client)
    token = csrf(client, "/settings")
    response = client.post("/api/settings/certificate", base_url="https://localhost",
                           headers={"X-CSRF-Token": token},
                           data={"domain": PRIMARY, "extra_names": "*.example.net", "acme_email": "pki@example.net",
                                 "key_type": "rsa2048", "renew_days": "30", "dns_propagation": "30"})
    assert response.status_code == 400 and "covered by" in response.get_json()["error"]
    assert config.load()["extra_names"] == []


def test_console_token_check_uses_unsaved_names(client, cloudflare):
    login(client)
    token = csrf(client, "/settings")
    response = client.post("/api/test-cloudflare", base_url="https://localhost", headers={"X-CSRF-Token": token},
                           data={"domain": PRIMARY, "extra_names": "guest.other.com"})
    assert response.status_code == 400 and "guest.other.com" in response.get_json()["error"]
