import pytest
from werkzeug.datastructures import MultiDict

from ise_cert_utility import config, paths


def test_certificate_validation():
    clean, secret = config.validate_certificate({
        "domain": "ISE.Example.NET.", "acme_email": "pki@example.net", "key_type": "ecdsa256",
        "renew_days": "30", "dns_propagation": "60", "cloudflare_token": "abcDEF_123-abcdefghijklmn"})
    assert clean["domain"] == "ise.example.net"
    assert secret == {"cloudflare_token": "abcDEF_123-abcdefghijklmn"}


@pytest.mark.parametrize("domain", ["https://ise.example.net", "ise", "ise.example.net:443", "-bad.example.net"])
def test_rejects_bad_hostnames(domain):
    with pytest.raises(ValueError):
        config.validate_certificate({"domain": domain, "acme_email": "a@b.co", "key_type": "rsa2048",
                                     "renew_days": "30", "dns_propagation": "30"})


def test_ise_requires_a_role():
    form = {"node": "ise-01", "username": "api", "ise_port": "443", "verify_minutes": "30", "portal_tag": "x"}
    with pytest.raises(ValueError, match="role"):
        config.validate_ise(form)
    clean, secret, ca = config.validate_ise({**form, "deploy_admin": "on", "ise_password": "pw",
                                             "eap_fingerprint": "AA:" * 31 + "AA"})
    assert clean["deploy_admin"] and not clean["deploy_portal"]
    assert clean["eap_fingerprint"] == "aa" * 32
    assert secret == {"ise_password": "pw"}


def test_schedule_weekdays_from_multidict():
    form = MultiDict([("timezone", "Europe/London"), ("window_start", "22:00"), ("window_end", "01:00"),
                      ("weekdays", "0"), ("weekdays", "4"), ("retry_minutes", "30"), ("max_attempts", "3"),
                      ("schedule_enabled", "on")])
    clean = config.validate_schedule(form)
    assert clean["weekdays"] == [0, 4] and clean["schedule_enabled"]
    with pytest.raises(ValueError, match="timezone"):
        config.validate_schedule(MultiDict({**form.to_dict(), "timezone": "Mars/Base"}))


def test_secrets_are_private_and_cloudflare_ini_written():
    config.save_secrets({"cloudflare_token": "tok_" + "x" * 30, "ignored": "nope"})
    assert "ignored" not in config.secrets()
    assert paths.CLOUDFLARE_INI.read_text() == "dns_cloudflare_api_token = tok_" + "x" * 30 + "\n"
    assert oct(paths.SECRETS.stat().st_mode & 0o777) == "0o600"
    assert oct(paths.CLOUDFLARE_INI.stat().st_mode & 0o777) == "0o600"


def test_missing_lists_required_settings():
    assert "Cloudflare API token" in config.missing()
    assert "Certificate hostname" in config.missing()
