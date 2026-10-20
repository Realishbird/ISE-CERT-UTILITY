import re

import pytest

from ise_cert_utility import acme, certs, config, jobs, paths, store, web


def test_log_scrubs_secrets_and_keys(configured):
    log = jobs.Log()
    log("token cf_token_value_123456789 password ise-secret-password")
    log("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----")
    text = paths.JOB_LOG.read_text()
    assert "cf_token_value" not in text and "ise-secret-password" not in text and "abc" not in text


def test_log_run_hides_key_blocks(configured):
    log = jobs.Log()
    log.run(["printf", "ok\\n-----BEGIN EC PRIVATE KEY-----\\nsecret\\n-----END EC PRIVATE KEY-----\\ndone\\n"])
    text = paths.JOB_LOG.read_text()
    assert "ok" in text and "done" in text and "secret" not in text


def test_failed_job_is_recorded(configured):
    config.save({"acme_email": ""})
    job = jobs.start("check", spawn=False)
    result = jobs.work(job["id"])
    assert result["state"] == "failed" and "ACME account email" in result["message"]
    assert jobs.history()[0]["id"] == job["id"]


def test_single_job_at_a_time(configured):
    jobs.start("check", spawn=False)
    store.write_json(paths.JOB, {**store.read_json(paths.JOB), "pid": 1})
    with pytest.raises(ValueError, match="already running"):
        jobs.start("check", spawn=False)


def test_renewal_decision(configured):
    cfg = {**configured, "key_type": "ecdsa256"}  # the fixture certificate is P-256
    run, force, reason = acme.renewal_decision(cfg)
    assert not run and "not due" in reason
    run, force, _ = acme.renewal_decision({**cfg, "renew_days": 120})
    assert run and force
    run, _, reason = acme.renewal_decision({**configured, "key_type": "rsa2048"})
    assert run and "Key type changed" in reason


def test_certbot_arguments_use_private_dirs(configured):
    args = acme.certbot_args(configured, dry_run=True)
    assert "--dry-run" in args and str(paths.CLOUDFLARE_INI) in args
    assert args[args.index("--config-dir") + 1].startswith(str(paths.ACME))


def csrf(client, path="/login"):
    page = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf(?:-token)?" (?:value|content)="([^"]+)"', page).group(1)


def login(client):
    token = csrf(client)
    return client.post("/login", data={"csrf": token, "username": "admin", "password": "correct horse battery"},
                       base_url="https://localhost")


def test_requires_login(client):
    assert client.get("/").status_code == 302
    assert client.get("/api/status").status_code == 401


def test_login_and_pages(client):
    assert login(client).status_code == 302
    for path in ("/", "/activity", "/certificate", "/settings", "/account"):
        response = client.get(path, base_url="https://localhost")
        assert response.status_code == 200, path
        body = response.get_data(as_text=True)
        assert "ise-secret-password" not in body and "cf_token_value" not in body
    status = client.get("/api/status", base_url="https://localhost").get_json()
    assert status["certificate"]["present"]


def test_post_without_csrf_rejected(client):
    login(client)
    response = client.post("/api/settings/schedule", data={}, base_url="https://localhost")
    assert response.status_code == 403


def test_settings_save(client):
    login(client)
    token = csrf(client, "/settings")
    response = client.post("/api/settings/schedule", base_url="https://localhost", headers={"X-CSRF-Token": token},
                           data={"timezone": "UTC", "window_start": "01:00", "window_end": "03:00",
                                 "weekdays": ["1", "3"], "retry_minutes": "20", "max_attempts": "2",
                                 "schedule_enabled": "on"})
    assert response.status_code == 200, response.get_json()
    assert config.load()["weekdays"] == [1, 3]


def test_lockout_after_failures(client):
    for _ in range(web.MAX_FAILURES):
        token = csrf(client)
        client.post("/login", data={"csrf": token, "username": "admin", "password": "wrong"},
                    base_url="https://localhost")
    token = csrf(client)
    response = client.post("/login", data={"csrf": token, "username": "admin", "password": "correct horse battery"},
                           base_url="https://localhost")
    assert response.status_code == 429


def test_intermediates_listed_with_ise_trust(client):
    yr1 = certs.letsencrypt_intermediates("rsa")[0]
    store.write_json(paths.ISE_STATE, {"checked_at": 1, "trusted_fingerprints": [yr1["fingerprint"]]})
    login(client)
    body = client.get("/certificate", base_url="https://localhost").get_data(as_text=True)
    assert "YR1" in body and "YR3" in body and "YE1" not in body
    assert body.count("Not trusted by ISE") == 2 and "Trusted by ISE" in body
    token = csrf(client, "/certificate")
    response = client.post("/download/ca-yr2", data={"csrf": token}, base_url="https://localhost")
    assert response.status_code == 200 and b"BEGIN CERTIFICATE" in response.data
    assert client.post("/download/ca-zz9", data={"csrf": token}, base_url="https://localhost").status_code == 404
