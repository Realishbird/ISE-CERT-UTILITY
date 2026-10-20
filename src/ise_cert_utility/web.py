"""Web console. Served by gunicorn over HTTPS; see packaging/systemd."""
import hmac
import io
import os
import secrets
import subprocess
import time
from datetime import UTC, datetime

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import __version__, acme, certs, config, jobs, paths, schedule, store

SESSION_IDLE = 1800
MAX_FAILURES = 10
FAILURE_WINDOW = 600
PASSWORD_HASH = "pbkdf2:sha256:600000"
DUMMY_HASH = generate_password_hash(secrets.token_hex(16), method=PASSWORD_HASH)
NAV = [
    ("overview", "Overview"),
    ("activity", "Activity"),
    ("certificate", "Certificate"),
    ("settings", "Settings"),
    ("account", "Account"),
]


def hash_password(password):
    return generate_password_hash(password, method=PASSWORD_HASH)


def _auth():
    return store.read_json(paths.AUTH)


def _throttled():
    attempts = store.read_json(paths.ATTEMPTS)
    now = time.time()
    return [t for t in attempts.get("failures", []) if now - t < FAILURE_WINDOW]


def verify_password(password, record=None):
    """Check the console password with a shared, persistent failure budget."""
    record = record or _auth()
    with store.exclusive(paths.VAR / "auth.lock", wait=True):
        recent = _throttled()
        if len(recent) >= MAX_FAILURES:
            raise PermissionError("Too many failed attempts. Try again in 10 minutes.")
        if check_password_hash(record.get("password_hash", DUMMY_HASH), password):
            store.write_json(paths.ATTEMPTS, {"failures": []})
            return True
        store.write_json(paths.ATTEMPTS, {"failures": recent + [time.time()]})
        return False


def create_app():
    app = Flask(__name__)
    try:
        secret_key = paths.WEB_SECRET.read_text().strip()
    except FileNotFoundError:
        raise SystemExit("Console is not initialised. Run: ise-cert-utility init") from None
    app.config.update(
        SECRET_KEY=secret_key,
        SESSION_COOKIE_NAME="__Host-ise-cert-utility",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=64 * 1024,
    )

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    app.jinja_env.globals.update(csrf=csrf_token, version=__version__, nav=NAV, weekdays=config.WEEKDAYS,
                                 key_types=config.KEY_TYPES)

    @app.template_filter("when")
    def when(ts):
        if not ts:
            return "Never"
        return datetime.fromtimestamp(ts, UTC).astimezone().strftime("%Y-%m-%d %H:%M")

    @app.before_request
    def protect():
        if request.endpoint in (None, "static"):
            return None
        if request.method == "POST":
            sent = request.form.get("csrf") or request.headers.get("X-CSRF-Token", "")
            if not sent or not hmac.compare_digest(sent, session.get("csrf", "")):
                if request.endpoint == "login":
                    return render_template("login.html", error="Your session expired. Sign in again."), 400
                abort(403)
        if request.endpoint == "login":
            return None
        record = _auth()
        valid = (session.get("user") and session.get("user") == record.get("username")
                 and hmac.compare_digest(session.get("generation", ""), record.get("generation", "")))
        if not valid or time.time() - session.get("seen", 0) > SESSION_IDLE:
            session.pop("user", None)
            if request.path.startswith("/api/"):
                return jsonify(error="Your session expired.", login=url_for("login")), 401
            return redirect(url_for("login"))
        if request.endpoint != "status":  # background polling must not keep a session alive
            session["seen"] = time.time()
        return None

    @app.after_request
    def headers(response):
        response.headers.update({
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                       "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        })
        return response

    @app.errorhandler(403)
    def forbidden(_exc):
        if request.path.startswith("/api/"):
            return jsonify(error="The request could not be verified. Reload the page and try again."), 403
        return render_template("error.html", title="Request rejected",
                               detail="The request could not be verified. Reload the page and try again."), 403

    @app.errorhandler(404)
    def not_found(_exc):
        return render_template("error.html", title="Not found", detail="That page does not exist."), 404

    @app.errorhandler(500)
    def server_error(_exc):
        return render_template("error.html", title="Something went wrong",
                               detail="The error was logged. Check the service journal for details."), 500

    # Authentication

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            record = _auth()
            username = request.form.get("username", "")
            try:
                ok = verify_password(request.form.get("password", ""), record)
            except PermissionError as exc:
                return render_template("login.html", error=str(exc)), 429
            if ok and record and hmac.compare_digest(username, record.get("username", "")):
                session.clear()
                session.update(user=username, generation=record["generation"], seen=time.time())
                return redirect(url_for("overview"))
            error = "The username or password is incorrect."
        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # Pages

    def page(template, **extra):
        cfg = config.load()
        secret = config.secrets()
        return render_template(template, cfg=cfg, missing=config.missing(cfg, secret), user=_auth().get("username"),
                               saved={k: bool(secret.get(k)) for k in config.SECRET_KEYS},
                               active=request.endpoint, **extra)

    @app.get("/")
    def overview():
        return page("overview.html")

    @app.get("/activity")
    def activity():
        return page("activity.html", history=jobs.history(50))

    @app.get("/certificate")
    def certificate():
        cfg = config.load()
        state = store.read_json(paths.ISE_STATE)
        trusted = set(state.get("trusted_fingerprints", []))
        intermediates = [{**i, "trusted": (i["fingerprint"] in trusted) if "trusted_fingerprints" in state else None}
                         for i in certs.letsencrypt_intermediates(config.KEY_TYPES[cfg["key_type"]][0])]
        return page("certificate.html", cert=certs.info(cfg["domain"]), names=config.cert_names(cfg),
                    intermediates=intermediates)

    @app.get("/settings")
    def settings():
        try:
            trusted = [certs.describe(c) for c in certs.load_pems(paths.ISE_CA.read_bytes())]
        except (OSError, ValueError):
            trusted = []
        return page("settings.html", ise_ca=trusted)

    @app.get("/account")
    def account():
        return page("account.html", console_cert=_console_cert())

    def _console_cert():
        try:
            from cryptography import x509
            return certs.describe(x509.load_pem_x509_certificate(paths.TLS_CERT.read_bytes()))
        except (OSError, ValueError):
            return None

    # JSON API

    @app.get("/api/status")
    def status():
        cfg = config.load()
        job = jobs.current()
        log = paths.JOB_LOG.read_text()[-60000:] if paths.JOB_LOG.exists() else ""
        upcoming = schedule.next_window(cfg) if cfg["schedule_enabled"] else None
        return jsonify(
            certificate=certs.info(cfg["domain"]),
            names=config.cert_names(cfg),
            renew_days=cfg["renew_days"],
            job=job,
            log=log,
            pending=store.read_json(paths.PENDING),
            ise=store.read_json(paths.ISE_STATE),
            schedule={
                "enabled": cfg["schedule_enabled"],
                "in_window": schedule.window(cfg) is not None,
                "next": upcoming.isoformat() if upcoming else None,
                "timezone": cfg["timezone"],
                "last": store.read_json(paths.SCHEDULER),
            },
            history=jobs.history(8),
            missing=config.missing(cfg),
        )

    def guarded(fn):
        try:
            with store.exclusive():
                if jobs.busy():
                    raise ValueError("Wait for the running operation to finish before changing settings.")
                return fn()
        except ValueError as exc:
            return jsonify(error=str(exc)), 400

    @app.post("/api/settings/<section>")
    def save_settings(section):
        form = request.form

        def apply():
            if section == "certificate":
                clean, secret = config.validate_certificate(form)
                config.save(clean)
                config.save_secrets(secret)
            elif section == "ise":
                clean, secret, ca_pem = config.validate_ise(form)
                if ca_pem:
                    try:
                        parsed = certs.load_pems(ca_pem.encode())
                    except ValueError:
                        parsed = []
                    if not parsed:
                        raise ValueError("The trusted CA could not be parsed as PEM certificates.")
                    store.write_private(paths.ISE_CA, "".join(certs.to_pem(c) for c in parsed))
                if form.get("clear_ise_ca"):
                    paths.ISE_CA.unlink(missing_ok=True)
                config.save(clean)
                config.save_secrets(secret)
            elif section == "schedule":
                config.save(config.validate_schedule(form))
            elif section == "notifications":
                clean, secret = config.validate_notifications(form)
                config.save(clean)
                config.save_secrets(secret)
            else:
                abort(404)
            return jsonify(message="Settings saved.")

        return guarded(apply)

    @app.post("/api/test-cloudflare")
    def test_cloudflare():
        token = (request.form.get("cloudflare_token") or "").strip() or config.secrets().get("cloudflare_token")
        if not token:
            return jsonify(error="Enter or save a Cloudflare API token first."), 400
        saved = config.load()
        try:
            if request.form.get("domain"):
                domain = config.hostname(request.form["domain"], "Certificate hostname")
                names = [domain, *config.extra_names(request.form.get("extra_names", ""), domain)]
            else:
                names = config.cert_names(saved)
            return jsonify(message=acme.test_cloudflare(token, names))
        except (RuntimeError, ValueError) as exc:
            return jsonify(error=str(exc)), 400

    @app.post("/api/test-notification")
    def test_notification():
        from . import notify
        job = {"action": "test", "label": "Test notification", "state": "succeeded",
               "message": "Webhook delivery from the certificate console works."}
        cfg = {**config.load(), "notify_on": "always"}
        try:
            if not notify.send(job, cfg):
                return jsonify(error="Save a webhook URL first."), 400
        except Exception as exc:  # noqa: BLE001
            return jsonify(error=f"Delivery failed: {type(exc).__name__}."), 400
        return jsonify(message="Test notification sent.")

    @app.post("/api/action")
    def action():
        name = request.form.get("action", "")
        if name in jobs.DISRUPTIVE and request.form.get("confirm") != "yes":
            return jsonify(error="Confirm that ISE services may restart before deploying."), 400
        try:
            job = jobs.start(name, force=request.form.get("force") == "yes")
        except ValueError as exc:
            return jsonify(error=str(exc)), 409
        return jsonify(message=f"{job['label']} started.", job=job)

    @app.post("/api/clear-pending")
    def clear_pending():
        def apply():
            paths.PENDING.unlink(missing_ok=True)
            return jsonify(message="Pending import cleared. The next deployment will check ISE first.")
        return guarded(apply)

    @app.post("/api/password")
    def change_password():
        record = _auth()
        try:
            if not verify_password(request.form.get("current_password", ""), record):
                return jsonify(error="The current password is incorrect."), 403
        except PermissionError as exc:
            return jsonify(error=str(exc)), 429
        new = request.form.get("new_password", "")
        if not 14 <= len(new) <= 256:
            return jsonify(error="Use a password between 14 and 256 characters."), 400
        if new != request.form.get("confirm_password", ""):
            return jsonify(error="The new passwords do not match."), 400
        record.update(password_hash=hash_password(new), generation=secrets.token_hex(16))
        store.write_json(paths.AUTH, record)
        session.clear()
        return jsonify(message="Password changed. Sign in again.", redirect=url_for("login"))

    # Downloads

    @app.post("/download/<kind>")
    def download(kind):
        cfg = config.load()
        live = paths.live_dir(cfg["domain"])
        public = {"certificate": "cert.pem", "chain": "chain.pem", "fullchain": "fullchain.pem"}
        if kind in public:
            path = live / public[kind]
            if not cfg["domain"] or not path.is_file():
                abort(404)
            return send_file(path, as_attachment=True, download_name=f"{cfg['domain']}-{public[kind]}",
                             mimetype="application/x-pem-file")
        if kind == "console":
            return send_file(paths.TLS_CERT, as_attachment=True, download_name="console.crt")
        if kind.startswith("ca-"):
            name = kind[3:].upper()
            if name not in {n for n, _, _ in certs.LETS_ENCRYPT_INTERMEDIATES}:
                abort(404)
            return send_file(io.BytesIO(certs.intermediate_pem(name)), as_attachment=True,
                             download_name=f"letsencrypt-{name.lower()}.pem", mimetype="application/x-pem-file")
        if kind not in ("pfx", "key"):
            abort(404)
        try:
            ok = verify_password(request.form.get("current_password", ""))
        except PermissionError as exc:
            return render_template("error.html", title="Export blocked", detail=str(exc)), 429
        if not ok:
            return render_template("error.html", title="Export blocked",
                                   detail="The console password was incorrect."), 403
        export_password = request.form.get("export_password", "")
        if not 14 <= len(export_password) <= 256 or "\x00" in export_password:
            return render_template("error.html", title="Export blocked",
                                   detail="Use an export password between 14 and 256 characters."), 400
        if kind == "pfx":
            args = ["openssl", "pkcs12", "-export", "-in", str(live / "cert.pem"), "-inkey", str(live / "privkey.pem"),
                    "-certfile", str(live / "chain.pem"), "-name", cfg["domain"]]
            filename = f"{cfg['domain']}.pfx"
        else:
            args = ["openssl", "pkcs8", "-topk8", "-v2", "aes-256-cbc", "-in", str(live / "privkey.pem")]
            filename = f"{cfg['domain']}-key-encrypted.pem"
        args += ["-passout", "env:EXPORT_PASSWORD"]
        try:
            result = subprocess.run(args, env={**os.environ, "EXPORT_PASSWORD": export_password},
                                    capture_output=True, timeout=20, check=True)
        except (subprocess.SubprocessError, OSError):
            return render_template("error.html", title="Export failed",
                                   detail="Check that a certificate has been issued."), 400
        app.logger.warning("Private key exported as %s by %s from %s", kind, session.get("user"), request.remote_addr)
        return send_file(io.BytesIO(result.stdout), as_attachment=True, download_name=filename,
                         mimetype="application/octet-stream")

    return app
