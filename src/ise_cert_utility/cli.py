"""Command-line interface: ise-cert-utility <command>."""
import argparse
import datetime
import getpass
import ipaddress
import json
import os
import pwd
import secrets
import socket
import sys
from pathlib import Path

from . import __version__, certs, config, jobs, paths, store

SERVICE_USER = "ise-cert"


def _prompt_password():
    if not sys.stdin.isatty():
        password = sys.stdin.readline().rstrip("\n")
        if not 14 <= len(password) <= 256:
            raise SystemExit("Password from stdin must be 14-256 characters.")
        return password
    while True:
        password = getpass.getpass("Console password (14+ characters): ")
        if not 14 <= len(password) <= 256:
            print("Use between 14 and 256 characters.")
        elif password != getpass.getpass("Confirm password: "):
            print("Passwords do not match.")
        else:
            return password


def cmd_init(args):
    from .web import hash_password
    for directory in (paths.ETC, paths.VAR):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not paths.WEB_SECRET.exists():
        store.write_private(paths.WEB_SECRET, secrets.token_hex(32) + "\n")
    if not paths.TLS_CERT.exists() or args.regenerate_tls:
        cmd_tls(args)
    if paths.AUTH.exists() and not args.reset_password:
        print("Console account already exists; leaving it unchanged.")
        return 0
    username = args.username or (input("Console username [admin]: ").strip() if sys.stdin.isatty() else "") or "admin"
    if not (username.isascii() and username.isprintable() and 0 < len(username) <= 64):
        raise SystemExit("Usernames must be 1-64 printable ASCII characters.")
    if args.generate_password:
        password = secrets.token_urlsafe(18)
    else:
        password = _prompt_password()
    store.write_json(paths.AUTH, {"username": username, "password_hash": hash_password(password),
                                  "generation": secrets.token_hex(16)})
    store.write_json(paths.ATTEMPTS, {"failures": []})
    print(f"Console account '{username}' saved.")
    if args.generate_password:
        print(f"Generated password: {password}")
        print("Store it now; it is not shown again. Change it under Account after signing in.")
    return 0


def cmd_tls(args):
    """Create a self-signed certificate for the console itself."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    fqdn = socket.getfqdn()
    names = {fqdn, socket.gethostname(), "localhost", *(getattr(args, "san", None) or [])}
    alt = []
    for name in sorted(n for n in names if n):
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            alt.append(x509.DNSName(name))
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn[:64]),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ISE Certificate Utility")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))
    store.write_private(paths.TLS_KEY, key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    store.write_private(paths.TLS_CERT, cert.public_bytes(serialization.Encoding.PEM))
    print(f"Console TLS certificate created for {', '.join(sorted(n for n in names if n))}.")
    print(f"SHA-256 fingerprint: {certs.fingerprint(cert)}")
    return 0


def cmd_run(args):
    if args.action in jobs.DISRUPTIVE and not args.yes:
        raise SystemExit(f"'{args.action}' can restart ISE services. Re-run with --yes to confirm.")
    job = jobs.start(args.action, force=args.force, spawn=False)
    job = jobs.work(job["id"], echo=True)
    return 0 if job.get("state") == "succeeded" else 1


def cmd_status(args):
    cfg = config.load()
    out = {
        "version": __version__,
        "domain": cfg["domain"],
        "names": config.cert_names(cfg),
        "certificate": certs.info(cfg["domain"]),
        "ise": store.read_json(paths.ISE_STATE),
        "job": jobs.current(),
        "pending_import": store.read_json(paths.PENDING),
        "missing_settings": config.missing(cfg),
    }
    if args.json:
        print(json.dumps(out, indent=2, default=str))
        return 0
    cert = out["certificate"]
    if cfg["extra_names"]:
        print(f"Also covers:   {', '.join(cfg['extra_names'])}")
    print(f"Domain:        {cfg['domain'] or '(not configured)'}")
    print(f"Certificate:   {cert.get('expires', 'none')[:10]} ({cert.get('days', '-')} days left)"
          if cert.get("present") else "Certificate:   not issued")
    ise_state = out["ise"]
    print(f"ISE deployed:  {'yes' if ise_state.get('deployed') else 'no'} (checked "
          f"{datetime.datetime.fromtimestamp(ise_state['checked_at']):%Y-%m-%d %H:%M})"
          if ise_state else "ISE deployed:  never checked")
    job = out["job"]
    print(f"Last job:      {job.get('label', '-')} {job.get('state', '')}: {job.get('message', '')}".rstrip())
    if out["missing_settings"]:
        print("Missing:       " + ", ".join(out["missing_settings"]))
    return 0


def cmd_tick(args):
    jobs.scheduled_tick(echo=args.verbose)
    return 0


def cmd_worker(args):
    jobs.work(args.job_id)
    return 0


def cmd_migrate(args):
    """Import settings from the 1.x layout (/etc/ise-cert-sync) into the current configuration."""
    if os.geteuid() != 0:
        raise SystemExit("Run migrate-legacy as root so the 1.x files can be read.")
    legacy = store.read_json(Path(args.legacy_dir) / "config.json")
    if not legacy:
        raise SystemExit(f"No legacy configuration found in {args.legacy_dir}.")
    cfg = {k: legacy[k] for k in ("domain", "node", "username", "portal_tag") if legacy.get(k)}
    if legacy.get("eap_fingerprint"):
        cfg["eap_fingerprint"] = config.fingerprint(legacy["eap_fingerprint"])
    old_schedule = store.read_json(Path(args.legacy_web_dir) / "schedule.json")
    if old_schedule:
        cfg.update(schedule_enabled=bool(old_schedule.get("enabled")), timezone=old_schedule.get("timezone", "UTC"),
                   window_start=old_schedule.get("start", "02:00"), window_end=old_schedule.get("end", "04:00"))
    config.save(cfg)
    secret = {}
    if legacy.get("password"):
        secret["ise_password"] = legacy["password"]
    ini = Path(args.cloudflare_ini)
    if ini.exists():
        for line in ini.read_text().splitlines():
            if line.strip().startswith("dns_cloudflare_api_token") and "=" in line:
                secret["cloudflare_token"] = line.split("=", 1)[1].strip()
    config.save_secrets(secret)
    user = pwd.getpwnam(args.owner)
    for path in (paths.CONFIG, paths.SECRETS, paths.CLOUDFLARE_INI):
        if path.exists():
            os.chown(path, user.pw_uid, user.pw_gid)
    print(f"Imported: {', '.join(sorted(cfg))}; secrets: {', '.join(sorted(secret)) or 'none'}.")
    print("Set the ACME account email in Settings, then run 'Renew and deploy' to issue a certificate "
          "under the new layout. The 1.x files were not modified.")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="ise-cert-utility",
                                     description="Let's Encrypt certificate automation for Cisco ISE.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create the console account, session key and TLS certificate")
    p.add_argument("--username")
    p.add_argument("--reset-password", action="store_true", help="replace the existing console account")
    p.add_argument("--generate-password", action="store_true", help="create a random password and print it once")
    p.add_argument("--regenerate-tls", action="store_true")
    p.add_argument("--san", action="append", help="extra DNS name or IP for the console certificate")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("tls", help="regenerate the console's self-signed TLS certificate")
    p.add_argument("--san", action="append", help="extra DNS name or IP address")
    p.set_defaults(func=cmd_tls)

    p = sub.add_parser("run", help="run an operation in the foreground")
    p.add_argument("action", choices=sorted(jobs.ACTIONS))
    p.add_argument("--force", action="store_true", help="renew even if the certificate is not due")
    p.add_argument("--yes", action="store_true", help="confirm operations that can restart ISE services")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("status", help="show certificate and deployment status")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("scheduled-tick", help="run by the systemd timer every minute")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_tick)

    p = sub.add_parser("worker", help=argparse.SUPPRESS)
    p.add_argument("job_id")
    p.set_defaults(func=cmd_worker)

    p = sub.add_parser("migrate-legacy", help="import settings from a 1.x installation (run as root)")
    p.add_argument("--legacy-dir", default="/etc/ise-cert-sync")
    p.add_argument("--legacy-web-dir", default="/etc/ise-cert-web")
    p.add_argument("--cloudflare-ini", default="/root/.secrets/certbot/cloudflare.ini")
    p.add_argument("--owner", default=SERVICE_USER)
    p.set_defaults(func=cmd_migrate)
    return parser


def main(argv=None):
    os.umask(0o077)
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
