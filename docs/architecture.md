# Architecture

## Components

```text
                     ┌──────────────────────── container ─────────────────────────┐
  Browser ──HTTPS──▶ │ gunicorn: ise_cert_utility.web (Flask)                      │
                     │        │ starts                                             │
                     │        ▼                                                    │
  systemd timer ───▶ │ worker: ise_cert_utility.jobs ──▶ certbot + dns-cloudflare ─┼──▶ Let's Encrypt
  (every minute)     │        │                                     │              │
                     │        │                                     └──────────────┼──▶ Cloudflare API
                     │        └──▶ ise_cert_utility.ise ────────────────────────────┼──▶ ISE OpenAPI (PAN)
                     └─────────────────────────────────────────────────────────────┘
```

| Module | Responsibility |
| --- | --- |
| `web.py` | Console pages, JSON API, authentication, CSRF protection, downloads. |
| `jobs.py` | Single-operation queue, background worker, scrubbed logging, history, scheduler tick. |
| `acme.py` | Certbot arguments, renewal decision, Cloudflare token test. |
| `ise.py` | ISE OpenAPI client, preflight, trusted chain import, deployment and verification. |
| `certs.py` | Certificate parsing and chain, hostname and key validation with `cryptography`. |
| `schedule.py` | Maintenance-window arithmetic. |
| `config.py` | Settings, secrets and input validation. |
| `notify.py` | Webhook delivery. |
| `store.py` | Atomic 0600 file writes and file locks. |
| `cli.py` | `ise-cert-utility` command. |

There is no database. State is a handful of JSON files written atomically.

## File layout

```text
/opt/ise-cert-utility/venv/            Application, Certbot and dependencies
/usr/local/bin/ise-cert-utility        Wrapper that runs as the service account
/etc/default/ise-cert-utility          Console bind address
/etc/ise-cert-utility/                 Configuration (0700, ise-cert)
  config.json                          Settings
  secrets.json                         ISE password, Cloudflare token, webhook URL
  cloudflare.ini                       Certbot credentials file
  ise-trusted-ca.pem                   Optional CA for the ISE API connection
  auth.json                            Console account (PBKDF2-SHA256, 600,000 iterations)
  web-secret                           Session signing key
  tls/console.{crt,key}                Console certificate
/var/lib/ise-cert-utility/             State (0700, ise-cert)
  acme/{config,work,logs}/             Certbot directories; live/<host>/ holds the certificate
  job.json, job.log, history.json      Current operation, its log, history
  scheduler.json                       Window and attempt tracking
  ise-state.json                       Result of the last ISE read
  pending-import.json                  Present only while an import is unverified
  ca-chain/                            Exported chain from the last preflight
```

## Concurrency

- `control.lock` serialises starting an operation and changing settings. Settings cannot change while an operation runs.
- `deploy.lock` is held by the worker for the whole operation, so a CLI run, a scheduled run and a console run can never overlap.
- The current operation's process ID is recorded; if the worker dies, the next status read marks the operation as interrupted.

## Scheduling

The `ise-cert-utility-scheduler.timer` unit fires every minute and runs `scheduled-tick`, which exits immediately unless:

- automation is enabled,
- the current time is inside a window on an enabled day, and
- this is the first run of the window, or the previous run in this window failed, the retry delay has passed and attempts remain.

A scheduled run executes in the timer's own service, so a console restart does not interrupt it.

## ISE API usage

| Call | Purpose |
| --- | --- |
| `GET /api/v1/certs/system-certificate/{node}` | List system certificates and their roles (paged) |
| `GET /api/v1/certs/trusted-certificate` | List trusted CAs (paged) |
| `POST /api/v1/certs/trusted-certificate/import` | Import a missing CA, trusted for ISE authentication only |
| `POST /api/v1/certs/system-certificate/import` | Import the certificate with an encrypted PKCS#8 key for the Admin and/or Portal role |
| `DELETE /api/v1/certs/system-certificate/{node}/{id}` | Remove a superseded certificate (optional) |

Certificates imported by the utility are named `ise-cert-utility <first 16 hex digits of the SHA-256 fingerprint>`; CAs are named `ise-cert-utility CA <...>`. Cleanup only considers certificates with that prefix (or the 1.x `ACME Admin Portal` prefix) that no role uses.
