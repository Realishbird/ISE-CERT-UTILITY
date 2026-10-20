# Configuration

All settings are edited in the console under **Settings**. They are stored in `/etc/ise-cert-utility/config.json` (non-secret values) and `/etc/ise-cert-utility/secrets.json` (credentials), both mode 0600 and owned by `ise-cert`. Saved credentials are never sent back to the browser; leave a credential field blank to keep the stored value.

Settings cannot be changed while an operation is running.

## Certificate and DNS

| Setting | Default | Description |
| --- | --- | --- |
| Certificate hostname | | FQDN that users and browsers use to reach ISE. Becomes the certificate's only subject alternative name. |
| ACME account email | | Registered with Let's Encrypt for account and expiry notices. |
| Key type | RSA 2048 | RSA 2048, 3072, 4096, or ECDSA P-256, P-384. Changing it replaces the certificate at the next renewal run. Confirm your ISE release supports ECDSA before choosing it. |
| Renew when | 30 days left | The certificate is renewed when it has this many days or fewer remaining. Let's Encrypt certificates last 90 days. |
| DNS wait | 30 seconds | Time to wait after creating the TXT record before asking Let's Encrypt to validate. Increase it if validation fails intermittently. |
| Cloudflare API token | | Scoped API token; see the [installation guide](installation.md#3-create-the-cloudflare-api-token). Also written to `cloudflare.ini` for Certbot. |

## ISE connection

| Setting | Default | Description |
| --- | --- | --- |
| API host | certificate hostname | Primary Admin Node FQDN. Set it when the PAN differs from the node receiving the certificate. |
| Port | 443 | OpenAPI port on the PAN. |
| Node name | | Target node as listed under Administration > System > Deployment. |
| API username, password | | ISE administrator with the ERS Admin or Super Admin role. |
| Roles to assign | Admin, Portal | Admin replaces the certificate used by the admin GUI and API and **restarts ISE application services**. Portal replaces the certificate for the selected portal group. |
| Portal group tag | Default Portal Certificate Group | Required when Portal is selected. |

### Advanced

| Setting | Default | Description |
| --- | --- | --- |
| Trusted CA for the ISE API | none | PEM certificate(s) trusted in addition to the system store when connecting to ISE. Needed while ISE presents a self-signed or private-CA admin certificate. |
| Pinned EAP certificate | none | SHA-256 fingerprint. When set, every operation stops unless ISE's EAP certificate is exactly this one. Without it, the utility still stops if the EAP assignment changes during an import. |
| Verification timeout | 30 minutes | How long to wait for ISE to come back and report the new certificate after an import. |
| Delete superseded certificates | off | After a verified deployment, delete system certificates on the node that this utility imported earlier and that are no longer used by any role. Certificates imported by other means are never touched. |

## Maintenance window

| Setting | Default | Description |
| --- | --- | --- |
| Renew and deploy automatically | off | Enables the scheduler. |
| Opens, Closes | 02:00, 04:00 | Local time in the selected time zone. A window may cross midnight; it then belongs to the day it opens. |
| Time zone | UTC | IANA name such as `America/Chicago`. |
| Days | every day | Days on which a window opens. |
| Attempts per window | 3 | Total runs allowed per window. Retries happen only after a failure. |
| Retry after | 30 minutes | Minimum delay between attempts in one window. |

The scheduler starts a run only inside the window. The import step is checked again immediately before it is sent, so a slow renewal that finishes after the window closes defers deployment to the next window rather than restarting ISE during business hours. A restart that has already started may complete after the window ends.

Manual operations from the console or CLI ignore the window.

## Notifications

| Setting | Default | Description |
| --- | --- | --- |
| Webhook URL | none | HTTPS endpoint that receives a JSON POST. Stored as a secret. |
| Send | Failures only | `Failures only`, `Every operation`, or `Never`. |

Payload:

```json
{
  "text": "[ise-certs] Renew and deploy: failed. Could not reach the Cloudflare API: timed out",
  "source": "ise-cert-utility",
  "host": "ise-certs",
  "domain": "ise.example.com",
  "action": "renew",
  "state": "failed",
  "message": "Could not reach the Cloudflare API: timed out",
  "scheduled": true
}
```

The `text` field is accepted directly by Slack incoming webhooks and Microsoft Teams workflow webhooks.

## Console listener

The bind address is set in `/etc/default/ise-cert-utility`:

```bash
ISE_CERT_UTILITY_BIND=0.0.0.0:8443
```

Restart with `systemctl restart ise-cert-utility-web` after changing it. To regenerate the console certificate, for example after renaming the host:

```bash
ise-cert-utility tls --san ise-certs.example.com --san 192.0.2.10
systemctl restart ise-cert-utility-web
```
