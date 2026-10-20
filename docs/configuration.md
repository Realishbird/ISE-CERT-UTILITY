# Configuration

All settings are edited in the console under **Settings**. They are stored in `/etc/ise-cert-utility/config.json` (non-secret values) and `/etc/ise-cert-utility/secrets.json` (credentials), both mode 0600 and owned by `ise-cert`. Saved credentials are never sent back to the browser; leave a credential field blank to keep the stored value.

Settings cannot be changed while an operation is running.

## Certificate and DNS

| Setting | Default | Description |
| --- | --- | --- |
| Certificate hostname | | FQDN that users and browsers use to reach ISE. Becomes the certificate's subject and first subject alternative name. |
| Additional names | none | Further DNS names to include as subject alternative names, one per line. See [Additional names](#additional-names). |
| ACME account email | | Registered with Let's Encrypt for account and expiry notices. |
| Key type | RSA 2048 | RSA 2048, 3072, 4096, or ECDSA P-256, P-384. Changing it replaces the certificate at the next renewal run. Confirm your ISE release supports ECDSA before choosing it. |
| Renew when | 30 days left | The certificate is renewed when it has this many days or fewer remaining. Let's Encrypt certificates last 90 days. |
| DNS wait | 30 seconds | Time to wait after creating the TXT record before asking Let's Encrypt to validate. Increase it if validation fails intermittently. |
| Cloudflare API token | | Scoped API token; see the [installation guide](installation.md#3-create-the-cloudflare-api-token). Also written to `cloudflare.ini` for Certbot. |

### Additional names

Use additional names when one certificate must cover more than the admin hostname, for example the FQDNs of guest, sponsor or BYOD portals, other nodes in the deployment, or a wildcard such as `*.portal.example.com`.

- Every name must be in a zone managed by Cloudflare, and the API token needs **Zone / DNS / Edit** and **Zone / Zone / Read** on each of those zones. Names may span several zones. **Test token** reports the zone found for each name and lists any it cannot reach.
- Let's Encrypt validates each name separately with its own DNS TXT record, so a run takes slightly longer for every name added.
- A wildcard covers one label only: `*.example.com` covers `guest.example.com` but not `example.com` or `a.guest.example.com`. Names already covered by a wildcard in the list are rejected, because Let's Encrypt refuses them.
- A certificate holds at most 100 names, including the certificate hostname.
- Changing the list makes the next **Renew and deploy** run request a replacement certificate immediately, without waiting for the renewal threshold. The **Certificate** page shows which names are pending until then, and deployment to ISE is blocked while the certificate on disk is missing a configured name.

## ISE connection

| Setting | Default | Description |
| --- | --- | --- |
| API host | certificate hostname | Primary Admin Node FQDN. The deployment node list and the trusted certificate store are read here. |
| Port | 443 | OpenAPI port, the same on every node. |
| Nodes to update | listed nodes | **Only the nodes listed** updates the nodes named below. **Every node in the deployment** reads the node list from ISE on each run, so nodes added later are picked up automatically. |
| Nodes | | One node per line, named as under Administration > System > Deployment. Optionally follow the name with the API host used to reach that node, for example `psn-02 psn-02.mgmt.example.com`. In *every node* mode, lines here only override API hosts. |
| API username, password | | ISE administrator with the ERS Admin or Super Admin role. |
| Roles to assign | Admin, Portal | Admin replaces the certificate used by the admin GUI and API and **restarts ISE application services**. Portal replaces the certificate for the selected portal group. |
| Portal group tag | Default Portal Certificate Group | Required when Portal is selected. |

### Advanced

| Setting | Default | Description |
| --- | --- | --- |
| Trusted CA for the ISE API | none | PEM certificate(s) trusted in addition to the system store when connecting to ISE. Needed while ISE presents a self-signed or private-CA admin certificate. |
| Pinned EAP certificates | none | SHA-256 fingerprints, one per line. When set, every operation stops unless each node's EAP certificate is one of these. Nodes often have their own EAP certificate, so list one per node. Without a pin, the utility still stops if a node's EAP assignment changes during an import. |
| Verification timeout per node | 30 minutes | How long to wait for a node to come back and report the new certificate after an import. |
| Delete superseded certificates | off | After a verified deployment, delete system certificates on each node that this utility imported earlier and that are no longer used by any role. Certificates imported by other means are never touched. |

## Multiple ISE nodes

ISE's API has no way to import a system certificate onto another node: the certificate is installed on the node that receives the request. The utility therefore connects to each node's own API host, which means:

- OpenAPI must answer on every node being updated, and the container needs HTTPS access to each of them.
- Each node's API host is, in order of preference, the host given after its name in **Nodes**, the **API host** setting for the Primary Admin Node (or when only one node is configured), and otherwise the FQDN ISE reports for the node.
- With the Admin role, the certificate must include each node's API host, because that is the name the admin GUI and the utility use to reach it. Add node FQDNs under **Additional names**. Portal-only deployments do not need them.
- If a node still presents a self-signed or private-CA admin certificate, add its issuing CA under **Trusted CA for the ISE API**.

Nodes are updated one at a time: Policy Service and dedicated Monitoring nodes first, then the Secondary Admin Node, and the Primary Admin Node last. Each node is verified before the next import starts, so at most one node is restarting at any moment and the PAN is only touched after every other node succeeded. Roles come from the deployment list; if the API account cannot read it in *listed nodes* mode, nodes are updated in the order listed.

Trusted certificates replicate across the deployment, so CA imports (including a manual import of a Let's Encrypt intermediate) are done once, on the PAN.

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
