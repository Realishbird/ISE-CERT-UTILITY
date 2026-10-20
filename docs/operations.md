# Operations

## What each operation does

| Operation | Changes ISE | Contacts Let's Encrypt | Description |
| --- | --- | --- | --- |
| Check ISE | No | No | Validates the local certificate, chain and key, reads each node's system certificates and the trusted store, and records whether each node serves the current certificate. |
| Test renewal | No | Staging only | Runs Certbot with `--dry-run` against the staging service. Proves the Cloudflare token and DNS propagation without affecting the real certificate or rate limits. |
| Import CA chain | Trusted store only | No | Adds the intermediate and root CAs that ISE does not already trust. System certificate assignments are not changed. |
| Renew and deploy | Yes, if needed | If due | Renews when the certificate is within the renewal threshold (or when forced), then deploys if ISE does not already serve it. This is what the scheduler runs. |
| Deploy current certificate | Yes, if needed | No | Deploys the certificate on disk. Useful after fixing an ISE-side problem. |

Only one operation runs at a time. Operations started from the console run in the background; you can close the browser.

## Renewal and deployment sequence

1. **Renewal decision.** If no certificate exists, the key type or the list of names changed, or fewer than *Renew when* days remain, Certbot requests a new certificate. Otherwise this step is skipped.
2. **Local validation.** The certificate must match the hostname, include every configured additional name, be valid for at least 7 more days, carry the serverAuth usage, chain to a root in the system trust store, and match the private key.
3. **ISE preflight.** The target nodes are resolved and put in update order (see [Multiple ISE nodes](configuration.md#multiple-ise-nodes)). Every node's system certificates are read through its own API host, its EAP certificate is recorded and checked against the pins, and with the Admin role its API host must be on the certificate. If any node fails, nothing is imported.
4. **Trust chain.** Missing CAs are imported and the import is confirmed.
5. **Idempotency check.** Nodes that already serve this certificate for the selected roles are skipped. If every node does, the run ends here with no import and no restart.

Steps 6 to 8 then run for each remaining node in turn:

6. **Window check.** Scheduled runs confirm the maintenance window is still open. If it has closed, the remaining nodes are updated in the next window.
7. **Import.** A pending-import marker for the node is written, then the certificate and an encrypted copy of the key are sent to that node once. With the Admin role, the node restarts its application services.
8. **Verification.** The utility polls the node every 30 seconds until the new certificate is assigned to the selected roles and its EAP certificate is unchanged, or until the verification timeout. A failure stops the run, so later nodes, including the Primary Admin Node, are left untouched. The next run continues with the nodes that still need the certificate.

9. **Cleanup.** If enabled, superseded certificates imported earlier are deleted on each node.

## The pending-import marker

The ISE import call can succeed even when its HTTP response is lost, because the Admin role restart drops connections. To avoid importing twice, the utility writes a marker for the node before the request and removes it only after verification.

If verification times out, the marker remains and further imports to that node are blocked. The Overview page then shows **Unverified import**. To recover:

1. Open ISE, go to **Administration > System > Certificates > System Certificates**, and check whether the node named in the operation log shows the new certificate on the expected roles.
2. If it does, or if the import clearly failed, select **Clear marker** in the console.
3. Run **Deploy current certificate**. If ISE already serves the certificate, the run ends without importing.

## Command line

The wrapper at `/usr/local/bin/ise-cert-utility` runs commands as the `ise-cert` account, so it is safe to use from a root shell.

```text
ise-cert-utility status [--json]
ise-cert-utility run {check,test-renewal,trust-chain,renew,deploy} [--force] [--yes]
ise-cert-utility init [--reset-password] [--generate-password] [--regenerate-tls] [--san NAME]
ise-cert-utility tls [--san NAME]
ise-cert-utility migrate-legacy
```

`run` executes in the foreground and prints the log. It shares the console's lock, so it refuses to start while another operation is running. `renew` and `deploy` require `--yes` because they can restart ISE services. `--force` renews even when the certificate is not due.

`status --json` is suitable for monitoring systems. A simple expiry check:

```bash
ise-cert-utility status --json | jq '.certificate.days'
```

## Logs

| Source | Location |
| --- | --- |
| Current operation | Activity page, or `/var/lib/ise-cert-utility/job.log` |
| Operation history | Activity page, or `/var/lib/ise-cert-utility/history.json` (last 100) |
| Web console and private-key exports | `journalctl -u ise-cert-utility-web` |
| Scheduler | `journalctl -u ise-cert-utility-scheduler` |
| Certbot | `/var/lib/ise-cert-utility/acme/logs/` |

Operation logs are scrubbed of stored credentials and private keys.

## Troubleshooting

**"Could not verify the ISE API certificate"**
ISE presents a certificate that is not publicly trusted. Paste its issuing CA under **Settings > ISE connection > Advanced**, or set the API host to the name the ISE certificate was issued for.

**"ISE rejected the API credentials (HTTP 401)"**
Check the username and password, confirm the account is in the ERS Admin or Super Admin group, and confirm OpenAPI is enabled on the PAN.

**"ISE's API refused to import ... (Security Check Failed)"** during Import CA chain or Renew and deploy
ISE's request filter rejects some CA certificates through the API, notably Let's Encrypt intermediates whose organisation is "Let's Encrypt". The admin portal accepts the same file. Download the CA from **Let's Encrypt intermediates** on the **Certificate** page, import it in ISE under **Administration > System > Certificates > Trusted Certificates** with **Trust for authentication within ISE**, then run **Deploy**.

**"ISE does not trust Let's Encrypt YR1"** (or another intermediate) in Check ISE
Let's Encrypt signs each renewal with one of two active intermediates, chosen per certificate. A renewal signed by one ISE does not trust cannot deploy. Import every intermediate listed as not trusted on the **Certificate** page once, through the ISE admin portal, so unattended renewals keep working.

**"ISE rejected the request: HTTP 404"** during Check ISE
The node name does not match. Use the name exactly as shown in the ISE deployment list.

**"N of M nodes failed their checks, so nothing was imported"**
The **ISE nodes** panel on the Overview page shows the reason for each node. Common causes are an API host the container cannot reach, OpenAPI not answering on that node, a node's admin certificate signed by a CA the utility does not trust yet, or a node's EAP certificate missing from the pins.

**"The certificate does not include psn-01.example.com, so node psn-01 cannot use it for the Admin role"**
Add the node's FQDN under **Additional names** and run **Renew and deploy**, or set the API host for that node to a name the certificate already covers.

**"Could not read the ISE deployment"**
*Every node in the deployment* needs an API account that can read the deployment node list. Grant that access or switch to *Only the nodes listed* and name the nodes.

**Test renewal fails with a DNS or authorization error**
Use **Test token** under Settings to confirm the token sees the zone for every name. Before contacting Let's Encrypt, Test renewal and Renew and deploy stop with a list of any names whose zone the token cannot see. If the zones are correct, increase **DNS wait** to 60 or 120 seconds.

**"The certificate does not include ..."** during Check ISE or Deploy
Additional names were added after the certificate was issued. Run **Renew and deploy** to request a certificate with the current list.

**"The certificate chain did not validate against public roots"**
The container's CA bundle is out of date. Run `apt-get update && apt-get install --only-upgrade ca-certificates`.

**Too many failed sign-in attempts**
The console blocks sign-in for 10 minutes after 10 failures across all clients. Wait, or reset the account with `ise-cert-utility init --reset-password`.

**Let's Encrypt rate limits**
Repeated forced renewals can hit the limit of 5 duplicate certificates per week. Use **Test renewal**, which uses the staging service, for experiments.
