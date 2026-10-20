# Changelog

## Unreleased

### Added
- Multi-node deployments: update every node in the ISE deployment (read from ISE on each run) or a listed set, each through its own API host. Nodes are updated one at a time, Policy Service nodes first and the Primary Admin Node last, and each is verified before the next import. Every node must pass its checks before anything is imported; a failure stops the run before later nodes, and the next run resumes where it stopped.
- Per-node status on the Overview page and in `status`, per-node pending-import markers, and multiple pinned EAP fingerprints (one per node).
- With the Admin role, deployment stops if the certificate does not cover a node's API host.
- Additional names: request one certificate that also covers portal FQDNs, other nodes or wildcard names, set under Settings > Certificate and DNS.
- Test token, Test renewal and Renew and deploy confirm that a Cloudflare zone is visible for every certificate name.
- Changing the name list triggers a replacement certificate on the next run; the Certificate page shows pending names, and deployment is blocked until the certificate includes them.
- `status` output and `/api/status` list all certificate names.

## 2.0.0

A rewrite of the 1.x scripts into a packaged application.

### Added
- First-time certificate issuance through Certbot and the Cloudflare DNS plugin, with selectable RSA or ECDSA keys and a configurable renewal threshold.
- Installer, systemd units and a command wrapper; `migrate-legacy` imports 1.x settings.
- Maintenance windows with weekday selection, retries within the window and a single scheduler.
- ISE API host, port and custom trusted CA settings, so the first deployment works while ISE still presents its self-signed certificate.
- Paginated ISE API reads.
- Optional removal of superseded certificates the utility imported earlier.
- Webhook notifications.
- Cloudflare token test that confirms zone access.
- Operation history, `status` command and JSON status output.
- Test suite with a simulated ISE API, and CI.

### Changed
- Runs as the unprivileged `ise-cert` account in a hardened systemd sandbox instead of root.
- Certbot state lives under `/var/lib/ise-cert-utility/acme` and is managed only by this utility.
- The EAP certificate is checked against a snapshot taken before each import; the fingerprint pin is now optional.
- Certificate and chain validation uses the `cryptography` library, including hostname and serverAuth checks.
- New web console design with light and dark themes.

### Removed
- Hard-coded hostnames, node names and fingerprints.
- The separate `install-timer` scheduler that competed with the console scheduler.
