# Security

## Threat model

The appliance holds three valuable secrets: an ISE administrator credential, a Cloudflare token that can edit DNS in a zone, and the private key of a publicly trusted certificate for ISE. The design goal is that compromising the web console, a dependency or the network path does not expose more than necessary.

## Privilege separation

- Every component runs as the `ise-cert` system account. Nothing runs as root after installation.
- Certbot uses private directories under `/var/lib/ise-cert-utility/acme` instead of `/etc/letsencrypt`.
- The systemd units apply `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`, an empty capability set, a system call filter and address family restrictions. Only the configuration and state directories are writable.

## Secrets

- Credentials are kept in `secrets.json` and `cloudflare.ini`, mode 0600, in a 0700 directory owned by the service account. Files are replaced atomically and never created with broader permissions.
- The console never returns stored credentials. Credential fields only accept new values.
- Operation logs replace any stored credential with `[redacted]` and drop any PEM private key block, including output from Certbot and OpenSSL.
- The private key sent to ISE is encrypted with a random single-use password for transport inside the API request, which itself is TLS-protected and certificate-verified.
- Error messages from ISE are included only if they are short plain text, because API error bodies can echo submitted data.

## Console

- HTTPS only, with a per-installation certificate. Session cookies are `Secure`, `HttpOnly`, `SameSite=Strict` and use the `__Host-` prefix.
- Sessions expire after 30 minutes without user activity. Background status polling does not extend a session.
- Every state-changing request requires a per-session CSRF token.
- A strict Content Security Policy allows only same-origin scripts and styles; there are no third-party assets, CDNs or analytics.
- Password checks share a persistent budget of 10 failures per 10 minutes across all clients, for sign-in, password change and private-key export. Passwords are stored with PBKDF2-SHA256 at 600,000 iterations.
- Changing the password invalidates all sessions.
- Private-key exports require the console password, are encrypted with a separate export password of at least 14 characters, and are logged with the user and client address.

## Recommendations

- Restrict access to TCP 8443 to administrator networks with the Proxmox firewall or your network firewall.
- Scope the Cloudflare token to the single zone and, where possible, to the container's egress IP.
- Use a dedicated ISE administrator for this utility and review the ISE audit log for its activity.
- Include `/etc/ise-cert-utility` in encrypted backups; it contains everything needed to rebuild the appliance.
- Set a webhook so failed renewals are noticed well before expiry.

## Reporting a vulnerability

Please report security issues privately through GitHub security advisories on the repository rather than in a public issue.
