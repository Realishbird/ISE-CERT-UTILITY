# Installation

This guide covers a new installation on a Proxmox LXC container. Any Debian 12+ or Ubuntu 22.04+ host with systemd works the same way from step 4.

## 1. Create the container

On the Proxmox host, download a Debian template and create an unprivileged container. Adjust the ID, storage, bridge and addressing for your environment, and use the template name that `pveam available --section system` lists for the current Debian release.

```bash
pveam update
pveam available --section system | grep debian
pveam download local debian-12-standard_12.7-1_amd64.tar.zst

pct create 210 local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  --hostname ise-certs \
  --unprivileged 1 \
  --features nesting=1 \
  --cores 1 --memory 512 --swap 256 \
  --rootfs local-lvm:4 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --onboot 1

pct start 210
pct enter 210
```

`nesting=1` lets systemd apply its sandboxing inside the container. One core and 512 MB of memory are sufficient.

The container needs outbound HTTPS (TCP 443) to:

- `acme-v02.api.letsencrypt.org` and `acme-staging-v02.api.letsencrypt.org`
- `api.cloudflare.com`
- the ISE Primary Admin Node
- your Python package index during installation and upgrades

## 2. Prepare ISE

1. Enable the API: **Administration > System > Settings > API Settings > API Service Settings**, enable **Open API (Read/Write)**.
2. Create an administrator for the utility: **Administration > System > Admin Access > Administrators > Admin Users**. Assign the **ERS Admin** group, or **Super Admin** if your policy requires it for certificate operations. Use a long random password.
3. Note the node name exactly as shown under **Administration > System > Deployment**. This is the value for **Node name** in the console.

If ISE currently presents a self-signed or private-CA admin certificate, export the issuing CA certificate (for a self-signed certificate, the certificate itself) in PEM format. You will paste it under **Settings > ISE connection > Advanced** so the utility can verify the API connection. After the first deployment ISE presents a Let's Encrypt certificate and this is no longer needed.

## 3. Create the Cloudflare API token

In the Cloudflare dashboard, open **My Profile > API Tokens > Create Token** and use the **Edit zone DNS** template:

- Permissions: **Zone / DNS / Edit** and **Zone / Zone / Read**
- Zone resources: **Include / Specific zone /** the zone that contains the ISE hostname, plus any other zone that hosts one of the certificate's [additional names](configuration.md#additional-names)

Restrict client IP addresses to the container's public egress address if it is fixed. The console's **Test token** button confirms the token is active and can see the zone for every name on the certificate.

## 4. Install

```bash
apt-get update && apt-get install -y git
git clone https://github.com/Realishbird/ISE-CERT-UTILITY.git /usr/local/src/ise-cert-utility
cd /usr/local/src/ise-cert-utility
./install.sh
```

The installer:

1. installs Python, `venv`, OpenSSL and CA certificates from the distribution;
2. creates the `ise-cert` system account;
3. installs the application, Certbot and the Cloudflare plugin into `/opt/ise-cert-utility/venv`;
4. installs the systemd units and the `/usr/local/bin/ise-cert-utility` wrapper;
5. creates a self-signed console certificate covering the host name and IP addresses;
6. asks for the console username and password (or generates a password when run without a terminal);
7. starts the web console and the scheduler timer.

The console listens on `0.0.0.0:8443` by default. To change it, set `ISE_CERT_UTILITY_BIND` before installing or edit `/etc/default/ise-cert-utility` and restart `ise-cert-utility-web`.

Compare the fingerprint the installer prints with the one your browser shows before accepting the certificate.

## 5. Configure and run

Sign in and complete the four sections under **Settings**. Then, from **Overview**:

1. **Test renewal** confirms DNS validation against the Let's Encrypt staging service.
2. **Check ISE** confirms API access and reports whether ISE trusts the issuing chain. The first run reports that no certificate exists yet; that is expected.
3. **Renew and deploy** issues the first certificate, imports the CA chain if required, installs the certificate on ISE and waits for ISE to restart and confirm it.
4. Enable **Renew and deploy automatically** under **Settings > Maintenance window**.

## Upgrading

```bash
cd /usr/local/src/ise-cert-utility
git pull
./install.sh
```

The installer is idempotent. Settings, credentials, certificates and history are preserved, and the console account is left unchanged.

## Migrating from 1.x

Version 1.x stored settings in `/etc/ise-cert-sync` and ran everything as root. When `install.sh` finds `/etc/ise-cert-sync/config.json` it imports the hostname, node, API credentials, portal tag, EAP pin, schedule and the Cloudflare token automatically. Settings that 1.x kept as constants in `/usr/local/sbin/ise-cert-sync.py` (hostname, node, portal tag and EAP pin) are read from that script. You can also run it manually:

```bash
/opt/ise-cert-utility/venv/bin/ise-cert-utility migrate-legacy
```

After migrating:

1. Add the ACME account email under **Settings > Certificate and DNS**.
2. Run **Renew and deploy**. A fresh certificate is issued into the new Certbot directory; ISE is updated only if it is not already serving an identical certificate.

The installer stops and disables the 1.x units (`ise-cert-web.service`, `ise-cert-web-scheduler.timer`, `ise-cert-sync.timer`), because the 1.x console uses the same port and its timer would deploy alongside the new scheduler. It prints the commands to roll back. The 1.x files are not modified or removed by the migration.

## Uninstalling

```bash
systemctl disable --now ise-cert-utility-web.service ise-cert-utility-scheduler.timer
rm -f /etc/systemd/system/ise-cert-utility-* /usr/local/bin/ise-cert-utility /etc/default/ise-cert-utility
systemctl daemon-reload
rm -rf /opt/ise-cert-utility
# Removes credentials, certificates and history:
rm -rf /etc/ise-cert-utility /var/lib/ise-cert-utility
userdel ise-cert
```
