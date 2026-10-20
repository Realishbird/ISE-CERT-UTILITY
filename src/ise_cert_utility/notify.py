"""Outbound webhook notifications (Slack, Microsoft Teams workflows, or any JSON receiver)."""
import json
import socket
import urllib.error
import urllib.request

from . import config


def send(job, cfg=None, secret=None):
    cfg = cfg or config.load()
    secret = secret if secret is not None else config.secrets()
    url = secret.get("webhook_url")
    level = cfg.get("notify_on", "failure")
    if not url or level == "never" or (level == "failure" and job.get("state") != "failed"):
        return False
    host = socket.gethostname()
    summary = f"[{host}] {job.get('label', job.get('action'))}: {job.get('state')}. {job.get('message', '')}".strip()
    payload = {
        "text": summary,
        "source": "ise-cert-utility",
        "host": host,
        "domain": cfg.get("domain"),
        "action": job.get("action"),
        "state": job.get("state"),
        "message": job.get("message"),
        "scheduled": job.get("scheduled", False),
    }
    request = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=15) as response:
        response.read()
    return True
