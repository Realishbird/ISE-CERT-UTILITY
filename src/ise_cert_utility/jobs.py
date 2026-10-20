"""Background operations: one at a time, logged, scrubbed of secrets, and recorded in history."""
import os
import re
import secrets
import selectors
import signal
import subprocess
import sys
import time

from . import acme, config, ise, notify, paths, schedule, store

ACTIONS = {
    "check": "Check ISE",
    "test-renewal": "Test renewal",
    "renew": "Renew and deploy",
    "deploy": "Deploy to ISE",
    "trust-chain": "Import CA chain",
}
DISRUPTIVE = {"renew", "deploy"}
HISTORY_LIMIT = 100
LOG_LIMIT = 500_000
PRIVATE_KEY = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S)


def current():
    """Return the current job, marking it interrupted if its worker died."""
    job = store.read_json(paths.JOB)
    if job.get("state") in ("queued", "running"):
        pid = job.get("pid")
        dead = False
        if pid:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                dead = True
            except PermissionError:
                pass
        elif time.time() - job.get("started", 0) > 60:
            dead = True
        if dead:
            job.update(state="interrupted", finished=time.time(),
                       message="The worker stopped unexpectedly. Check ISE before retrying an import.")
            store.write_json(paths.JOB, job)
            _remember(job)
    return job


def busy():
    return current().get("state") in ("queued", "running")


def history(limit=25):
    return store.read_json(paths.HISTORY, default=[])[-limit:][::-1]


def _remember(job):
    entries = store.read_json(paths.HISTORY, default=[])
    entries = [e for e in entries if e.get("id") != job["id"]] + [
        {k: job.get(k) for k in ("id", "action", "label", "state", "message", "started", "finished", "scheduled")}]
    store.write_json(paths.HISTORY, entries[-HISTORY_LIMIT:])


def start(action, scheduled=False, force=False, spawn=True):
    if action not in ACTIONS:
        raise ValueError("Unknown operation.")
    with store.exclusive():
        if busy():
            raise ValueError("Another operation is already running.")
        job = {"id": secrets.token_hex(10), "action": action, "label": ACTIONS[action], "state": "queued",
               "started": time.time(), "scheduled": scheduled, "force": bool(force)}
        store.write_json(paths.JOB, job)
        if spawn:
            try:
                subprocess.Popen([sys.executable, "-m", "ise_cert_utility", "worker", job["id"]],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True, close_fds=True)
            except OSError:
                job.update(state="failed", message="The background worker could not be started.")
                store.write_json(paths.JOB, job)
                raise
    return job


class Log:
    """Append-only operation log that never records credentials or private keys."""

    def __init__(self, echo=False):
        self.echo = echo
        self.size = 0
        self.secrets = [v for v in config.secrets().values() if isinstance(v, str) and len(v) >= 4]
        store.write_private(paths.JOB_LOG, "")

    def scrub(self, text):
        for value in self.secrets:
            text = text.replace(value, "[redacted]")
        return PRIVATE_KEY.sub("[private key redacted]", text)

    def __call__(self, line):
        clean = self.scrub(line.rstrip("\n"))
        stamped = f"{time.strftime('%H:%M:%S')}  {clean}\n"
        if self.size < LOG_LIMIT:
            with open(paths.JOB_LOG, "a") as out:
                out.write(stamped)
            self.size += len(stamped)
        if self.echo:
            print(clean, flush=True)

    def run(self, args, timeout=2700):
        """Run a command, streaming scrubbed output. Lines inside a PEM private key are dropped."""
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   env={**os.environ, "PYTHONUNBUFFERED": "1"}, start_new_session=True)
        deadline = time.monotonic() + timeout
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        buffer, in_key = b"", False
        try:
            while True:
                if time.monotonic() > deadline:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise RuntimeError(f"{os.path.basename(args[0])} timed out after {timeout // 60} minutes.")
                if not selector.select(timeout=1):
                    continue
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    if buffer and not in_key:
                        self(buffer.decode(errors="replace"))
                    break
                buffer += chunk
                while b"\n" in buffer or len(buffer) > 16384:
                    if b"\n" in buffer:
                        raw, buffer = buffer.split(b"\n", 1)
                    else:
                        raw, buffer = buffer[:16384], buffer[16384:]
                    text = raw.decode(errors="replace")
                    if "-----BEGIN" in text and "PRIVATE KEY-----" in text:
                        in_key = True
                    if not in_key and text.strip():
                        self(text)
                    if "-----END" in text and "PRIVATE KEY-----" in text:
                        in_key = False
            code = process.wait(timeout=30)
        finally:
            selector.close()
            process.stdout.close()
        if code:
            raise RuntimeError(f"{os.path.basename(args[0])} exited with status {code}; see the operation log.")


def _execute(job, log):
    cfg = config.load()
    secret = config.secrets()
    action = job["action"]
    gaps = config.missing(cfg, secret)
    if action == "test-renewal":
        gaps = [g for g in gaps if not g.startswith("ISE")]
    if gaps:
        raise RuntimeError("Complete the configuration first: " + ", ".join(gaps) + ".")

    def in_window():
        return not job.get("scheduled") or (cfg["schedule_enabled"] and schedule.window(cfg) is not None)

    if not in_window():
        raise RuntimeError("The maintenance window closed before the run started.")

    if action == "test-renewal":
        log("Requesting a test certificate from the Let's Encrypt staging environment (nothing is saved).")
        log.run(acme.certbot_args(cfg, dry_run=True))
        return "DNS validation through Cloudflare works. A real renewal will succeed."

    client = ise.Client.from_config(cfg, secret)
    if action == "check":
        leaf, rows = ise.preflight(cfg, client, log)
        state = store.read_json(paths.ISE_STATE)
        return ("ISE already serves the current certificate." if state.get("deployed")
                else "Ready to deploy. ISE does not serve the current certificate yet.")
    if action == "trust-chain":
        ise.preflight(cfg, client, log, import_chain=True)
        return "ISE trusts the full issuing chain."

    if action == "renew":
        run, force, reason = acme.renewal_decision(cfg, force=job.get("force"))
        log(reason)
        if run:
            log.run(acme.certbot_args(cfg, force=force))
            log("Certificate issued.")
        if job.get("scheduled") and not in_window():
            log("The window closed after renewal; deployment will run in the next window.")
            return "Certificate renewed; deployment deferred to the next window."
    outcome = ise.deploy(cfg, client, log, may_import=in_window)
    return {
        "unchanged": "Certificate is current and already deployed.",
        "deployed": "New certificate deployed and verified on ISE.",
        "deferred": "Deployment deferred to the next maintenance window.",
    }[outcome]


def work(job_id, echo=False):
    job = store.read_json(paths.JOB)
    if job.get("id") != job_id or job.get("state") != "queued":
        return job
    job.update(state="running", pid=os.getpid())
    store.write_json(paths.JOB, job)
    log = Log(echo=echo)
    log(f"{job['label']} started{' by the scheduler' if job.get('scheduled') else ''}.")
    try:
        with store.exclusive(paths.DEPLOY_LOCK, busy_message="Another worker holds the deployment lock."):
            job.update(state="succeeded", message=_execute(job, log))
    except Exception as exc:  # noqa: BLE001 - every failure must be recorded
        known = isinstance(exc, (RuntimeError, ValueError, OSError, subprocess.SubprocessError))
        message = log.scrub(str(exc)) if known else f"Unexpected {type(exc).__name__}; see the service journal."
        job.update(state="failed", message=message)
        log(f"Failed: {message}")
    else:
        log(job["message"])
    job["finished"] = time.time()
    store.write_json(paths.JOB, job)
    _remember(job)
    try:
        notify.send(job)
    except Exception as exc:  # noqa: BLE001 - notification failure must not mask the result
        log(f"Notification could not be delivered: {type(exc).__name__}.")
    return job


def scheduled_tick(echo=False):
    """Called every minute by the systemd timer."""
    cfg = config.load()
    state = store.read_json(paths.SCHEDULER)
    if not schedule.due(cfg, state):
        return None
    anchor = schedule.window(cfg)
    try:
        job = start("renew", scheduled=True, spawn=False)
    except ValueError:
        return None
    attempts = state.get("attempts", 0) + 1 if state.get("window") == anchor else 1
    store.write_json(paths.SCHEDULER, {"window": anchor, "attempts": attempts, "started": job["started"],
                                       "result": "running"})
    job = work(job["id"], echo=echo)
    state = store.read_json(paths.SCHEDULER)
    state["result"] = job.get("state")
    store.write_json(paths.SCHEDULER, state)
    return job
