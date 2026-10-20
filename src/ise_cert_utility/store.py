"""Atomic JSON persistence and cross-process locking."""
import contextlib
import fcntl
import json
import os
import secrets
from pathlib import Path

from . import paths


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return {} if default is None else default
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{path} is not valid JSON; restore it from backup or delete it.") from exc


def write_private(path, data):
    """Write bytes or text atomically with mode 0600."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(f".{path.name}.{secrets.token_hex(6)}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data.encode() if isinstance(data, str) else data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()
        raise


def write_json(path, value):
    write_private(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


@contextlib.contextmanager
def exclusive(path=None, wait=False, busy_message="Another operation is in progress. Try again shortly."):
    path = Path(path or paths.LOCK)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle = open(path, "a")
    try:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError:
            raise ValueError(busy_message) from None
        yield
    finally:
        handle.close()
