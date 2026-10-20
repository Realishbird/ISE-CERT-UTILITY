"""Maintenance-window arithmetic.

A window is identified by the local date on which it opens, so an overnight
window such as 22:00-02:00 belongs to the day it started. Weekday filters apply
to that opening date.
"""
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo


def _local(cfg, now):
    tz = ZoneInfo(cfg["timezone"])
    return datetime.now(tz) if now is None else now.astimezone(tz)


def window(cfg, now=None):
    """Return the ISO date the current window opened on, or None when outside a window."""
    now = _local(cfg, now)
    current = now.strftime("%H:%M")
    start, end = cfg["window_start"], cfg["window_end"]
    if start < end:
        inside = start <= current < end
        opened = now.date()
    else:
        inside = current >= start or current < end
        opened = now.date() - timedelta(days=1) if current < end else now.date()
    if not inside or opened.weekday() not in cfg["weekdays"]:
        return None
    return opened.isoformat()


def next_window(cfg, now=None):
    """Return the next window opening as an aware datetime (the current one if open)."""
    now = _local(cfg, now)
    hour, minute = map(int, cfg["window_start"].split(":"))
    for offset in range(-1, 8):
        day = now.date() + timedelta(days=offset)
        if day.weekday() not in cfg["weekdays"]:
            continue
        opens = datetime(day.year, day.month, day.day, hour, minute, tzinfo=now.tzinfo)
        if window(cfg, opens) == day.isoformat() and (opens > now or window(cfg, now) == day.isoformat()):
            return opens
    return None


def due(cfg, state, now=None):
    """Decide whether the scheduler should start a run.

    The first run in a window always starts. Later runs in the same window are
    retries, allowed only after a failure, after retry_minutes, and while the
    attempt budget lasts.
    """
    if not cfg.get("schedule_enabled"):
        return False
    now = _local(cfg, now)
    anchor = window(cfg, now)
    if anchor is None:
        return False
    if state.get("window") != anchor:
        return True
    if state.get("result") != "failed":
        return False
    if state.get("attempts", 0) >= cfg["max_attempts"]:
        return False
    return now.timestamp() - state.get("started", 0) >= cfg["retry_minutes"] * 60
