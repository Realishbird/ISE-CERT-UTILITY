from datetime import datetime
from zoneinfo import ZoneInfo

from ise_cert_utility import schedule

TZ = ZoneInfo("America/Chicago")
BASE = {"schedule_enabled": True, "timezone": "America/Chicago", "window_start": "02:00", "window_end": "04:00",
        "weekdays": list(range(7)), "retry_minutes": 30, "max_attempts": 3}


def at(day, hhmm):
    h, m = map(int, hhmm.split(":"))
    return datetime(2026, 10, day, h, m, tzinfo=TZ)


def test_same_day_window():
    assert schedule.window(BASE, at(20, "02:00")) == "2026-10-20"
    assert schedule.window(BASE, at(20, "03:59")) == "2026-10-20"
    assert schedule.window(BASE, at(20, "04:00")) is None
    assert schedule.window(BASE, at(20, "01:59")) is None


def test_overnight_window_belongs_to_opening_day():
    cfg = {**BASE, "window_start": "22:00", "window_end": "02:00"}
    assert schedule.window(cfg, at(20, "23:00")) == "2026-10-20"
    assert schedule.window(cfg, at(21, "01:30")) == "2026-10-20"
    assert schedule.window(cfg, at(21, "02:00")) is None


def test_weekday_filter_uses_opening_day():
    # 2026-10-24 is a Saturday.
    cfg = {**BASE, "weekdays": [0, 1, 2, 3, 4], "window_start": "23:00", "window_end": "01:00"}
    assert schedule.window(cfg, at(23, "23:30")) == "2026-10-23"  # Friday night
    assert schedule.window(cfg, at(24, "00:30")) == "2026-10-23"  # still Friday's window
    assert schedule.window(cfg, at(24, "23:30")) is None          # Saturday


def test_due_first_run_then_retry_only_after_failure():
    now = at(20, "02:10")
    assert schedule.due(BASE, {}, now)
    ran = {"window": "2026-10-20", "attempts": 1, "started": at(20, "02:01").timestamp(), "result": "succeeded"}
    assert not schedule.due(BASE, ran, now)
    failed = {**ran, "result": "failed"}
    assert not schedule.due(BASE, failed, now)                 # too soon
    assert schedule.due(BASE, failed, at(20, "02:31"))
    assert not schedule.due(BASE, {**failed, "attempts": 3}, at(20, "03:30"))


def test_disabled_never_due():
    assert not schedule.due({**BASE, "schedule_enabled": False}, {}, at(20, "02:10"))


def test_next_window():
    assert schedule.next_window(BASE, at(20, "05:00")) == at(21, "02:00")
    assert schedule.next_window(BASE, at(20, "02:30")) == at(20, "02:00")
    cfg = {**BASE, "weekdays": [0]}  # Mondays; 2026-10-20 is a Tuesday
    assert schedule.next_window(cfg, at(20, "05:00")) == at(26, "02:00")
