"""Finestre di manutenzione: 'sat 02:00-06:00', 'sat,sun 22:00-02:00'."""

from __future__ import annotations

from datetime import datetime, time

from sage.config import WINDOW_RE

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def in_window(window: str | None, now: datetime) -> bool:
    """`now` deve essere già nel fuso orario della finestra.

    Una finestra che attraversa la mezzanotte (22:00-02:00) appartiene al giorno
    in cui inizia: 'sat 22:00-02:00' copre sabato 22:00 - domenica 02:00.
    """
    if not window:
        return False
    match = WINDOW_RE.match(window)
    if not match:
        return False
    days = {DAYS.index(d) for d in match.group("days").split(",")}
    start = time.fromisoformat(match.group("start"))
    end = time.fromisoformat(match.group("end"))
    current, weekday = now.time(), now.weekday()
    if start <= end:
        return weekday in days and start <= current < end
    if current >= start:
        return weekday in days
    return (weekday - 1) % 7 in days and current < end
