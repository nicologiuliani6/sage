"""Finestre di manutenzione: 'sat 02:00-06:00', 'sat,sun 22:00-02:00'."""

from __future__ import annotations

from datetime import datetime, time, timedelta

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


# ------------------------------------------------------------------ cron

CRON_ALIASES = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
    "@monthly": "0 0 1 * *",
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
}
CRON_RANGES = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))


def _cron_field(text: str, low: int, high: int) -> set[int]:
    values: set[int] = set()
    for part in text.split(","):
        body, _, step_text = part.partition("/")
        step = int(step_text) if step_text else 1
        if step < 1:
            raise ValueError(part)
        if body == "*":
            start, end = low, high
        elif "-" in body:
            start, end = (int(x) for x in body.split("-", 1))
        else:
            start = int(body)
            end = high if step_text else start
        if not (low <= start <= end <= high):
            raise ValueError(part)
        values.update(range(start, end + 1, step))
    return values


def next_run(expr: str, after: datetime, limit_days: int = 366) -> datetime | None:
    """Prossima esecuzione di un'espressione cron a 5 campi, nel fuso di `after`.

    Come cron: se giorno del mese e giorno della settimana sono entrambi limitati, basta
    che uno dei due corrisponda. None se l'espressione non è valida.
    """
    expr = CRON_ALIASES.get(expr.strip(), expr)
    fields = expr.split()
    if len(fields) != 5:
        return None
    try:
        minutes, hours, mdays, months, wdays = (
            _cron_field(f, low, high) for f, (low, high) in zip(fields, CRON_RANGES, strict=True)
        )
    except ValueError:
        return None
    wdays = {d % 7 for d in wdays}  # 7 = domenica, come 0
    mday_any, wday_any = fields[2] == "*", fields[4] == "*"
    current = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    end = after + timedelta(days=limit_days)
    while current <= end:
        cron_wday = (current.weekday() + 1) % 7  # cron: 0 = domenica
        if mday_any or wday_any:
            day_ok = (current.day in mdays) and (cron_wday in wdays)
        else:
            day_ok = current.day in mdays or cron_wday in wdays
        if current.month not in months or not day_ok:
            current = (current + timedelta(days=1)).replace(hour=0, minute=0)
            continue
        if current.hour not in hours:
            current = (current + timedelta(hours=1)).replace(minute=0)
            continue
        if current.minute in minutes:
            return current
        current += timedelta(minutes=1)
    return None


def next_window(window: str | None, now: datetime) -> datetime | None:
    """Inizio della prossima finestra di manutenzione (o `now` se è già aperta)."""
    if not window:
        return None
    if in_window(window, now):
        return now
    match = WINDOW_RE.match(window)
    if not match:
        return None
    days = {DAYS.index(d) for d in match.group("days").split(",")}
    start = time.fromisoformat(match.group("start"))
    for offset in range(8):
        day = now + timedelta(days=offset)
        candidate = day.replace(hour=start.hour, minute=start.minute, second=0, microsecond=0)
        if candidate.weekday() in days and candidate > now:
            return candidate
    return None
