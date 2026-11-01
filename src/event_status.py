"""Canonical event status values used across HashGuard."""

from enum import StrEnum


class EventStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


EVENT_STATUSES = tuple(status.value for status in EventStatus)
