"""Small helpers."""
from __future__ import annotations

import re


def slugify(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")
    return value or "client"
