"""Shared helpers. Standard library only; runs on Python 3.9+."""
from __future__ import annotations

import datetime as dt
import email.utils
import hashlib
import json
import os
import re
import unicodedata
from typing import Any, Iterator, Optional

CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$")
CVE_FIND_RE = re.compile(r"(?<![A-Za-z0-9])CVE-\d{4}-\d{4,7}(?!\d)", re.IGNORECASE)
GHSA_RE = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
URL_RE = re.compile(r"^https?://[^\s<>\"'`\\]{1,2000}$")

_WS = re.compile(r"\s+")
_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?\s*(Z|[+-]\d{2}:?\d{2})?)?$"
)


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def ts(value: Optional[dt.datetime] = None) -> str:
    """Format a datetime as a UTC timestamp, second precision."""
    return (value or utcnow()).astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: Any) -> Optional[dt.datetime]:
    """Parse an ISO 8601 date or timestamp. Returns None when it does not parse."""
    if not isinstance(value, str):
        return None
    match = _ISO.match(value.strip())
    if not match:
        return None
    year, month, day, hour, minute, second, zone = match.groups()
    tzinfo = dt.timezone.utc
    if zone and zone != "Z":
        sign = -1 if zone[0] == "-" else 1
        digits = zone[1:].replace(":", "")
        tzinfo = dt.timezone(sign * dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    try:
        parsed = dt.datetime(
            int(year), int(month), int(day),
            int(hour or 0), int(minute or 0), int(second or 0), tzinfo=tzinfo,
        )
    except ValueError:
        return None
    return parsed.astimezone(dt.timezone.utc)


def parse_any_date(value: Any) -> Optional[dt.datetime]:
    """Parse an ISO 8601 or RFC 822 date, as found in JSON APIs and RSS feeds."""
    parsed = parse_ts(value)
    if parsed or not isinstance(value, str):
        return parsed
    try:
        parsed = email.utils.parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def clean_text(value: Any, max_len: int) -> str:
    """Drop control, format and private-use characters, collapse whitespace, truncate."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        value = str(value)
    if not isinstance(value, str):
        return ""
    out = []
    for char in value[: max_len * 4]:
        category = unicodedata.category(char)
        if category == "Cc":
            out.append(" ")
        elif category in ("Cf", "Co", "Cs", "Cn"):
            continue
        else:
            out.append(char)
    return _WS.sub(" ", "".join(out)).strip()[:max_len]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cve_relpath(cve_id: str) -> str:
    """Relative path of a CVE record, mirroring the cvelistV5 layout."""
    match = CVE_RE.match(cve_id)
    if not match:
        raise ValueError("not a CVE ID: %r" % (cve_id,))
    year, number = match.groups()
    return "cves/%s/%sxxx/%s.json" % (year, number[:-3], cve_id)


def read_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default


def write_json_atomic(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=True))
        handle.write("\n")
    os.replace(tmp, path)


def read_jsonl(path: str, max_line: int = 16 * 1024 * 1024) -> Iterator[Any]:
    """Yield parsed lines; skips lines that are too long or not JSON objects."""
    try:
        handle = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return
    with handle:
        for line in handle:
            if not line.strip() or len(line) > max_line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if isinstance(obj, dict):
                yield obj
