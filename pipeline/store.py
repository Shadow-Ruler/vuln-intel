"""Data store: applies validated observations to the data branch's files.

Applying the same observations twice leaves the files unchanged, so a retried
run is harmless. Every path is built from an ID that already matched its
pattern, never from free text.

Layout:
  cves/<year>/<n>xxx/<CVE>.json   one record per CVE
  ghsa/<xx>/<GHSA>.json           one record per GitHub advisory
  kev.json                        CISA KEV entries keyed by CVE
  epss/current.json               CVEs at or above the 80th / 95th percentile
  news/<day>.jsonl                news items by the day the pipeline first saw them
  coverage/<kind>.json            public rules and exploits per CVE: [identifier, title, note]
  coverage/recent.json            CVEs that recently gained their first rule or exploit
  fixes/<year>/<n>xxx/<CVE>.json  fixed package versions per vendor (Red Hat, Debian, Ubuntu)
  state/                          cursors, heartbeat, news de-duplication index
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from typing import Any, Dict, Iterable

from . import common

NEWS_MAX_AGE_DAYS = 7
NEWS_SEEN_KEEP_DAYS = 60
COVERAGE_PER_CVE = 20
EXPLOIT_KINDS = ("metasploit", "exploitdb")   # working exploit code, as opposed to scanner templates or rules
FIX_ROWS_PER_VENDOR = 80
COVERAGE_RECENT_DAYS = 14
# More newly covered CVEs than this in one refresh is a list being re-indexed
# (Exploit-DB gained 2,837 at once on 23 November 2026), not that many new exploits.
COVERAGE_BURST = 300


def _without_fetch_time(obs: Dict[str, Any]) -> Dict[str, Any]:
    copy = {k: v for k, v in obs.items() if k not in ("src", "first_seen")}
    copy["_sha"] = (obs.get("src") or {}).get("sha256")
    return copy


def _write_record(path: str, obs: Dict[str, Any], now: str) -> bool:
    existing = common.read_json(path, None)
    if isinstance(existing, dict):
        if _without_fetch_time(existing) == _without_fetch_time(obs):
            return False
        obs["first_seen"] = existing.get("first_seen") or now
    else:
        obs["first_seen"] = now
    common.write_json_atomic(path, obs)
    return True


def _news_key(item: Dict[str, Any]) -> str:
    raw = "%s\n%s" % (item["src"]["origin"], item["url"])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _write_table(path: str, table: Dict[str, Any]) -> None:
    """One CVE per line, so a daily refresh changes only the lines that moved."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = ["%s:%s" % (json.dumps(key), json.dumps(table[key], separators=(",", ":"), ensure_ascii=True))
             for key in sorted(table)]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write("{\n" + ",\n".join(lines) + "\n}\n")
    os.replace(tmp, path)


def _apply_coverage(data_dir: str, coverage: Dict[str, Dict[str, set]], day: str, now: dt.datetime,
                    stats: Dict[str, int]) -> None:
    """Each source is a complete snapshot, so it replaces its file. CVEs that
    gained their first rule or exploit of a kind are noted in recent.json, so
    the scorer can look at them again."""
    recent_path = os.path.join(data_dir, "coverage", "recent.json")
    recent = common.read_json(recent_path, {})
    recent = recent if isinstance(recent, dict) else {}
    # What exploit code each CVE had before this run, across both exploit lists.
    had_exploit = set()
    for exploit_kind in EXPLOIT_KINDS:
        before = common.read_json(os.path.join(data_dir, "coverage", exploit_kind + ".json"), {})
        had_exploit.update(before if isinstance(before, dict) else {})
    for kind, found in coverage.items():
        path = os.path.join(data_dir, "coverage", kind + ".json")
        old = common.read_json(path, {})
        old = old if isinstance(old, dict) else {}
        new = {cve: [list(item) for item in sorted(items)[:COVERAGE_PER_CVE]] for cve, items in found.items()}
        if old and len(new) * 2 < len(old):
            # A snapshot that lost over half its entries is more likely truncated than true.
            stats["coverage_refused"] = stats.get("coverage_refused", 0) + 1
            continue
        if new == old:
            continue
        added = [cve for cve in new if cve not in old] if old else []  # on the first load everything would look new
        if len(added) > COVERAGE_BURST:
            # Stored like any other snapshot, but nothing in it is called news.
            stats["coverage_bursts"] = stats.get("coverage_bursts", 0) + 1
            added = []
        for cve in added:
            entry = recent.get(cve) if isinstance(recent.get(cve), dict) else {"kinds": []}
            entry["day"] = day
            entry["kinds"] = sorted(set(entry.get("kinds", [])) | {kind})
            if kind in EXPLOIT_KINDS and cve not in had_exploit:
                # Its first exploit code ever, not just a second listing
                # or a new scanner template for a long-known exploit.
                entry["first_exploit"] = True
            recent[cve] = entry
        _write_table(path, new)
        stats["coverage"] += 1
    cutoff = (now - dt.timedelta(days=COVERAGE_RECENT_DAYS)).strftime("%Y-%m-%d")
    recent = {cve: entry for cve, entry in recent.items()
              if isinstance(entry, dict) and str(entry.get("day", "")) >= cutoff}
    _write_table(recent_path, recent)


def apply(data_dir: str, observations: Iterable[Dict[str, Any]], now: dt.datetime) -> Dict[str, int]:
    stamp = common.ts(now)
    day = stamp[:10]
    stats = {"cve": 0, "ghsa": 0, "kev_new": 0, "epss": 0, "news": 0, "unchanged": 0, "coverage": 0}

    kev_path = os.path.join(data_dir, "kev.json")
    kev = common.read_json(kev_path, {})
    if not isinstance(kev, dict):
        kev = {}
    kev_changed = False

    seen_path = os.path.join(data_dir, "state", "news_seen.json")
    seen = common.read_json(seen_path, {})
    if not isinstance(seen, dict):
        seen = {}
    fresh_news = []
    coverage: Dict[str, Dict[str, set]] = {}
    fixes: Dict[Any, set] = {}

    for obs in observations:
        kind = obs["type"]
        if kind == "cve":
            path = os.path.join(data_dir, common.cve_relpath(obs["id"]))
            stats["cve" if _write_record(path, obs, stamp) else "unchanged"] += 1
        elif kind == "ghsa":
            path = os.path.join(data_dir, "ghsa", obs["id"][5:7], obs["id"] + ".json")
            stats["ghsa" if _write_record(path, obs, stamp) else "unchanged"] += 1
        elif kind == "kev":
            entry = {k: obs[k] for k in ("vendor", "product", "name", "date_added", "due_date", "ransomware")}
            previous = kev.get(obs["cve"])
            if not isinstance(previous, dict):
                entry["first_seen"] = stamp
                kev[obs["cve"]] = entry
                stats["kev_new"] += 1
                kev_changed = True
            else:
                entry["first_seen"] = previous.get("first_seen") or stamp
                if entry != previous:
                    kev[obs["cve"]] = entry
                    kev_changed = True
        elif kind == "epss":
            common.write_json_atomic(
                os.path.join(data_dir, "epss", "current.json"),
                {"date": obs["date"], "model": obs["model"], "p95": obs["p95"], "p80": obs["p80"],
                 "src": obs["src"]},
            )
            stats["epss"] += 1
        elif kind == "fix":
            fixes.setdefault((obs["cve"], obs["vendor"]), set()).add(
                (obs["product"], obs["package"], obs["fixed"], obs["state"], obs["advisory"]))
        elif kind == "coverage":
            coverage.setdefault(obs["kind"], {}).setdefault(obs["cve"], set()).add(
                (obs["ident"], obs["title"], obs["note"]))
        elif kind == "news":
            published = common.parse_ts(obs["published"])
            if published and (now - published).days > NEWS_MAX_AGE_DAYS:
                continue
            key = _news_key(obs)
            if key in seen:
                continue
            seen[key] = day
            item = dict(obs)
            item["seen"] = stamp
            fresh_news.append(item)
            stats["news"] += 1

    if coverage:
        _apply_coverage(data_dir, coverage, day, now, stats)
    # Each vendor document is that vendor's complete statement for the CVE, so
    # it replaces what was stored for that vendor and leaves the others alone.
    for (cve, vendor), rows in fixes.items():
        path = os.path.join(data_dir, "fixes" + common.cve_relpath(cve)[len("cves"):])
        record = common.read_json(path, {})
        record = record if isinstance(record, dict) else {}
        new = [dict(zip(("product", "package", "fixed", "state", "advisory"), row))
               for row in sorted(rows)[:FIX_ROWS_PER_VENDOR]]
        if record.get(vendor) != new:
            record[vendor] = new
            record["updated"] = stamp
            common.write_json_atomic(path, record)
            stats["fix"] = stats.get("fix", 0) + 1
    if kev_changed:
        common.write_json_atomic(kev_path, kev)
    if fresh_news:
        news_path = os.path.join(data_dir, "news", day + ".jsonl")
        os.makedirs(os.path.dirname(news_path), exist_ok=True)
        with open(news_path, "a", encoding="utf-8") as handle:
            for item in fresh_news:
                handle.write(json.dumps(item, sort_keys=True, ensure_ascii=True) + "\n")
        cutoff = (now - dt.timedelta(days=NEWS_SEEN_KEEP_DAYS)).strftime("%Y-%m-%d")
        seen = {key: value for key, value in seen.items() if isinstance(value, str) and value >= cutoff}
        common.write_json_atomic(seen_path, seen)
    return stats
