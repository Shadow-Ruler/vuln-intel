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


def apply(data_dir: str, observations: Iterable[Dict[str, Any]], now: dt.datetime) -> Dict[str, int]:
    stamp = common.ts(now)
    day = stamp[:10]
    stats = {"cve": 0, "ghsa": 0, "kev_new": 0, "epss": 0, "news": 0, "unchanged": 0}

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
