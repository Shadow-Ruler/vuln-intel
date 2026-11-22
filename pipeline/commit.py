"""Commit stage: validate parser output and apply it to the data directory.

This is the only stage allowed to write the data branch. It trusts the
collector's report and manifest (produced by our own code) and nothing from the
parser: every observation is re-validated and tied back to a fetched document.

Usage: python3 -m pipeline.commit --data DIR --collected DIR --parsed DIR
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from typing import Any, Dict

from . import common, store, validate

MAX_OBSERVATIONS = 300000
WANTED_NEWS_DAYS = 7     # CVEs named in news this recently are worth a record
WANTED_KEV_DAYS = 30     # and so are CVEs added to KEV this recently
WANTED_KEEP_DAYS = 30
WANTED_MAX = 3000
ENRICH_KEEP_DAYS = 30    # keep asking vendors about a CVE this long after it was last named
ENRICH_MAX = 4000


def load_manifest(path: str) -> Dict[str, Dict[str, Any]]:
    manifest = {}
    for entry in common.read_jsonl(path):
        digest = entry.get("sha256")
        if isinstance(digest, str) and common.SHA256_RE.match(digest):
            manifest[digest] = entry
    return manifest


def update_state(data_dir, report, parse_report, rejected, now_stamp):
    """Advance cursors and write the per-source heartbeat."""
    state_dir = os.path.join(data_dir, "state")
    heartbeat = common.read_json(os.path.join(state_dir, "heartbeat.json"), {})
    if not isinstance(heartbeat, dict):
        heartbeat = {}
    sources = heartbeat.get("sources") if isinstance(heartbeat.get("sources"), dict) else {}
    cursors = common.read_json(os.path.join(state_dir, "cursors.json"), {})
    if not isinstance(cursors, dict):
        cursors = {}
    parsed = parse_report.get("sources") if isinstance(parse_report.get("sources"), dict) else {}
    attempted_at = report.get("at") or now_stamp

    for sid, entry in (report.get("sources") or {}).items():
        if not common.SOURCE_ID_RE.match(sid) or not isinstance(entry, dict):
            continue
        beat = sources.get(sid) if isinstance(sources.get(sid), dict) else {}
        status = entry.get("status")
        detail = str(entry.get("detail", ""))[:300]
        stats = parsed.get(sid) if isinstance(parsed.get(sid), dict) else {}
        files, file_errors = int(stats.get("files", 0)), int(stats.get("errors", 0))
        observations, dropped = int(stats.get("observations", 0)), rejected.get(sid, 0)

        # A cursor only advances when the documents behind it were parsed, so a
        # failed parse is fetched again next run instead of being skipped. A few
        # bad records in a large batch, or a few rejected items, are tolerated.
        if status == "ok" and files == 0:
            status, detail = "error", "fetched documents never reached the parser"
        elif status == "ok" and file_errors:
            detail = ("%d of %d documents failed to parse: %s"
                      % (file_errors, files, stats.get("last_error", "")))[:300]
            if file_errors * 10 > files:
                status = "parse_error"
        elif status == "ok" and dropped:
            detail = "%d of %d observations rejected by validation" % (dropped, observations)
            if dropped * 2 > observations:
                status = "parse_error"

        beat.update({"last_attempt": attempted_at, "status": status, "detail": detail,
                     "every_minutes": entry.get("every_minutes", 60), "role": entry.get("role", "")})
        if status in ("ok", "unchanged"):
            beat["last_ok"] = attempted_at
            beat["consecutive_errors"] = 0
            if status == "ok":
                beat["last_change"] = attempted_at
            cursor = (report.get("cursors") or {}).get(sid)
            if isinstance(cursor, dict):
                cursors[sid] = cursor
        else:
            beat["consecutive_errors"] = int(beat.get("consecutive_errors", 0)) + 1
        sources[sid] = beat

    common.write_json_atomic(os.path.join(state_dir, "heartbeat.json"),
                             {"updated": now_stamp, "sources": sources})
    common.write_json_atomic(os.path.join(state_dir, "cursors.json"), cursors)
    return sources


def update_wanted(data_dir: str, report: Dict[str, Any], now) -> Dict[str, int]:
    """Keep the list of CVE records to backfill.

    A CVE named in recent news or newly added to KEV, with no record in the
    store, is marked pending. The collector tries it once: if the record
    exists it arrives through the normal path and the entry is dropped; if
    cvelistV5 has no such record the entry becomes "missing", which tells the
    scorer the CVE really is unpublished.
    """
    path = os.path.join(data_dir, "state", "wanted.json")
    wanted = common.read_json(path, {})
    wanted = wanted if isinstance(wanted, dict) else {}
    stamp = common.ts(now)

    def has_record(cve: str) -> bool:
        return os.path.exists(os.path.join(data_dir, common.cve_relpath(cve)))

    named = set()
    for back in range(WANTED_NEWS_DAYS + 1):
        day = (now - dt.timedelta(days=back)).strftime("%Y-%m-%d")
        for item in common.read_jsonl(os.path.join(data_dir, "news", day + ".jsonl")):
            cves = item.get("cves")
            named.update(c for c in (cves if isinstance(cves, list) else [])
                         if isinstance(c, str) and common.CVE_RE.match(c))
    kev = common.read_json(os.path.join(data_dir, "kev.json"), {})
    cutoff = now - dt.timedelta(days=WANTED_KEV_DAYS)
    for cve, entry in (kev.items() if isinstance(kev, dict) else []):
        added = common.parse_ts(entry.get("date_added")) if isinstance(entry, dict) else None
        if added and added >= cutoff and common.CVE_RE.match(cve):
            named.add(cve)

    for cve in named:
        if cve not in wanted and not has_record(cve):
            wanted[cve] = {"status": "pending", "since": stamp}

    # The same CVEs are the ones worth asking vendors about (fixed versions).
    enrich_path = os.path.join(data_dir, "state", "enrich.json")
    enrich = common.read_json(enrich_path, {})
    enrich = enrich if isinstance(enrich, dict) else {}
    for cve in named:
        enrich[cve] = stamp[:10]
    keep_from = (now - dt.timedelta(days=ENRICH_KEEP_DAYS)).strftime("%Y-%m-%d")
    enrich = {cve: day for cve, day in enrich.items()
              if isinstance(day, str) and day >= keep_from and common.CVE_RE.match(cve)}
    if len(enrich) > ENRICH_MAX:
        enrich = dict(sorted(enrich.items(), key=lambda item: (item[1], item[0]), reverse=True)[:ENRICH_MAX])
    common.write_json_atomic(enrich_path, enrich)
    for entry in (report.get("sources") or {}).values():
        backfill = entry.get("backfill") if isinstance(entry, dict) else None
        for cve in (backfill.get("missing") or []) if isinstance(backfill, dict) else []:
            if isinstance(wanted.get(cve), dict):
                wanted[cve].update({"status": "missing", "checked": stamp})

    oldest = now - dt.timedelta(days=WANTED_KEEP_DAYS)
    for cve in list(wanted):
        entry = wanted[cve]
        since = common.parse_ts(entry.get("since")) if isinstance(entry, dict) else None
        if not common.CVE_RE.match(cve) or since is None or since < oldest or has_record(cve):
            del wanted[cve]
    if len(wanted) > WANTED_MAX:
        keep = sorted(wanted, key=lambda cve: wanted[cve]["since"], reverse=True)[:WANTED_MAX]
        wanted = {cve: wanted[cve] for cve in keep}
    common.write_json_atomic(path, wanted)
    return {"pending": sum(1 for e in wanted.values() if e.get("status") == "pending"),
            "missing": sum(1 for e in wanted.values() if e.get("status") == "missing")}


def run(data_dir: str, collected_dir: str, parsed_dir: str, now=None) -> Dict[str, Any]:
    now = now or common.utcnow()
    report = common.read_json(os.path.join(collected_dir, "collect-report.json"), {}) or {}
    manifest = load_manifest(os.path.join(collected_dir, "manifest.jsonl"))
    parse_report = common.read_json(os.path.join(parsed_dir, "parse-report.json"), {}) or {}

    valid, rejected = [], {}
    count = 0
    for obs in common.read_jsonl(os.path.join(parsed_dir, "observations.jsonl")):
        count += 1
        if count > MAX_OBSERVATIONS:
            break
        try:
            valid.append(validate.validate(obs, manifest))
        except validate.Invalid:
            source = (obs.get("src") or {}).get("source") if isinstance(obs.get("src"), dict) else None
            key = source if isinstance(source, str) and common.SOURCE_ID_RE.match(source) else "unknown"
            rejected[key] = rejected.get(key, 0) + 1

    stats = store.apply(data_dir, valid, now)
    update_state(data_dir, report, parse_report, rejected, common.ts(now))
    wanted = update_wanted(data_dir, report, now)
    summary = {"applied": stats, "rejected": rejected, "observations": len(valid), "wanted": wanted}
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True)
    parser.add_argument("--collected", required=True, help="directory with collect-report.json and manifest.jsonl")
    parser.add_argument("--parsed", required=True, help="directory with observations.jsonl and parse-report.json")
    args = parser.parse_args(argv)
    os.makedirs(args.data, exist_ok=True)
    print(json.dumps(run(args.data, args.collected, args.parsed), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
