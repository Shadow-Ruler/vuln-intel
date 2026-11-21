"""Commit stage: validate parser output and apply it to the data directory.

This is the only stage allowed to write the data branch. It trusts the
collector's report and manifest (produced by our own code) and nothing from the
parser: every observation is re-validated and tied back to a fetched document.

Usage: python3 -m pipeline.commit --data DIR --collected DIR --parsed DIR
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict

from . import common, store, validate

MAX_OBSERVATIONS = 300000


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
    summary = {"applied": stats, "rejected": rejected, "observations": len(valid)}
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
