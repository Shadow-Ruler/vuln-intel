"""Collect stage: fetch raw documents from allowlisted sources.

This is the only stage with network access. It stores bytes addressed by
SHA-256 and writes a manifest; it does not interpret what it downloads. The one
exception is the cvelistV5 change log, a JSON index it must read to learn which
records changed.

Usage: python3 -m pipeline.collect --config config/sources.json --state DIR --out DIR
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from typing import Any, Dict, List, Optional, Tuple

from . import common

DUE_SLACK_SECONDS = 300
MAX_RUN_BYTES = 600 * 1024 * 1024
PARSERS = ("cve", "kev", "epss", "ghsa", "hn", "feed")


class FetchError(Exception):
    pass


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only when it stays on HTTPS and on an allowlisted host."""

    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        # A source may opt in to redirects to any HTTPS host (for files served
        # from a CDN whose hostname is not stable). Never plain HTTP.
        any_https = getattr(req, "any_https_redirect", False)
        if parts.scheme != "https" or not (any_https or (parts.hostname or "").lower() in self.hosts):
            raise urllib.error.HTTPError(
                req.full_url, code, "redirect to a host outside the allowlist was blocked", headers, fp
            )
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.any_https_redirect = any_https
        return new


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        cfg = json.load(handle)
    seen = set()
    for src in cfg.get("sources", []):
        sid = src.get("id", "")
        if not common.SOURCE_ID_RE.match(sid) or sid in seen:
            raise ValueError("bad or duplicate source id: %r" % (sid,))
        seen.add(sid)
        if src.get("kind") not in ("http", "cvelist_delta"):
            raise ValueError("%s: unknown kind" % sid)
        if src["kind"] == "http" and src.get("parser") not in PARSERS:
            raise ValueError("%s: unknown parser" % sid)
        for key in ("url", "record_base", "fallback_url"):
            if key in src and not src[key].startswith("https://"):
                raise ValueError("%s: %s must be https" % (sid, key))
        if src.get("redirects", "allowlist") not in ("allowlist", "any-https"):
            raise ValueError("%s: redirects must be 'allowlist' or 'any-https'" % sid)
        if not isinstance(src.get("every_minutes"), int) or src["every_minutes"] < 5:
            raise ValueError("%s: every_minutes must be an integer >= 5" % sid)
        origin = src.get("origin", sid)
        if not common.SOURCE_ID_RE.match(origin):
            raise ValueError("%s: bad origin" % sid)
    return cfg


def allowed_hosts(cfg: Dict[str, Any]) -> set:
    hosts = set()
    for src in cfg["sources"]:
        for key in ("url", "record_base", "fallback_url"):
            if key in src:
                hosts.add((urllib.parse.urlsplit(src[key]).hostname or "").lower())
        for host in src.get("redirect_hosts", []):
            hosts.add(host.lower())
    hosts.discard("")
    return hosts


class Fetcher:
    def __init__(self, cfg: Dict[str, Any], token: Optional[str] = None, timeout: int = 30):
        self.hosts = allowed_hosts(cfg)
        self.user_agent = cfg.get("user_agent", "vuln-intel-pipeline")
        self.token = token
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_SafeRedirect(self.hosts))

    def check_url(self, url: str) -> str:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https" or host not in self.hosts:
            raise FetchError("URL is not on the allowlist: %s" % host)
        return host

    def get(self, url: str, max_bytes: int, etag: Optional[str] = None, auth: Optional[str] = None,
            any_https_redirect: bool = False) -> Tuple[int, Optional[bytes], Optional[str]]:
        """Return (status, body, etag). Status is 200 or 304."""
        host = self.check_url(url)
        last_error = "no attempt made"
        for attempt in range(3):
            if attempt:
                time.sleep(2 * attempt)
            req = urllib.request.Request(url, method="GET")
            req.any_https_redirect = any_https_redirect
            req.add_header("User-Agent", self.user_agent)
            req.add_header("Accept", "*/*")
            req.add_header("Accept-Encoding", "gzip")
            if etag:
                req.add_header("If-None-Match", etag)
            if auth == "github" and self.token and host == "api.github.com":
                # Unredirected: the token is never forwarded to another host.
                req.add_unredirected_header("Authorization", "Bearer " + self.token)
                req.add_header("X-GitHub-Api-Version", "2022-11-28")
            try:
                with self.opener.open(req, timeout=self.timeout) as resp:
                    body = _read_capped(resp, max_bytes)
                    return 200, body, _clean_etag(resp.headers.get("ETag"))
            except urllib.error.HTTPError as err:
                if err.code == 304:
                    return 304, None, etag
                last_error = "HTTP %d" % err.code
                if err.code != 429 and not 500 <= err.code < 600:
                    break
            except FetchError as err:
                last_error = str(err)
                break
            except (urllib.error.URLError, OSError, ValueError, zlib.error) as err:
                last_error = "%s: %s" % (type(err).__name__, str(err)[:120])
        raise FetchError(last_error)


def _clean_etag(value: Optional[str]) -> Optional[str]:
    if not value or len(value) > 200 or not value.isprintable():
        return None
    return value


def _read_capped(resp, max_bytes: int) -> bytes:
    """Read a response body, refusing anything over max_bytes before or after gzip."""
    raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise FetchError("response larger than %d bytes" % max_bytes)
    if (resp.headers.get("Content-Encoding") or "").lower() != "gzip":
        return raw
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    body = decoder.decompress(raw, max_bytes + 1)
    if len(body) > max_bytes or decoder.unconsumed_tail:
        raise FetchError("decoded response larger than %d bytes" % max_bytes)
    return body


class RawWriter:
    """Stores raw bytes by SHA-256 and records each one in the manifest."""

    def __init__(self, out_dir: str):
        self.raw_dir = os.path.join(out_dir, "raw")
        os.makedirs(self.raw_dir, exist_ok=True)
        self.entries: List[Dict[str, Any]] = []
        self.total = 0

    def add(self, src: Dict[str, Any], parser: str, url: str, body: bytes, fetched_at: str,
            hint: str = "") -> str:
        digest = common.sha256_bytes(body)
        self.total += len(body)
        if self.total > MAX_RUN_BYTES:
            raise FetchError("run exceeded the total download budget")
        path = os.path.join(self.raw_dir, digest)
        if not os.path.exists(path):
            with open(path, "wb") as handle:
                handle.write(body)
        self.entries.append({
            "source": src["id"], "origin": src.get("origin", src["id"]), "role": src.get("role", ""),
            "parser": parser,
            "url": url, "sha256": digest, "bytes": len(body), "fetched_at": fetched_at, "hint": hint,
        })
        return digest


def is_due(src: Dict[str, Any], heartbeat: Dict[str, Any], now: dt.datetime) -> bool:
    last_ok = common.parse_ts((heartbeat.get(src["id"]) or {}).get("last_ok"))
    if last_ok is None:
        return True
    return (now - last_ok).total_seconds() >= src["every_minutes"] * 60 - DUE_SLACK_SECONDS


def collect_http(src, fetcher, cursor, writer, cfg, now):
    max_bytes = src.get("max_bytes", cfg.get("max_bytes", 20000000))
    status, body, etag = fetcher.get(src["url"], max_bytes, etag=cursor.get("etag"), auth=src.get("auth"),
                                     any_https_redirect=src.get("redirects") == "any-https")
    if status == 304 or body is None:
        return {"status": "unchanged", "items": 0}, None
    digest = common.sha256_bytes(body)
    if digest == cursor.get("sha256"):
        return {"status": "unchanged", "items": 0}, None
    writer.add(src, src["parser"], src["url"], body, common.ts(now))
    next_cursor = {"sha256": digest}
    if etag:
        next_cursor["etag"] = etag
    return {"status": "ok", "items": 1}, next_cursor


def record_url(base: str, cve_id: str) -> str:
    # cve_relpath validates the ID, so nothing but digits reaches the URL.
    return base + common.cve_relpath(cve_id)[len("cves/"):]


def select_deltas(log: Any, cursor: dt.datetime, max_records: int):
    """Pick changed CVE IDs from deltas newer than the cursor, oldest first."""
    if isinstance(log, dict) and "fetchTime" not in log:
        # Tolerate a wrapper object around the list of deltas.
        lists = [value for value in log.values() if isinstance(value, list)]
        log = lists[0] if len(lists) == 1 else log
    if isinstance(log, dict):
        log = [log]
    if not isinstance(log, list):
        raise FetchError("change log is not a list")
    deltas = []
    for delta in log:
        if isinstance(delta, dict):
            when = common.parse_ts(delta.get("fetchTime"))
            if when and when > cursor:
                deltas.append((when, delta))
    deltas.sort(key=lambda pair: pair[0])
    ids: Dict[str, None] = {}
    new_cursor = cursor
    for when, delta in deltas:
        batch = []
        for key in ("new", "updated"):
            for entry in delta.get(key) or []:
                cve_id = entry.get("cveId") if isinstance(entry, dict) else None
                if isinstance(cve_id, str) and common.CVE_RE.match(cve_id):
                    batch.append(cve_id)
        fresh = [cve_id for cve_id in batch if cve_id not in ids]
        if ids and len(ids) + len(fresh) > max_records:
            break
        for cve_id in fresh:
            ids[cve_id] = None
        new_cursor = when
    return list(ids), new_cursor


def collect_cvelist(src, fetcher, cursor, writer, cfg, now, wanted=()):
    start = common.parse_ts(cursor.get("fetch_time"))
    if start is None:
        start = now - dt.timedelta(hours=src.get("bootstrap_hours", 24))
    def load(url, max_bytes):
        _, body, _ = fetcher.get(url, max_bytes)
        try:
            return json.loads((body or b"").decode("utf-8", "replace"))
        except (ValueError, RecursionError) as err:
            raise FetchError("change log is not JSON: %s" % type(err).__name__)

    degraded = ""
    try:
        ids, new_cursor = select_deltas(load(src["url"], src.get("max_bytes", 120000000)), start,
                                        src.get("max_records", 1500))
    except FetchError as err:
        # The 30-day log is unavailable. Fall back to the latest-changes file so
        # new records keep flowing, but report an error and leave the cursor so
        # the gap is filled once the log is readable again.
        if not src.get("fallback_url"):
            raise
        degraded = "change log unreadable (%s); fetched only the latest changes" % err
        ids, new_cursor = select_deltas(load(src["fallback_url"], 5000000), start, src.get("max_records", 1500))
    # Backfill: records the commit stage asked for because news or KEV named a
    # CVE the pipeline has no record of (usually one published before it started).
    changed = set(ids)
    backfill = [c for c in wanted if isinstance(c, str) and common.CVE_RE.match(c) and c not in changed]
    backfill = backfill[: src.get("backfill_max", 300)]
    asked = set(backfill)
    fetched_at = common.ts(now)

    def fetch(cve_id):
        url = record_url(src["record_base"], cve_id)
        try:
            return cve_id, url, fetcher.get(url, 5000000)[1], None
        except FetchError as err:
            return cve_id, url, None, str(err)

    failures, found, missing = [], [], []
    if ids or backfill:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for cve_id, url, record, error in pool.map(fetch, list(ids) + backfill):
                if record is not None:
                    writer.add(src, "cve", url, record, fetched_at, hint=cve_id)
                    if cve_id in asked:
                        found.append(cve_id)
                elif cve_id not in asked:
                    failures.append("%s (%s)" % (cve_id, error))
                elif error == "HTTP 404":
                    missing.append(cve_id)  # not published; any other error is retried next run
    done = len(ids) - len(failures) + len(found)

    def result(status, cursor, detail=""):
        report = {"status": status, "items": done, "backfill": {"found": found, "missing": missing}}
        if detail:
            report["detail"] = detail[:300]
        return report, cursor

    if degraded:
        return result("error", None, degraded)
    if len(failures) * 10 > len(ids):
        # Too many gaps: leave the cursor so the next run retries the window.
        return result("error", None, "%d of %d records failed, e.g. %s" % (len(failures), len(ids), failures[0]))
    detail = "%d records failed, e.g. %s" % (len(failures), failures[0]) if failures else ""
    return result("ok" if done else "unchanged", {"fetch_time": common.ts(new_cursor)}, detail)


def run(cfg, state_dir, out_dir, token=None, only=None, now=None, fetcher=None):
    now = now or common.utcnow()
    heartbeat = (common.read_json(os.path.join(state_dir, "heartbeat.json"), {}) or {}).get("sources", {})
    cursors = common.read_json(os.path.join(state_dir, "cursors.json"), {}) or {}
    wanted = common.read_json(os.path.join(state_dir, "wanted.json"), {})
    wanted = wanted if isinstance(wanted, dict) else {}
    # Newest requests first, so a burst of old ones cannot delay a fresh one.
    pending = sorted((cve for cve, entry in wanted.items()
                      if isinstance(entry, dict) and entry.get("status") == "pending"),
                     key=lambda cve: str(wanted[cve].get("since", "")), reverse=True)
    fetcher = fetcher or Fetcher(cfg, token=token)
    writer = RawWriter(out_dir)
    report = {"at": common.ts(now), "sources": {}, "cursors": {}}
    for src in cfg["sources"]:
        sid = src["id"]
        if only and sid not in only:
            continue
        if not only and not is_due(src, heartbeat, now):
            continue
        try:
            if src["kind"] == "cvelist_delta":
                entry, cursor = collect_cvelist(src, fetcher, cursors.get(sid) or {}, writer, cfg, now,
                                                wanted=pending)
            else:
                entry, cursor = collect_http(src, fetcher, cursors.get(sid) or {}, writer, cfg, now)
        except FetchError as err:
            entry, cursor = {"status": "error", "items": 0, "detail": str(err)[:300]}, None
        entry["every_minutes"] = src["every_minutes"]
        entry["role"] = src.get("role", "")
        report["sources"][sid] = entry
        if cursor:
            report["cursors"][sid] = cursor
        print("%-18s %-9s %s" % (sid, entry["status"], entry.get("detail", "")), file=sys.stderr)
    with open(os.path.join(out_dir, "manifest.jsonl"), "w", encoding="utf-8") as handle:
        for item in writer.entries:
            handle.write(json.dumps(item, sort_keys=True) + "\n")
    common.write_json_atomic(os.path.join(out_dir, "collect-report.json"), report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--state", required=True, help="directory holding heartbeat.json and cursors.json")
    parser.add_argument("--out", required=True)
    parser.add_argument("--only", action="append", help="collect just this source id, ignoring the schedule")
    args = parser.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    run(load_config(args.config), args.state, args.out, token=os.environ.get("GITHUB_TOKEN"), only=args.only)
    return 0


if __name__ == "__main__":
    sys.exit(main())
