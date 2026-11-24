import datetime as dt
import json
import os
import sys
import tempfile
import unittest
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import fixtures as fx  # noqa: E402
from pipeline import collect, commit, common, parse, store, validate  # noqa: E402

NOW = dt.datetime(2099, 1, 4, 12, 30, tzinfo=dt.timezone.utc)
BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"

CONFIG = {
    "user_agent": "test", "max_bytes": 1000000,
    "sources": [
        {"id": "cvelist", "kind": "cvelist_delta", "every_minutes": 60,
         "url": BASE + "deltaLog.json", "record_base": BASE, "max_records": 100},
        {"id": "kev", "kind": "http", "parser": "kev", "every_minutes": 60, "url": "https://kev.example/kev.json"},
        {"id": "epss", "kind": "http", "parser": "epss", "every_minutes": 1440, "url": "https://epss.example/e.gz"},
        {"id": "ghsa", "kind": "http", "parser": "ghsa", "every_minutes": 60, "auth": "github",
         "url": "https://api.github.com/advisories"},
        {"id": "hn-cve", "kind": "http", "parser": "hn", "origin": "hackernews", "every_minutes": 15,
         "url": "https://hn.example/search"},
        {"id": "blog", "kind": "http", "parser": "feed", "every_minutes": 15, "url": "https://blog.example.com/rss"},
        {"id": "php", "kind": "http", "parser": "feed", "every_minutes": 30, "url": "https://www.php.net/feed.atom"},
        {"id": "debian", "kind": "http", "parser": "feed", "every_minutes": 30, "url": "https://www.debian.org/dsa"},
        {"id": "evil", "kind": "http", "parser": "feed", "every_minutes": 15, "url": "https://evil.example/rss"},
        {"id": "down", "kind": "http", "parser": "feed", "every_minutes": 15, "url": "https://down.example/rss"},
    ],
}

RSS = fx.RSS.replace(b"Fri, 04 Jan 99 12:00:00 +0000", b"Sun, 04 Jan 2099 12:00:00 +0000")


class FakeFetcher:
    def __init__(self):
        record = dict(fx.CVE_RECORD)
        self.pages = {
            BASE + "deltaLog.json": fx.dumps(fx.DELTA_LOG),
            BASE + "2099/10xxx/CVE-2099-10001.json": fx.dumps(record),
            "https://kev.example/kev.json": fx.dumps(fx.KEV),
            "https://epss.example/e.gz": fx.EPSS_GZ,
            "https://api.github.com/advisories": fx.dumps(fx.GHSA),
            "https://hn.example/search": fx.dumps(fx.HN),
            "https://blog.example.com/rss": RSS,
            "https://www.php.net/feed.atom": fx.ATOM,
            "https://www.debian.org/dsa": fx.RDF,
            "https://evil.example/rss": fx.ENTITY_BOMB,
        }
        self.calls = []

    def get(self, url, max_bytes, etag=None, auth=None, any_https_redirect=False):
        self.calls.append(url)
        if url not in self.pages:
            raise collect.FetchError("HTTP 404")
        return 200, self.pages[url], '"etag-1"'


def entry(source="s", parser="cve", data=b""):
    return {"source": source, "origin": source, "parser": parser, "url": "https://example.com/x",
            "sha256": common.sha256_bytes(data), "fetched_at": "2099-01-04T12:00:00Z"}


class CommonTests(unittest.TestCase):
    def test_cve_relpath_matches_cvelist_layout(self):
        self.assertEqual(common.cve_relpath("CVE-2026-0462"), "cves/2026/0xxx/CVE-2026-0462.json")
        self.assertEqual(common.cve_relpath("CVE-2026-40671"), "cves/2026/40xxx/CVE-2026-40671.json")
        self.assertEqual(common.cve_relpath("CVE-2026-109618"), "cves/2026/109xxx/CVE-2026-109618.json")
        for bad in ("CVE-2026-1", "../../x", "CVE-2026-0462/../x", "cve-2026-0462"):
            with self.assertRaises(ValueError):
                common.cve_relpath(bad)

    def test_dates(self):
        self.assertEqual(common.ts(common.parse_ts("2026-11-21T14:54:57.360Z")), "2026-11-21T14:54:57Z")
        self.assertEqual(common.ts(common.parse_ts("2026-11-19T14:00:00+05:30")), "2026-11-19T08:30:00Z")
        self.assertEqual(common.ts(common.parse_ts("2026-11-20")), "2026-11-20T00:00:00Z")
        self.assertIsNone(common.parse_ts("2026-13-40"))
        self.assertIsNone(common.parse_ts(None))
        self.assertEqual(common.ts(common.parse_any_date("Fri, 20 Nov 26 12:00:00 +0000")), "2026-11-20T12:00:00Z")
        self.assertEqual(common.ts(common.parse_any_date("Sat, 21 Nov 2026 09:26:04 -0500")), "2026-11-21T14:26:04Z")
        self.assertIsNone(common.parse_any_date("not a date"))

    def test_clean_text_removes_control_and_bidi(self):
        self.assertEqual(common.clean_text("a\x00b‮c\n\n d", 50), "a bc d")
        self.assertEqual(common.clean_text("x" * 100, 10), "x" * 10)
        self.assertEqual(common.clean_text(None, 10), "")
        self.assertEqual(common.clean_text(8.3, 10), "8.3")


class CollectTests(unittest.TestCase):
    def test_select_deltas_orders_filters_and_advances(self):
        cursor = common.parse_ts("2099-01-04T09:30:00Z")
        ids, new_cursor = collect.select_deltas(fx.DELTA_LOG, cursor, 100)
        self.assertEqual(ids, ["CVE-2099-10001", "CVE-2099-0462", "CVE-2099-123456"])
        self.assertEqual(common.ts(new_cursor), "2099-01-04T11:00:00Z")

    def test_select_deltas_stops_at_the_record_budget(self):
        cursor = common.parse_ts("2099-01-04T08:00:00Z")
        ids, new_cursor = collect.select_deltas(fx.DELTA_LOG, cursor, 2)
        self.assertEqual(ids, ["CVE-2099-10000"])
        self.assertEqual(common.ts(new_cursor), "2099-01-04T09:00:00Z")

    def test_single_delta_object_is_accepted(self):
        ids, _ = collect.select_deltas(fx.DELTA_LOG[0], common.parse_ts("2099-01-01"), 100)
        self.assertEqual(ids, ["CVE-2099-10001", "CVE-2099-0462"])

    def test_record_url(self):
        self.assertEqual(collect.record_url(BASE, "CVE-2099-0462"), BASE + "2099/0xxx/CVE-2099-0462.json")

    def test_is_due(self):
        src = {"id": "x", "every_minutes": 60}
        self.assertTrue(collect.is_due(src, {}, NOW))
        recent = {"x": {"last_ok": common.ts(NOW - dt.timedelta(minutes=30))}}
        self.assertFalse(collect.is_due(src, recent, NOW))
        old = {"x": {"last_ok": common.ts(NOW - dt.timedelta(minutes=56))}}
        self.assertTrue(collect.is_due(src, old, NOW))

    def test_fetcher_refuses_hosts_off_the_allowlist(self):
        fetcher = collect.Fetcher(CONFIG)
        for url in ("https://attacker.example/x", "http://kev.example/kev.json", "file:///etc/passwd"):
            with self.assertRaises(collect.FetchError):
                fetcher.get(url, 1000)

    def test_redirect_off_allowlist_is_blocked(self):
        handler = collect._SafeRedirect({"good.example"})
        import urllib.request
        req = urllib.request.Request("https://good.example/a")
        for target in ("https://evil.example/a", "http://good.example/a"):
            with self.assertRaises(urllib.error.HTTPError):
                handler.redirect_request(req, None, 302, "Found", {}, target)
        self.assertIsNotNone(handler.redirect_request(req, None, 302, "Found", {}, "https://good.example/b"))
        # A source that opted in may be redirected to any HTTPS host, and the
        # opt-in follows the chain, but plain HTTP is still refused.
        req.any_https_redirect = True
        hop = handler.redirect_request(req, None, 302, "Found", {}, "https://cdn.example/a")
        self.assertTrue(hop.any_https_redirect)
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(hop, None, 302, "Found", {}, "http://cdn.example/a")

    def test_cvelist_falls_back_to_latest_changes_when_the_log_is_unreadable(self):
        class Fetcher(FakeFetcher):
            def get(self, url, max_bytes, etag=None, auth=None, any_https_redirect=False):
                if url.endswith("deltaLog.json"):
                    raise collect.FetchError("response larger than 1 bytes")
                return super().get(url, max_bytes)

        fetcher = Fetcher()
        fetcher.pages[BASE + "delta.json"] = fx.dumps(fx.DELTA_LOG[0])
        src = dict(CONFIG["sources"][0], fallback_url=BASE + "delta.json")
        with tempfile.TemporaryDirectory() as tmp:
            writer = collect.RawWriter(tmp)
            entry_, cursor = collect.collect_cvelist(src, fetcher, {"fetch_time": "2099-01-04T09:30:00Z"},
                                                     writer, CONFIG, NOW)
        self.assertEqual((entry_["status"], cursor), ("error", None))      # visible, and the cursor stays
        self.assertIn("fetched only the latest changes", entry_["detail"])
        self.assertEqual([e["hint"] for e in writer.entries], ["CVE-2099-10001"])  # records still flow

    def test_wrapped_change_log_is_accepted(self):
        ids, _ = collect.select_deltas({"deltas": fx.DELTA_LOG}, common.parse_ts("2099-01-04T09:30:00Z"), 100)
        self.assertEqual(len(ids), 3)

    def test_read_capped_enforces_the_size_limit_before_and_after_gzip(self):
        import gzip
        import io

        class Response(io.BytesIO):
            def __init__(self, body, encoding=None):
                super().__init__(body)
                self.headers = {"Content-Encoding": encoding} if encoding else {}

        self.assertEqual(collect._read_capped(Response(b"hello"), 10), b"hello")
        self.assertEqual(collect._read_capped(Response(gzip.compress(b"hello"), "gzip"), 100), b"hello")
        with self.assertRaises(collect.FetchError):
            collect._read_capped(Response(b"x" * 11), 10)
        bomb = gzip.compress(b"\x00" * 1000000)
        self.assertLess(len(bomb), 5000)
        with self.assertRaises(collect.FetchError):
            collect._read_capped(Response(bomb, "gzip"), 5000)

    def test_fetcher_get_statuses_retries_and_token_scope(self):
        import io

        class Response(io.BytesIO):
            headers = {"ETag": '"v2"'}

        class Opener:
            def __init__(self, outcomes):
                self.outcomes, self.requests = list(outcomes), []

            def open(self, req, timeout=None):
                self.requests.append(req)
                outcome = self.outcomes.pop(0)
                if isinstance(outcome, Exception):
                    raise outcome
                return Response(outcome)

        def http_error(code):
            return urllib.error.HTTPError("https://kev.example/kev.json", code, "x", {}, None)

        sleeps = []
        real_sleep, collect.time.sleep = collect.time.sleep, sleeps.append
        try:
            fetcher = collect.Fetcher(CONFIG, token="secret-token")

            fetcher.opener = Opener([b"body"])
            self.assertEqual(fetcher.get("https://kev.example/kev.json", 100, etag='"v1"'), (200, b"body", '"v2"'))
            sent = fetcher.opener.requests[0]
            self.assertEqual(sent.get_header("If-none-match"), '"v1"')
            self.assertFalse(sent.unredirected_hdrs)          # no token for other hosts

            fetcher.opener = Opener([http_error(304)])
            self.assertEqual(fetcher.get("https://kev.example/kev.json", 100, etag='"v1"'), (304, None, '"v1"'))

            fetcher.opener = Opener([http_error(503), OSError("reset"), b"late"])
            self.assertEqual(fetcher.get("https://kev.example/kev.json", 100)[1], b"late")
            self.assertEqual(len(sleeps), 2)

            fetcher.opener = Opener([http_error(404), b"never"])
            with self.assertRaises(collect.FetchError):
                fetcher.get("https://kev.example/kev.json", 100)
            self.assertEqual(len(fetcher.opener.requests), 1)  # 404 is not retried

            fetcher.opener = Opener([b"[]"])
            fetcher.get("https://api.github.com/advisories", 100, auth="github")
            sent = fetcher.opener.requests[0]
            # The token is attached so that a redirect never carries it to another host.
            self.assertEqual(sent.unredirected_hdrs, {"Authorization": "Bearer secret-token"})
            self.assertNotIn("Authorization", sent.headers)
        finally:
            collect.time.sleep = real_sleep

    def test_config_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.json")
            for bad in ({"id": "Bad Id", "kind": "http", "parser": "feed", "every_minutes": 15, "url": "https://a/"},
                        {"id": "a", "kind": "http", "parser": "feed", "every_minutes": 15, "url": "http://a/"},
                        {"id": "a", "kind": "http", "parser": "exec", "every_minutes": 15, "url": "https://a/"}):
                with open(path, "w") as handle:
                    json.dump({"sources": [bad]}, handle)
                with self.assertRaises(ValueError):
                    collect.load_config(path)

    def test_shipped_config_is_valid(self):
        path = os.path.join(os.path.dirname(__file__), "..", "config", "sources.json")
        cfg = collect.load_config(path)
        self.assertGreater(len(cfg["sources"]), 10)


class ParseTests(unittest.TestCase):
    def test_cve_record(self):
        data = fx.dumps(fx.CVE_RECORD)
        obs = validate.validate(parse.parse_cve(data, entry(data=data))[0])
        self.assertEqual(obs["id"], "CVE-2099-10001")
        self.assertEqual(obs["state"], "PUBLISHED")
        self.assertEqual(obs["description"], "A crafted frame overflows a heap buffer.")
        self.assertEqual(obs["affected"][0]["product"], "NGINX Open Source")
        self.assertEqual(obs["affected"][0]["versions"][0]["less_than"], "1.30.7")
        self.assertEqual(obs["cvss"]["v3"], {"score": 9.8, "source": "cna",
                                             "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
        self.assertEqual(obs["ssvc"], {"exploitation": "active", "automatable": "yes", "technical_impact": "total"})
        self.assertEqual(obs["kev_adp"], "2099-01-04")
        self.assertEqual(obs["cwes"], ["CWE-122"])
        self.assertEqual(obs["references"], ["https://example.com/advisory/1"])
        self.assertEqual(obs["updated"], "2099-01-03T11:22:33Z")

    def test_cve_record_with_hostile_shapes_does_not_crash(self):
        for doc in ({}, {"cveMetadata": "x", "containers": []},
                    {"cveMetadata": {"cveId": "CVE-2099-10001"},
                     "containers": {"cna": {"affected": "x", "metrics": [1, None], "references": [None]},
                                    "adp": "x"}}):
            data = fx.dumps(doc)
            out = parse.parse_cve(data, entry(data=data))
            self.assertEqual(len(out), 1)
        with self.assertRaises(validate.Invalid):
            data = fx.dumps({})
            validate.validate(parse.parse_cve(data, entry(data=data))[0])

    def test_kev(self):
        data = fx.dumps(fx.KEV)
        out = parse.parse_kev(data, entry(parser="kev", data=data))
        self.assertEqual(len(out), 2)
        good = validate.validate(out[0])
        self.assertEqual((good["cve"], good["date_added"], good["product"]), ("CVE-2099-10001", "2099-01-04", "NGINX"))
        with self.assertRaises(validate.Invalid):
            validate.validate(out[1])

    def test_epss_gzip_and_plain(self):
        for data in (fx.EPSS_GZ, fx.EPSS_CSV.encode()):
            obs = validate.validate(parse.parse_epss(data, entry(parser="epss", data=data))[0])
            self.assertEqual(obs["p95"], ["CVE-2099-10001"])
            self.assertEqual(obs["p80"], ["CVE-2099-10002"])
            self.assertEqual((obs["date"], obs["model"]), ("2099-01-04", "v2099.01.01"))

    def test_ghsa(self):
        data = fx.dumps(fx.GHSA)
        obs = validate.validate(parse.parse_ghsa(data, entry(parser="ghsa", data=data))[0])
        self.assertEqual((obs["id"], obs["cve"], obs["severity"]), ("GHSA-cmxg-94mg-jq94", "CVE-2099-10002", "high"))
        self.assertEqual(obs["packages"][0], {"ecosystem": "composer", "name": "example/lib",
                                              "range": "< 2.3.1", "patched": "2.3.1"})
        self.assertEqual(obs["packages"][1]["patched"], "")

    def test_hacker_news(self):
        data = fx.dumps(fx.HN)
        out = parse.parse_hn(data, entry(parser="hn", data=data))
        self.assertEqual(len(out), 2)
        first = validate.validate(out[0])
        self.assertEqual(first["cves"], ["CVE-2099-10001"])
        self.assertEqual(first["names"], ["Nginx2Shell"])
        self.assertEqual(first["published"], "2099-01-04T09:00:00Z")
        self.assertEqual(out[1]["url"], "https://news.ycombinator.com/item?id=4243")

    def test_rss_atom_rdf(self):
        rss = parse.parse_feed(RSS, entry(parser="feed", data=RSS))
        self.assertEqual(len(rss), 1)
        item = validate.validate(rss[0])
        self.assertEqual(item["url"], "https://blog.example.com/phpghost")
        self.assertEqual(item["title"], "Critical flaw dubbed PHPGhost hits PHP servers")
        self.assertEqual(item["cves"], ["CVE-2099-10002", "CVE-2099-10003"])
        self.assertEqual(item["names"], ["PHPGhost"])
        self.assertEqual(item["published"], "2099-01-04T12:00:00Z")

        atom = parse.parse_feed(fx.ATOM, entry(parser="feed", data=fx.ATOM))
        self.assertEqual(atom[0]["url"], "https://www.php.net/releases/8_3_36.php")
        self.assertEqual(atom[0]["published"], "2099-01-04T14:00:00Z")

        rdf = parse.parse_feed(fx.RDF, entry(parser="feed", data=fx.RDF))
        self.assertEqual(rdf[0]["url"], "https://www.debian.org/security/2099/dsa-9001")
        self.assertEqual(rdf[0]["published"], "2099-01-04T00:00:00Z")

    def test_entity_declarations_are_refused(self):
        with self.assertRaises(ValueError):
            parse.parse_feed(fx.ENTITY_BOMB, entry(parser="feed", data=fx.ENTITY_BOMB))

    def test_bug_name_heuristic(self):
        self.assertEqual(parse.find_bug_names("Log4Shell and CitrixBleed return"), ["Log4Shell", "CitrixBleed"])
        self.assertEqual(parse.find_bug_names("New PowerShell webshell from Microsoft"), [])
        self.assertEqual(parse.find_bug_names('A bug dubbed "regreSSHion" hits OpenSSH'), [])
        self.assertEqual(parse.find_bug_names("Flaw named Sinkclose affects AMD"), ["Sinkclose"])


class ValidateTests(unittest.TestCase):
    def setUp(self):
        self.data = fx.dumps(fx.KEV)
        self.entry = entry(source="kev", parser="kev", data=self.data)
        self.manifest = {self.entry["sha256"]: self.entry}
        self.obs = parse.parse_kev(self.data, self.entry)[0]

    def test_evidence_comes_from_the_manifest(self):
        self.obs["src"]["url"] = "https://attacker.example/"
        clean = validate.validate(self.obs, self.manifest)
        self.assertEqual(clean["src"]["url"], "https://example.com/x")
        self.assertEqual(clean["src"]["fetched_at"], "2099-01-04T12:00:00Z")

    def test_unknown_document_is_rejected(self):
        self.obs["src"]["sha256"] = "0" * 64
        with self.assertRaises(validate.Invalid):
            validate.validate(self.obs, self.manifest)

    def test_source_mismatch_is_rejected(self):
        self.obs["src"]["source"] = "cvelist"
        with self.assertRaises(validate.Invalid):
            validate.validate(self.obs, self.manifest)

    def test_type_must_match_the_documents_parser(self):
        # A document fetched as a news feed cannot yield a KEV entry.
        self.manifest[self.entry["sha256"]] = dict(self.entry, parser="feed")
        with self.assertRaises(validate.Invalid):
            validate.validate(self.obs, self.manifest)

    def test_unknown_fields_and_types_are_dropped(self):
        self.obs["extra"] = {"anything": 1}
        self.obs["vendor"] = ["not", "a", "string"]
        clean = validate.validate(self.obs, self.manifest)
        self.assertNotIn("extra", clean)
        self.assertEqual(clean["vendor"], "")
        for bad in (None, [], "x", {"type": "shell"}):
            with self.assertRaises(validate.Invalid):
                validate.validate(bad, self.manifest)

    def test_news_requires_safe_url(self):
        base = {"type": "news", "title": "t", "src": {"source": "s", "sha256": "a" * 64}}
        for url in ("javascript:alert(1)", "https://x.example/a b", "ftp://x.example/", ""):
            with self.assertRaises(validate.Invalid):
                validate.validate(dict(base, url=url))
        ok = validate.validate(dict(base, url="https://x.example/a", names=["Good2Shell", "bad name!", "<b>"]))
        self.assertEqual(ok["names"], ["Good2Shell"])


class EndToEndTests(unittest.TestCase):
    def run_pipeline(self, tmp, fetcher, data_dir):
        collected, parsed = os.path.join(tmp, "collected"), os.path.join(tmp, "parsed")
        for path in (collected, parsed):
            if os.path.isdir(path):
                for root, _, files in os.walk(path, topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
        os.makedirs(collected, exist_ok=True)
        report = collect.run(CONFIG, os.path.join(data_dir, "state"), collected, now=NOW, fetcher=fetcher)
        parse.run(collected, parsed)
        summary = commit.run(data_dir, collected, parsed, now=NOW)
        return report, summary

    def snapshot(self, data_dir):
        files = {}
        for root, _, names in os.walk(data_dir):
            for name in names:
                path = os.path.join(root, name)
                with open(path, "rb") as handle:
                    files[os.path.relpath(path, data_dir)] = handle.read()
        return files

    def test_collect_parse_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = os.path.join(tmp, "data")
            os.makedirs(os.path.join(data_dir, "state"))
            common.write_json_atomic(os.path.join(data_dir, "state", "cursors.json"),
                                     {"cvelist": {"fetch_time": "2099-01-04T09:30:00Z"}})
            fetcher = FakeFetcher()
            report, summary = self.run_pipeline(tmp, fetcher, data_dir)

            # Collect: two of three CVE records are missing upstream, so the
            # cursor must not move; one feed is down.
            self.assertEqual(report["sources"]["cvelist"]["status"], "error")
            self.assertEqual(report["sources"]["down"]["status"], "error")
            self.assertEqual(report["sources"]["kev"]["status"], "ok")

            files = self.snapshot(data_dir)
            record = json.loads(files["cves/2099/10xxx/CVE-2099-10001.json"])
            self.assertEqual(record["src"]["url"], BASE + "2099/10xxx/CVE-2099-10001.json")
            self.assertEqual(record["first_seen"], "2099-01-04T12:30:00Z")
            kev = json.loads(files["kev.json"])
            self.assertEqual(list(kev), ["CVE-2099-10001"])
            self.assertEqual(json.loads(files["epss/current.json"])["p95"], ["CVE-2099-10001"])
            self.assertIn("ghsa/cm/GHSA-cmxg-94mg-jq94.json", files)
            news = [json.loads(line) for line in files["news/2099-01-04.jsonl"].decode().splitlines()]
            self.assertEqual({item["src"]["origin"] for item in news}, {"hackernews", "blog", "php", "debian"})
            self.assertEqual(len(news), 5)
            self.assertTrue(all(item["seen"] == "2099-01-04T12:30:00Z" for item in news))

            beat = json.loads(files["state/heartbeat.json"])["sources"]
            self.assertEqual(beat["kev"]["status"], "ok")
            self.assertEqual(beat["kev"]["last_ok"], "2099-01-04T12:30:00Z")
            self.assertEqual(beat["evil"]["status"], "parse_error")
            self.assertEqual(beat["down"]["consecutive_errors"], 1)
            self.assertNotIn("last_ok", beat["down"])
            # One of two KEV entries was invalid: tolerated, but reported.
            self.assertIn("rejected", beat["kev"]["detail"])

            cursors = json.loads(files["state/cursors.json"])
            self.assertEqual(cursors["cvelist"], {"fetch_time": "2099-01-04T09:30:00Z"})
            self.assertEqual(cursors["kev"]["etag"], '"etag-1"')
            self.assertNotIn("evil", cursors)
            self.assertEqual(summary["rejected"], {"kev": 1})

            # News named two CVEs the store has no record of: ask for them.
            # CVE-2099-10001 is named too, but its record is already stored.
            wanted = json.loads(files["state/wanted.json"])
            self.assertEqual({cve: entry["status"] for cve, entry in wanted.items()},
                             {"CVE-2099-10002": "pending", "CVE-2099-10003": "pending"})
            self.assertEqual(summary["wanted"], {"pending": 2, "missing": 0})

            # Second run: nothing is due except the failing sources, plus the
            # two backfill requests. Upstream has no such records, so they are
            # marked missing and not asked for again. Data files do not change.
            fetcher.calls.clear()
            self.run_pipeline(tmp, fetcher, data_dir)
            self.assertEqual(sorted(set(fetcher.calls) - {BASE + "deltaLog.json"}),
                             sorted([BASE + "2099/0xxx/CVE-2099-0462.json",
                                     BASE + "2099/10xxx/CVE-2099-10001.json",
                                     BASE + "2099/10xxx/CVE-2099-10002.json",
                                     BASE + "2099/10xxx/CVE-2099-10003.json",
                                     BASE + "2099/123xxx/CVE-2099-123456.json",
                                     "https://down.example/rss", "https://evil.example/rss"]))
            after = self.snapshot(data_dir)
            changed = sorted(name for name in after if after[name] != files.get(name))
            self.assertEqual(changed, ["state/heartbeat.json", "state/wanted.json"])
            wanted = json.loads(after["state/wanted.json"])
            self.assertEqual({entry["status"] for entry in wanted.values()}, {"missing"})

            fetcher.calls.clear()
            self.run_pipeline(tmp, fetcher, data_dir)
            self.assertNotIn(BASE + "2099/10xxx/CVE-2099-10002.json", fetcher.calls)

    def test_backfill_fetches_wanted_records_and_reports_what_is_missing(self):
        class Fetcher(FakeFetcher):
            def get(self, url, max_bytes, etag=None, auth=None, any_https_redirect=False):
                if url.endswith("CVE-2099-0500.json"):
                    raise collect.FetchError("HTTP 503")
                return super().get(url, max_bytes)

        fetcher = Fetcher()
        fetcher.pages[BASE + "deltaLog.json"] = fx.dumps([])
        fetcher.pages[BASE + "2099/0xxx/CVE-2099-0400.json"] = fx.dumps(fx.CVE_RECORD)
        src = CONFIG["sources"][0]
        with tempfile.TemporaryDirectory() as tmp:
            writer = collect.RawWriter(tmp)
            entry_, cursor = collect.collect_cvelist(
                src, fetcher, {"fetch_time": "2099-01-04T09:30:00Z"}, writer, CONFIG, NOW,
                wanted=["CVE-2099-0400", "CVE-2099-0401", "CVE-2099-0500", "not-a-cve"])
        # Found records flow through the normal path; a 404 means unpublished;
        # a server error is left pending for the next run; junk IDs are ignored.
        self.assertEqual(entry_["backfill"], {"found": ["CVE-2099-0400"], "missing": ["CVE-2099-0401"]})
        self.assertEqual((entry_["status"], entry_["items"]), ("ok", 1))
        self.assertEqual([e["hint"] for e in writer.entries], ["CVE-2099-0400"])
        self.assertEqual(cursor, {"fetch_time": "2099-01-04T09:30:00Z"})

    def test_wanted_tracks_recent_kev_entries_and_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            common.write_json_atomic(os.path.join(tmp, "kev.json"), {
                "CVE-2099-7000": {"date_added": "2099-01-01"},      # recent, no record: wanted
                "CVE-2090-7001": {"date_added": "2095-01-01"},      # added years ago: not wanted
            })
            common.write_json_atomic(os.path.join(tmp, "state", "wanted.json"), {
                "CVE-2099-8000": {"status": "missing", "since": "2098-11-01T00:00:00Z"},  # expired
                "bogus": {"status": "pending", "since": "2099-01-04T00:00:00Z"},
            })
            counts = commit.update_wanted(tmp, {"sources": {}}, NOW)
            wanted = common.read_json(os.path.join(tmp, "state", "wanted.json"), {})
            self.assertEqual(list(wanted), ["CVE-2099-7000"])
            self.assertEqual(counts, {"pending": 1, "missing": 0})

    def test_store_is_idempotent_and_dedupes_news(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = fx.dumps(fx.HN)
            item = entry(source="hn-cve", parser="hn", data=data)
            item["origin"] = "hackernews"
            manifest = {item["sha256"]: item}
            obs = [validate.validate(o, manifest) for o in parse.parse_hn(data, item)]
            self.assertEqual(store.apply(tmp, obs, NOW)["news"], 2)
            self.assertEqual(store.apply(tmp, obs, NOW + dt.timedelta(days=1))["news"], 0)
            old = dict(obs[0], url="https://example.org/old", published="2098-12-01T00:00:00Z")
            self.assertEqual(store.apply(tmp, [old], NOW)["news"], 0)


class CoverageTests(unittest.TestCase):
    """Public rule sets and exploit lists, reduced to (CVE, identifier, title)."""

    def check(self, parser, data):
        item = entry(source="cov", parser=parser, data=data)
        manifest = {item["sha256"]: item}
        return [validate.validate(obs, manifest) for obs in parse.PARSERS[parser](data, item)]

    def rows(self, out):
        return [(o["kind"], o["cve"], o["ident"], o["title"], o["note"]) for o in out]

    def test_nuclei_index(self):
        data = (b'{"ID":"CVE-2099-0001","Info":{"Name":"Acme - RCE","Severity":"critical"},'
                b'"file_path":"http/cves/2099/CVE-2099-0001.yaml"}\nnot json\n{"ID":"nope","file_path":"x.yaml"}\n')
        self.assertEqual(self.rows(self.check("nuclei_index", data)),
                         [("nuclei", "CVE-2099-0001", "http/cves/2099/CVE-2099-0001.yaml", "Acme - RCE", "critical")])

    def test_exploitdb(self):
        data = (b"id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,"
                b"codes,tags,aliases,screenshot_url,application_url,source_url\n"
                b'16929,exploits/aix/16929.rb,"Acme Daemon, Opcode 21 - Buffer Overflow",2010-11-11,Someone,remote,'
                b"aix,,2010-11-11,,1,CVE-2099-0002;OSVDB-1;CVE-2099-0003,,,,,\n"
                b'19046,exploits/x/19046.txt,"No CVE here",1999-10-15,"A B",dos,aix,,1999-10-15,,0,OSVDB-5970,,,,,\n')
        self.assertEqual(self.rows(self.check("exploitdb", data)), [
            ("exploitdb", "CVE-2099-0002", "16929", "Acme Daemon, Opcode 21 - Buffer Overflow", "remote, verified"),
            ("exploitdb", "CVE-2099-0003", "16929", "Acme Daemon, Opcode 21 - Buffer Overflow", "remote, verified")])

    def test_metasploit(self):
        data = fx.dumps({
            "exploit_linux/http/acme_rce": {
                "name": "Acme RCE", "fullname": "exploit/linux/http/acme_rce", "rank": 600, "type": "exploit",
                "references": ["CVE-2099-0004", "URL-https://x.example", 7],
                "path": "/modules/exploits/linux/http/acme_rce.rb"},
            "post_x": {"type": "post", "references": ["CVE-2099-0005"], "path": "/modules/post/x.rb"},
            "bad": "not a module"})
        self.assertEqual(self.rows(self.check("metasploit", data)), [
            ("metasploit", "CVE-2099-0004", "modules/exploits/linux/http/acme_rce.rb", "Acme RCE", "exploit, rank 600")])

    def test_emerging_threats_rules(self):
        data = (b"# a comment\n"
                b'#alert tcp any any -> any any (msg:"ET EXPLOIT ships disabled"; reference:cve,2099-0006; sid:1; rev:1;)\n'
                b'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Acme RCE Attempt"; flow:established,to_server; '
                b"reference:cve,2099-0007; reference:cve,CVE-2099-0008; classtype:attempted-admin; sid:2010375; rev:2;)\n"
                b'alert tcp any any -> any any (msg:"no cve here"; sid:5; rev:1;)\n')
        self.assertEqual(self.rows(self.check("et_rules", data)), [
            ("suricata-et", "CVE-2099-0007", "2010375", "ET EXPLOIT Acme RCE Attempt", ""),
            ("suricata-et", "CVE-2099-0008", "2010375", "ET EXPLOIT Acme RCE Attempt", "")])

    def test_sigma_tarball_is_read_without_extracting(self):
        import io
        import tarfile
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            def add(name, text):
                info = tarfile.TarInfo(name)
                body = text.encode()
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
            add("sigma-master/rules-emerging-threats/2099/Exploits/CVE-2099-0009/acme.yml",
                "title: Acme Exploit Attempt\nid: 1\ntags:\n    - attack.initial-access\n    - cve.2099-0009\n")
            add("sigma-master/rules/linux/other.yml", "title: Other Rule\ntags:\n    - cve.2099-0010\n")
            add("sigma-master/tests/not_a_rule.yml", "title: Test\ntags:\n    - cve.2099-0011\n")
            add("sigma-master/README.md", "cve.2099-0012")
            link = tarfile.TarInfo("sigma-master/rules/link.yml")
            link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
            archive.addfile(link)
        self.assertEqual(self.rows(self.check("sigma_tar", buffer.getvalue())), [
            ("sigma", "CVE-2099-0009", "rules-emerging-threats/2099/Exploits/CVE-2099-0009/acme.yml",
             "Acme Exploit Attempt", ""),
            ("sigma", "CVE-2099-0010", "rules/linux/other.yml", "Other Rule", "")])

    def test_empty_indexes_are_errors_not_empty_snapshots(self):
        for parser, data in (("nuclei_index", b"{}\n"), ("exploitdb", b"id,codes\n"), ("metasploit", b"{}"),
                             ("et_rules", b"# nothing\n")):
            with self.assertRaises(ValueError):
                parse.PARSERS[parser](data, entry(parser=parser, data=data))

    def test_identifiers_that_could_not_be_safe_links_are_refused(self):
        base = {"type": "coverage", "cve": "CVE-2099-0001", "title": "t", "note": "",
                "src": {"source": "s", "sha256": "a" * 64}}
        for ident in ("../../etc/passwd", "rules/../../x.yml", "a b.yml", "https://evil.example/x", "", "x\ny", 5):
            with self.assertRaises(validate.Invalid):
                validate.validate(dict(base, kind="sigma", ident=ident))
        for kind, ident in (("exploitdb", "12a"), ("suricata-et", "-1"), ("pastebin", "1")):
            with self.assertRaises(validate.Invalid):
                validate.validate(dict(base, kind=kind, ident=ident))
        self.assertEqual(validate.validate(dict(base, kind="exploitdb", ident="123"))["ident"], "123")

    def test_store_keeps_snapshots_and_notes_newly_covered_cves(self):
        def obs(cve, ident="rules/a.yml"):
            return {"type": "coverage", "kind": "sigma", "cve": cve, "ident": ident, "title": "T", "note": ""}

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "coverage", "sigma.json")
            recent = os.path.join(tmp, "coverage", "recent.json")
            store.apply(tmp, [obs("CVE-2099-0001"), obs("CVE-2099-0002"), obs("CVE-2099-0002", "rules/b.yml")], NOW)
            self.assertEqual(common.read_json(path, {})["CVE-2099-0002"], [["rules/a.yml", "T", ""], ["rules/b.yml", "T", ""]])
            self.assertEqual(common.read_json(recent, None), {})          # first load: nothing is "new"

            store.apply(tmp, [obs("CVE-2099-0001"), obs("CVE-2099-0002"), obs("CVE-2099-0003")], NOW)
            self.assertEqual(common.read_json(recent, {}), {"CVE-2099-0003": {"day": "2099-01-04", "kinds": ["sigma"]}})
            self.assertEqual(sorted(common.read_json(path, {})), ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"])

            # A snapshot that lost most of its entries is refused, not stored.
            stats = store.apply(tmp, [obs("CVE-2099-0001")], NOW)
            self.assertEqual(stats["coverage_refused"], 1)
            self.assertEqual(len(common.read_json(path, {})), 3)

            later = NOW + dt.timedelta(days=20)
            store.apply(tmp, [obs("CVE-2099-0001"), obs("CVE-2099-0002"), obs("CVE-2099-0003")], later)
            self.assertEqual(common.read_json(recent, None), {})          # the note expires

    def test_recent_notes_whether_exploit_code_is_a_first(self):
        def obs(kind, cve, ident="1"):
            return {"type": "coverage", "kind": kind, "cve": cve, "ident": ident, "title": "T", "note": ""}

        with tempfile.TemporaryDirectory() as tmp:
            recent = os.path.join(tmp, "coverage", "recent.json")
            # First load of each list: nothing is new.
            store.apply(tmp, [obs("metasploit", "CVE-2099-0001", "modules/a.rb"), obs("exploitdb", "CVE-2099-0002"),
                              obs("nuclei", "CVE-2099-0003", "http/a.yaml")], NOW)
            self.assertEqual(common.read_json(recent, None), {})
            store.apply(tmp, [
                obs("metasploit", "CVE-2099-0001", "modules/a.rb"),
                obs("metasploit", "CVE-2099-0002", "modules/b.rb"),   # already had an Exploit-DB entry
                obs("metasploit", "CVE-2099-0009", "modules/c.rb"),   # its first exploit code ever
                obs("exploitdb", "CVE-2099-0002"),
                obs("nuclei", "CVE-2099-0003", "http/a.yaml"),
                obs("nuclei", "CVE-2099-0001", "http/b.yaml"),        # a scanner template for a known exploit
            ], NOW)
            self.assertEqual(common.read_json(recent, {}), {
                "CVE-2099-0001": {"day": "2099-01-04", "kinds": ["nuclei"]},
                "CVE-2099-0002": {"day": "2099-01-04", "kinds": ["metasploit"]},
                "CVE-2099-0009": {"day": "2099-01-04", "kinds": ["metasploit"], "first_exploit": True},
            })

    def test_a_re_indexed_list_is_stored_but_not_called_news(self):
        def obs(n):
            return {"type": "coverage", "kind": "exploitdb", "cve": "CVE-2099-%05d" % n, "ident": str(n),
                    "title": "T", "note": ""}

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "coverage", "exploitdb.json")
            recent = os.path.join(tmp, "coverage", "recent.json")
            store.apply(tmp, [obs(n) for n in range(1000)], NOW)
            # One refresh adds far more CVEs than a day of new exploits could.
            stats = store.apply(tmp, [obs(n) for n in range(1000 + store.COVERAGE_BURST + 1)], NOW)
            self.assertEqual(stats["coverage_bursts"], 1)
            self.assertEqual(len(common.read_json(path, {})), 1000 + store.COVERAGE_BURST + 1)
            self.assertEqual(common.read_json(recent, None), {})
            # An ordinary day afterwards is noted as usual.
            stats = store.apply(tmp, [obs(n) for n in range(1000 + store.COVERAGE_BURST + 3)], NOW)
            self.assertNotIn("coverage_bursts", stats)
            self.assertEqual(sorted(common.read_json(recent, {})), ["CVE-2099-01301", "CVE-2099-01302"])
            self.assertTrue(all(entry.get("first_exploit") for entry in common.read_json(recent, {}).values()))

    def test_bulk_sources_are_stored_apart_and_still_parsed(self):
        data = b'{"ID":"CVE-2099-0001","Info":{"Name":"Acme"},"file_path":"http/cves/2099/CVE-2099-0001.yaml"}\n'
        src = {"id": "nuclei-index", "role": "coverage", "bulk": True}
        with tempfile.TemporaryDirectory() as tmp:
            writer = collect.RawWriter(tmp)
            digest = writer.add(src, "nuclei_index", "https://example.com/cves.json", data, "2099-01-04T12:00:00Z")
            self.assertTrue(os.path.exists(os.path.join(tmp, "bulk", digest)))
            self.assertFalse(os.path.exists(os.path.join(tmp, "raw", digest)))
            with open(os.path.join(tmp, "manifest.jsonl"), "w") as handle:
                handle.write(json.dumps(writer.entries[0]) + "\n")
            report = parse.run(tmp, os.path.join(tmp, "parsed"))
            self.assertEqual(report["sources"]["nuclei-index"], {"files": 1, "errors": 0, "observations": 1})
            summary = commit.run(os.path.join(tmp, "data"), tmp, os.path.join(tmp, "parsed"), now=NOW)
            self.assertEqual(summary["applied"]["coverage"], 1)
            table = common.read_json(os.path.join(tmp, "data", "coverage", "nuclei.json"), {})
            self.assertEqual(table, {"CVE-2099-0001": [["http/cves/2099/CVE-2099-0001.yaml", "Acme", ""]]})


REDHAT_DOC = {
    "name": "CVE-2099-6387", "threat_severity": "Important",
    "affected_release": [
        {"product_name": "Red Hat Enterprise Linux 9", "release_date": "2099-01-03T00:00:00Z",
         "advisory": "RHSA-2099:4312", "cpe": "cpe:/a:redhat:enterprise_linux:9",
         "package": "openssh-0:8.7p1-38.el9_4.1"},
        {"product_name": "Red Hat OpenShift Container Platform 4.13", "advisory": "RHSA-2099:4484",
         "package": "openshift/ose-rhel-coreos-9:413.92.202407091321-0"},
    ],
    "package_state": [
        {"product_name": "Red Hat Ceph Storage 5", "fix_state": "Not affected", "package_name": "openssh"},
        {"product_name": "Red Hat Enterprise Linux 6", "fix_state": "Out of support scope", "package_name": "openssh"},
        {"product_name": "Red Hat Enterprise Linux 8", "fix_state": "Affected", "package_name": "openssh"},
        "not an object",
    ],
}
OSV_DEBIAN = {
    "id": "DEBIAN-CVE-2099-6387", "upstream": ["CVE-2099-6387"],
    "affected": [
        {"package": {"name": "openssh", "ecosystem": "Debian:12"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:9.2p1-2+deb12u3"}]}]},
        {"package": {"name": "openssh", "ecosystem": "Debian:11"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
    ],
}
OSV_UBUNTU = {
    "id": "UBUNTU-CVE-2099-6387", "related": ["USN-6859-1"], "upstream": ["CVE-2099-6387"],
    "affected": [{"package": {"name": "openssh", "ecosystem": "Ubuntu:24.04:LTS"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:9.6p1-3ubuntu13.3"}]}]}],
}


class FixTests(unittest.TestCase):
    """Which package version fixes a CVE, as each vendor states it."""

    def check(self, parser, doc):
        data = fx.dumps(doc)
        item = entry(source="fix", parser=parser, data=data)
        manifest = {item["sha256"]: item}
        out = [validate.validate(obs, manifest) for obs in parse.PARSERS[parser](data, item)]
        return [(o["vendor"], o["product"], o["package"], o["fixed"], o["state"], o["advisory"]) for o in out]

    def test_red_hat(self):
        self.assertEqual(self.check("redhat_cve", REDHAT_DOC), [
            ("redhat", "Red Hat Enterprise Linux 9", "openssh", "8.7p1-38.el9_4.1", "fixed", "RHSA-2099:4312"),
            # A container image is not name-version-release: keep the name, claim no version.
            ("redhat", "Red Hat OpenShift Container Platform 4.13",
             "openshift/ose-rhel-coreos-9:413.92.202407091321-0", "", "fixed", "RHSA-2099:4484"),
            ("redhat", "Red Hat Ceph Storage 5", "openssh", "", "not_affected", ""),
            ("redhat", "Red Hat Enterprise Linux 6", "openssh", "", "wont_fix", ""),
            ("redhat", "Red Hat Enterprise Linux 8", "openssh", "", "affected", ""),
        ])

    def test_debian_and_ubuntu_from_osv(self):
        self.assertEqual(self.check("osv_distro", OSV_DEBIAN), [
            ("debian", "Debian:12", "openssh", "1:9.2p1-2+deb12u3", "fixed", ""),
            ("debian", "Debian:11", "openssh", "", "affected", ""),
        ])
        self.assertEqual(self.check("osv_distro", OSV_UBUNTU), [
            ("ubuntu", "Ubuntu:24.04:LTS", "openssh", "1:9.6p1-3ubuntu13.3", "fixed", "USN-6859-1"),
        ])
        data = fx.dumps({"id": "GHSA-xxxx", "affected": []})
        with self.assertRaises(ValueError):
            parse.parse_osv_distro(data, entry(parser="osv_distro", data=data))

    def test_validation_drops_odd_versions_and_advisories(self):
        base = {"type": "fix", "cve": "CVE-2099-6387", "vendor": "redhat", "product": "RHEL 9", "package": "openssh",
                "state": "fixed", "src": {"source": "s", "sha256": "a" * 64}}
        clean = validate.validate(dict(base, fixed="1.0'; DROP TABLE x;--", advisory="<b>RHSA</b>"))
        self.assertEqual((clean["fixed"], clean["advisory"]), ("", ""))
        for bad in (dict(base, vendor="acme"), dict(base, state="maybe"), dict(base, package=""), dict(base, cve="x")):
            with self.assertRaises(validate.Invalid):
                validate.validate(bad)

    def test_store_keeps_one_statement_per_vendor(self):
        def obs(vendor, product, fixed, state="fixed"):
            return {"type": "fix", "cve": "CVE-2099-6387", "vendor": vendor, "product": product, "package": "openssh",
                    "fixed": fixed, "state": state, "advisory": ""}

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "fixes", "2099", "6xxx", "CVE-2099-6387.json")
            store.apply(tmp, [obs("redhat", "RHEL 9", "8.7p1-38.el9"), obs("debian", "Debian:12", "", "affected")], NOW)
            record = common.read_json(path, {})
            self.assertEqual([r["fixed"] for r in record["redhat"]], ["8.7p1-38.el9"])
            self.assertEqual(record["debian"][0]["state"], "affected")
            # Debian ships its fix: only Debian's statement is replaced.
            stats = store.apply(tmp, [obs("debian", "Debian:12", "1:9.2p1-2+deb12u3")], NOW)
            record = common.read_json(path, {})
            self.assertEqual(stats["fix"], 1)
            self.assertEqual(record["debian"], [{"product": "Debian:12", "package": "openssh",
                                                 "fixed": "1:9.2p1-2+deb12u3", "state": "fixed", "advisory": ""}])
            self.assertEqual(len(record["redhat"]), 1)
            self.assertNotIn("fix", store.apply(tmp, [obs("debian", "Debian:12", "1:9.2p1-2+deb12u3")], NOW))

    def test_per_cve_lookup_remembers_what_it_asked(self):
        class Fetcher:
            def __init__(self):
                self.calls = []

            def get(self, url, max_bytes, etag=None, auth=None, any_https_redirect=False):
                self.calls.append(url)
                if url.endswith("CVE-2099-0001.json"):
                    return 200, fx.dumps(REDHAT_DOC), None
                raise collect.FetchError("HTTP 404" if url.endswith("CVE-2099-0002.json") else "HTTP 503")

        src = {"id": "fix-redhat", "kind": "per_cve", "parser": "redhat_cve", "every_minutes": 60,
               "max_per_run": 10, "refresh_days": 3, "url_template": "https://vendor.example/cve/{cve}.json"}
        names = ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003", "not-a-cve"]
        with tempfile.TemporaryDirectory() as tmp:
            fetcher, writer = Fetcher(), collect.RawWriter(tmp)
            report, cursor = collect.collect_per_cve(src, fetcher, {}, writer, CONFIG, NOW, enrich=names)
            self.assertEqual((report["status"], report["items"]), ("ok", 1))
            self.assertEqual(report["detail"], "1 found, 1 not tracked by this vendor, 1 failed")
            # Found and "vendor has nothing" are remembered; the server error is not, so it is retried.
            self.assertEqual(cursor, {"fetched": {"CVE-2099-0001": "2099-01-04", "CVE-2099-0002": "none:2099-01-04"}})
            self.assertEqual(writer.entries[0]["hint"], "CVE-2099-0001")

            fetcher.calls.clear()
            collect.collect_per_cve(src, fetcher, cursor, writer, CONFIG, NOW + dt.timedelta(days=1), enrich=names)
            self.assertEqual(fetcher.calls, ["https://vendor.example/cve/CVE-2099-0003.json"])
            fetcher.calls.clear()
            collect.collect_per_cve(src, fetcher, cursor, writer, CONFIG, NOW + dt.timedelta(days=4), enrich=names)
            self.assertEqual(sorted(fetcher.calls), ["https://vendor.example/cve/CVE-2099-0001.json",
                                                     "https://vendor.example/cve/CVE-2099-0003.json"])
            fetcher.calls.clear()
            collect.collect_per_cve(src, fetcher, cursor, writer, CONFIG, NOW + dt.timedelta(days=15), enrich=names)
            self.assertIn("https://vendor.example/cve/CVE-2099-0002.json", fetcher.calls)   # asked again after two weeks

    def test_known_exploited_cves_are_asked_about_first(self):
        class Fetcher:
            calls = []

            def get(self, url, max_bytes, etag=None, auth=None, any_https_redirect=False):
                self.calls.append(url)
                raise collect.FetchError("HTTP 404")

        cfg = {"sources": [{"id": "fix-redhat", "kind": "per_cve", "parser": "redhat_cve", "every_minutes": 60,
                            "max_per_run": 1, "url_template": "https://vendor.example/{cve}.json"}]}
        with tempfile.TemporaryDirectory() as tmp:
            state = os.path.join(tmp, "data", "state")
            common.write_json_atomic(os.path.join(state, "enrich.json"),
                                     {"CVE-2099-9000": "2099-01-04", "CVE-2098-0001": "2099-01-01"})
            common.write_json_atomic(os.path.join(tmp, "data", "kev.json"), {"CVE-2098-0001": {}})
            fetcher = Fetcher()
            collect.run(cfg, state, os.path.join(tmp, "out"), now=NOW, fetcher=fetcher)
            self.assertEqual(fetcher.calls, ["https://vendor.example/CVE-2098-0001.json"])

    def test_commit_lists_the_cves_worth_asking_vendors_about(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "news"))
            with open(os.path.join(tmp, "news", "2099-01-04.jsonl"), "w") as handle:
                handle.write(json.dumps({"cves": ["CVE-2099-0001", "junk"]}) + "\n")
            common.write_json_atomic(os.path.join(tmp, "kev.json"), {"CVE-2099-0002": {"date_added": "2099-01-01"}})
            common.write_json_atomic(os.path.join(tmp, "state", "enrich.json"),
                                     {"CVE-2098-0009": "2098-11-01", "CVE-2099-0005": "2098-12-20"})
            commit.update_wanted(tmp, {"sources": {}}, NOW)
            self.assertEqual(common.read_json(os.path.join(tmp, "state", "enrich.json"), {}),
                             {"CVE-2099-0001": "2099-01-04", "CVE-2099-0002": "2099-01-04", "CVE-2099-0005": "2098-12-20"})

    def test_shipped_config_has_the_vendor_lookups(self):
        path = os.path.join(os.path.dirname(__file__), "..", "config", "sources.json")
        cfg = collect.load_config(path)
        kinds = {s["id"]: s["kind"] for s in cfg["sources"]}
        self.assertEqual({k for k, v in kinds.items() if v == "per_cve"}, {"fix-redhat", "fix-debian", "fix-ubuntu"})
        self.assertIn("api.osv.dev", collect.allowed_hosts(cfg))


if __name__ == "__main__":
    unittest.main()
