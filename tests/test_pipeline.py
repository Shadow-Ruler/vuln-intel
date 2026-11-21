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

            # Second run: nothing is due except the failing sources, and the
            # data files do not change.
            fetcher.calls.clear()
            self.run_pipeline(tmp, fetcher, data_dir)
            self.assertEqual(sorted(set(fetcher.calls) - {BASE + "deltaLog.json"}),
                             sorted([BASE + "2099/0xxx/CVE-2099-0462.json",
                                     BASE + "2099/10xxx/CVE-2099-10001.json",
                                     BASE + "2099/123xxx/CVE-2099-123456.json",
                                     "https://down.example/rss", "https://evil.example/rss"]))
            after = self.snapshot(data_dir)
            changed = sorted(name for name in after if after[name] != files.get(name))
            self.assertEqual(changed, ["state/heartbeat.json"])

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


if __name__ == "__main__":
    unittest.main()
