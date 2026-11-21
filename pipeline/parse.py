"""Parse stage: turn raw documents into small, uniform observations.

Runs inside a sandbox with no network and no credentials. Everything it reads
is untrusted. Its output is untrusted too: the commit stage re-validates every
field before anything is stored.

Usage: python3 -m pipeline.parse --in DIR --out DIR [--require-sandbox]
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import os
import re
import socket
import sys
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List

from . import common

MAX_RAW = 150 * 1024 * 1024
MAX_DECOMPRESSED = 250 * 1024 * 1024
MAX_FEED_ITEMS = 200

T = common.clean_text

_TAG = re.compile(r"<[^>]{0,500}>")
_NAME_SUFFIX = re.compile(
    r"(?<![A-Za-z0-9])([A-Z][A-Za-z0-9]{1,24}(?:Shell|Bleed|Nightmare|Ghost|Potato|Smash|Pwn))(?![A-Za-z0-9])"
)
_NAME_DUBBED = re.compile(
    r"(?:dubbed|nicknamed|codenamed|named|called|known as)\s+[\"'‘“]?([A-Z][A-Za-z0-9-]{3,30})"
)
_NAME_STOP = {
    "powershell", "webshell", "nushell", "cloudshell", "secureshell", "bashshell", "reverseshell",
    "microsoft", "google", "apple", "windows", "linux", "github", "cisco", "oracle", "android",
}


def find_cves(text: str) -> List[str]:
    return sorted({match.upper() for match in common.CVE_FIND_RE.findall(text)})[:50]


def find_bug_names(title: str) -> List[str]:
    """Heuristic: nicknames such as Log4Shell or CitrixBleed, or 'dubbed X'."""
    names = []
    for match in _NAME_SUFFIX.findall(title) + _NAME_DUBBED.findall(title):
        if match.lower() not in _NAME_STOP and not match.upper().startswith("CVE-") and match not in names:
            names.append(match)
    return names[:5]


def strip_tags(text: str) -> str:
    return _TAG.sub(" ", text)


def _load_json(data: bytes) -> Any:
    return json.loads(data.decode("utf-8", "replace"))


def _src(entry: Dict[str, Any]) -> Dict[str, str]:
    return {"source": entry["source"], "sha256": entry["sha256"]}


# --- CVE records (cvelistV5, record format 5.x) ------------------------------

_CVSS_KEYS = (("cvssV4_0", "v4"), ("cvssV3_1", "v3"), ("cvssV3_0", "v3"))


def _first_english(descriptions: Any) -> str:
    fallback = ""
    for item in descriptions if isinstance(descriptions, list) else []:
        if isinstance(item, dict) and isinstance(item.get("value"), str):
            if str(item.get("lang", "")).lower().startswith("en"):
                return item["value"]
            fallback = fallback or item["value"]
    return fallback


def _affected(container: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    items = container.get("affected")
    for item in (items if isinstance(items, list) else [])[:60]:
        if not isinstance(item, dict):
            continue
        versions = []
        raw_versions = item.get("versions")
        for ver in (raw_versions if isinstance(raw_versions, list) else [])[:60]:
            if isinstance(ver, dict):
                versions.append({
                    "version": T(ver.get("version"), 80),
                    "status": T(ver.get("status"), 20),
                    "less_than": T(ver.get("lessThan"), 80),
                    "less_than_or_equal": T(ver.get("lessThanOrEqual"), 80),
                    "version_type": T(ver.get("versionType"), 20),
                })
        cpes = item.get("cpes")
        out.append({
            "vendor": T(item.get("vendor"), 120),
            "product": T(item.get("product"), 160),
            "package": T(item.get("packageName"), 160),
            "collection_url": T(item.get("collectionURL"), 300),
            "default_status": T(item.get("defaultStatus"), 20),
            "cpes": [T(cpe, 300) for cpe in (cpes if isinstance(cpes, list) else [])[:20] if isinstance(cpe, str)],
            "versions": versions,
        })
    return out


def _metrics(container: Dict[str, Any], source: str, obs: Dict[str, Any], is_adp: bool) -> None:
    metrics = container.get("metrics")
    for metric in (metrics if isinstance(metrics, list) else [])[:30]:
        if not isinstance(metric, dict):
            continue
        for key, slot in _CVSS_KEYS:
            cvss = metric.get(key)
            if not isinstance(cvss, dict) or slot in obs["cvss"]:
                continue
            score = cvss.get("baseScore")
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                obs["cvss"][slot] = {
                    "score": float(score), "vector": T(cvss.get("vectorString"), 200), "source": source,
                }
        other = metric.get("other")
        if not is_adp or not isinstance(other, dict) or not isinstance(other.get("content"), dict):
            continue
        kind = str(other.get("type", "")).lower()
        content = other["content"]
        if kind == "ssvc":
            options = content.get("options")
            for option in (options if isinstance(options, list) else [])[:10]:
                for key, value in (option.items() if isinstance(option, dict) else []):
                    name = str(key).strip().lower().replace(" ", "_")
                    if name in ("exploitation", "automatable", "technical_impact") and isinstance(value, str):
                        obs["ssvc"][name] = T(value.lower(), 20)
        elif kind == "kev":
            obs["kev_adp"] = T(content.get("dateAdded"), 10)


def parse_cve(data: bytes, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    doc = _load_json(data)
    if not isinstance(doc, dict):
        raise ValueError("record is not an object")
    meta = doc.get("cveMetadata") if isinstance(doc.get("cveMetadata"), dict) else {}
    containers = doc.get("containers") if isinstance(doc.get("containers"), dict) else {}
    cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else {}
    adps = [adp for adp in (containers.get("adp") or []) if isinstance(adp, dict)][:10] \
        if isinstance(containers.get("adp"), list) else []

    obs: Dict[str, Any] = {
        "type": "cve",
        "id": T(meta.get("cveId"), 30),
        "state": T(meta.get("state"), 20),
        "assigner": T(meta.get("assignerShortName"), 80),
        "published": T(meta.get("datePublished"), 40),
        "updated": T(meta.get("dateUpdated"), 40),
        "title": T(cna.get("title"), 300),
        "description": T(_first_english(cna.get("descriptions")), 2000),
        "affected": _affected(cna),
        "cvss": {}, "ssvc": {}, "kev_adp": "",
        "cwes": [], "references": [],
        "src": _src(entry),
    }
    _metrics(cna, "cna", obs, is_adp=False)
    for adp in adps:
        provider = adp.get("providerMetadata") if isinstance(adp.get("providerMetadata"), dict) else {}
        _metrics(adp, "adp:" + T(provider.get("shortName"), 40), obs, is_adp=True)
        if not obs["affected"]:
            obs["affected"] = _affected(adp)

    problem_types = cna.get("problemTypes")
    for problem in (problem_types if isinstance(problem_types, list) else [])[:20]:
        descs = problem.get("descriptions") if isinstance(problem, dict) else None
        for desc in (descs if isinstance(descs, list) else [])[:20]:
            cwe = desc.get("cweId") if isinstance(desc, dict) else None
            if isinstance(cwe, str) and cwe not in obs["cwes"]:
                obs["cwes"].append(T(cwe, 20))
    references = cna.get("references")
    for ref in (references if isinstance(references, list) else [])[:30]:
        url = ref.get("url") if isinstance(ref, dict) else None
        if isinstance(url, str):
            obs["references"].append(T(url, 2000))
    return [obs]


# --- CISA KEV ----------------------------------------------------------------

def parse_kev(data: bytes, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    doc = _load_json(data)
    items = doc.get("vulnerabilities") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise ValueError("no vulnerabilities list")
    out = []
    for item in items[:20000]:
        if not isinstance(item, dict):
            continue
        out.append({
            "type": "kev",
            "cve": T(item.get("cveID"), 30),
            "vendor": T(item.get("vendorProject"), 120),
            "product": T(item.get("product"), 160),
            "name": T(item.get("vulnerabilityName"), 300),
            "date_added": T(item.get("dateAdded"), 10),
            "due_date": T(item.get("dueDate"), 10),
            "ransomware": T(item.get("knownRansomwareCampaignUse"), 20),
            "src": _src(entry),
        })
    return out


# --- FIRST EPSS --------------------------------------------------------------

def parse_epss(data: bytes, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    if data[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
            data = handle.read(MAX_DECOMPRESSED + 1)
        if len(data) > MAX_DECOMPRESSED:
            raise ValueError("decompressed file too large")
    text = data.decode("utf-8", "replace")
    model, date = "", ""
    lines = text.splitlines()
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            key, _, value = part.partition(":")
            if key.strip() == "model_version":
                model = T(value, 40)
            elif key.strip() == "score_date":
                date = T(value, 10)
        lines = lines[1:]
    p95, p80 = [], []
    for row in csv.DictReader(lines):
        cve_id = (row.get("cve") or "").strip().upper()
        try:
            percentile = float(row.get("percentile") or "")
        except ValueError:
            continue
        if not common.CVE_RE.match(cve_id):
            continue
        if percentile >= 0.95:
            p95.append(cve_id)
        elif percentile >= 0.80:
            p80.append(cve_id)
    if not p95 and not p80:
        raise ValueError("no usable EPSS rows")
    return [{"type": "epss", "date": date, "model": model,
             "p95": sorted(p95), "p80": sorted(p80), "src": _src(entry)}]


# --- GitHub Advisory Database (REST) -----------------------------------------

def parse_ghsa(data: bytes, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    doc = _load_json(data)
    if not isinstance(doc, list):
        raise ValueError("advisories response is not a list")
    out = []
    for adv in doc[:500]:
        if not isinstance(adv, dict):
            continue
        packages = []
        vulns = adv.get("vulnerabilities")
        for vuln in (vulns if isinstance(vulns, list) else [])[:40]:
            package = vuln.get("package") if isinstance(vuln, dict) else None
            if not isinstance(package, dict):
                continue
            patched = vuln.get("first_patched_version")
            if isinstance(patched, dict):
                patched = patched.get("identifier")
            packages.append({
                "ecosystem": T(package.get("ecosystem"), 40),
                "name": T(package.get("name"), 200),
                "range": T(vuln.get("vulnerable_version_range"), 200),
                "patched": T(patched, 80),
            })
        out.append({
            "type": "ghsa",
            "id": T(adv.get("ghsa_id"), 30),
            "cve": T(adv.get("cve_id"), 30),
            "summary": T(adv.get("summary"), 300),
            "severity": T(adv.get("severity"), 20),
            "published": T(adv.get("published_at"), 40),
            "updated": T(adv.get("updated_at"), 40),
            "withdrawn": bool(adv.get("withdrawn_at")),
            "packages": packages,
            "src": _src(entry),
        })
    return out


# --- News: Hacker News search and RSS/Atom/RDF feeds -------------------------

def _news(entry, url, title, published, text):
    return {
        "type": "news",
        "url": T(url, 2000),
        "title": T(title, 300),
        "published": common.ts(published) if published else "",
        "cves": find_cves(text),
        "names": find_bug_names(T(title, 300)),
        "src": _src(entry),
    }


def parse_hn(data: bytes, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    doc = _load_json(data)
    hits = doc.get("hits") if isinstance(doc, dict) else None
    if not isinstance(hits, list):
        raise ValueError("no hits list")
    out = []
    for hit in hits[:MAX_FEED_ITEMS]:
        if not isinstance(hit, dict) or not isinstance(hit.get("title"), str):
            continue
        url = hit.get("url")
        if not isinstance(url, str) or not url:
            item_id = str(hit.get("objectID", ""))
            if not item_id.isdigit():
                continue
            url = "https://news.ycombinator.com/item?id=" + item_id
        out.append(_news(entry, url, hit["title"], common.parse_any_date(hit.get("created_at")),
                         hit["title"] + " " + url))
    return out


def _local(tag: Any) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def parse_feed(data: bytes, entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    if b"<!entity" in data.lower():
        raise ValueError("feeds that declare XML entities are refused")
    root = ET.fromstring(data)
    out = []
    count = 0
    for item in root.iter():
        if _local(item.tag) not in ("item", "entry"):
            continue
        count += 1
        if count > MAX_FEED_ITEMS:
            break
        fields: Dict[str, str] = {}
        for child in item:
            name = _local(child.tag)
            if name == "link":
                href = child.get("href")
                if href and child.get("rel") in (None, "alternate"):
                    fields.setdefault("link", href)
                elif child.text and child.text.strip():
                    fields.setdefault("link", child.text.strip())
            elif name in ("title", "pubdate", "published", "updated", "date",
                          "description", "summary", "content", "encoded"):
                fields.setdefault(name, "".join(child.itertext())[:200000])
        link = fields.get("link", "")
        if not link:
            for key, value in item.attrib.items():
                if _local(key) == "about":
                    link = value
        title = strip_tags(fields.get("title", ""))
        if not link or not title.strip():
            continue
        published = None
        for key in ("pubdate", "published", "date", "updated"):
            published = common.parse_any_date(fields.get(key))
            if published:
                break
        body = " ".join(fields.get(key, "") for key in ("description", "summary", "content", "encoded"))
        out.append(_news(entry, link, title, published, title + " " + strip_tags(body)[:50000]))
    return out


PARSERS: Dict[str, Callable[[bytes, Dict[str, Any]], List[Dict[str, Any]]]] = {
    "cve": parse_cve, "kev": parse_kev, "epss": parse_epss,
    "ghsa": parse_ghsa, "hn": parse_hn, "feed": parse_feed,
}


def assert_no_network() -> None:
    """Fail closed: refuse to parse untrusted input if a network path exists."""
    try:
        conn = socket.create_connection(("1.1.1.1", 443), timeout=3)
    except OSError:
        return
    conn.close()
    raise SystemExit("refusing to parse: this process can reach the network")


def run(in_dir: str, out_dir: str) -> Dict[str, Any]:
    report: Dict[str, Any] = {"sources": {}}
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "observations.jsonl"), "w", encoding="utf-8") as sink:
        for entry in common.read_jsonl(os.path.join(in_dir, "manifest.jsonl")):
            source = entry.get("source")
            digest = entry.get("sha256")
            parser = PARSERS.get(entry.get("parser"))
            if not isinstance(source, str) or not common.SOURCE_ID_RE.match(source):
                continue
            stats = report["sources"].setdefault(source, {"files": 0, "errors": 0, "observations": 0})
            stats["files"] += 1
            try:
                if parser is None or not isinstance(digest, str) or not common.SHA256_RE.match(digest):
                    raise ValueError("bad manifest entry")
                path = os.path.join(in_dir, "raw", digest)
                if os.path.islink(path) or os.path.getsize(path) > MAX_RAW:
                    raise ValueError("raw file is a link or too large")
                with open(path, "rb") as handle:
                    data = handle.read()
                if common.sha256_bytes(data) != digest:
                    raise ValueError("raw file does not match its hash")
                observations = parser(data, entry)
            except Exception as err:  # one bad document must not stop the rest
                stats["errors"] += 1
                stats["last_error"] = "%s: %s" % (type(err).__name__, str(err)[:160])
                continue
            for obs in observations:
                sink.write(json.dumps(obs, sort_keys=True) + "\n")
            stats["observations"] += len(observations)
    common.write_json_atomic(os.path.join(out_dir, "parse-report.json"), report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="in_dir", required=True)
    parser.add_argument("--out", dest="out_dir", required=True)
    parser.add_argument("--require-sandbox", action="store_true",
                        help="abort unless the process is cut off from the network")
    args = parser.parse_args(argv)
    if args.require_sandbox:
        assert_no_network()
    report = run(args.in_dir, args.out_dir)
    print(json.dumps(report, sort_keys=True), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
