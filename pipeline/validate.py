"""Strict validation of parser output.

The parser runs on untrusted input, so its output is treated as untrusted. Each
validator rebuilds the observation from known fields only: unknown keys are
dropped, strings are cleaned and capped, IDs must match their pattern, and the
evidence pointer must match a document the collector really fetched.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import common

PARSER_TYPE = {"cve": "cve", "kev": "kev", "epss": "epss", "ghsa": "ghsa", "hn": "news", "feed": "news",
               "nuclei_index": "coverage", "exploitdb": "coverage", "metasploit": "coverage",
               "et_rules": "coverage", "sigma_tar": "coverage"}

_ROLES = ("backbone", "exploitation", "ecosystem", "trend", "vendor", "coverage")
_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./+-]{1,250}$")
_NUMBER = re.compile(r"^[0-9]{1,10}$")
_COVERAGE_IDENT = {"nuclei": _PATH, "sigma": _PATH, "metasploit": _PATH, "exploitdb": _NUMBER, "suricata-et": _NUMBER}
_STATES = ("PUBLISHED", "REJECTED")
_STATUSES = ("affected", "unaffected", "unknown")
_SSVC = {
    "exploitation": ("none", "poc", "active"),
    "automatable": ("yes", "no"),
    "technical_impact": ("partial", "total"),
}


class Invalid(ValueError):
    pass


def _s(value: Any, max_len: int) -> str:
    return common.clean_text(value, max_len) if isinstance(value, str) else ""


def _url(value: Any) -> str:
    text = _s(value, 2000)
    return text if common.URL_RE.match(text) else ""


def _ts(value: Any) -> str:
    parsed = common.parse_ts(value)
    return common.ts(parsed) if parsed else ""


def _date(value: Any) -> str:
    text = _s(value, 10)
    return text if common.DATE_RE.match(text) and common.parse_ts(text) else ""


def _enum(value: Any, allowed) -> str:
    text = _s(value, 40)
    return text if text in allowed else ""


def _list(value: Any, limit: int) -> List[Any]:
    return value[:limit] if isinstance(value, list) else []


def _cve_id(value: Any, required: bool = True) -> str:
    text = _s(value, 30).upper()
    if common.CVE_RE.match(text):
        return text
    if required:
        raise Invalid("bad CVE ID")
    return ""


def _src(obs: Dict[str, Any], manifest: Optional[Dict[str, Dict[str, Any]]]) -> Dict[str, str]:
    src = obs.get("src")
    if not isinstance(src, dict):
        raise Invalid("missing src")
    digest = src.get("sha256")
    source = src.get("source")
    if not isinstance(digest, str) or not common.SHA256_RE.match(digest):
        raise Invalid("bad src.sha256")
    if not isinstance(source, str) or not common.SOURCE_ID_RE.match(source):
        raise Invalid("bad src.source")
    if manifest is None:
        return {"source": source, "origin": source, "role": "", "sha256": digest, "url": "", "fetched_at": ""}
    entry = manifest.get(digest)
    if entry is None or entry.get("source") != source:
        raise Invalid("src does not match a fetched document")
    if PARSER_TYPE.get(entry.get("parser")) != obs.get("type"):
        raise Invalid("observation type does not match the document's parser")
    # URL, origin, role and fetch time come from the collector's manifest, not the parser.
    return {
        "source": source, "origin": _s(entry.get("origin"), 40) or source,
        "role": _enum(entry.get("role"), _ROLES), "sha256": digest,
        "url": _url(entry.get("url")), "fetched_at": _ts(entry.get("fetched_at")),
    }


def _cve(obs, src):
    affected = []
    for item in _list(obs.get("affected"), 60):
        if not isinstance(item, dict):
            continue
        versions = []
        for ver in _list(item.get("versions"), 60):
            if isinstance(ver, dict):
                versions.append({
                    "version": _s(ver.get("version"), 80),
                    "status": _enum(ver.get("status"), _STATUSES),
                    "less_than": _s(ver.get("less_than"), 80),
                    "less_than_or_equal": _s(ver.get("less_than_or_equal"), 80),
                    "version_type": _s(ver.get("version_type"), 20),
                })
        affected.append({
            "vendor": _s(item.get("vendor"), 120),
            "product": _s(item.get("product"), 160),
            "package": _s(item.get("package"), 160),
            "collection_url": _url(item.get("collection_url")),
            "default_status": _enum(item.get("default_status"), _STATUSES),
            "cpes": [c for c in (_s(c, 300) for c in _list(item.get("cpes"), 20)) if c.startswith("cpe:")],
            "versions": versions,
        })
    cvss = {}
    raw_cvss = obs.get("cvss") if isinstance(obs.get("cvss"), dict) else {}
    for slot in ("v4", "v3"):
        entry = raw_cvss.get(slot)
        if not isinstance(entry, dict):
            continue
        score = entry.get("score")
        if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 10:
            cvss[slot] = {"score": round(float(score), 1), "vector": _s(entry.get("vector"), 200),
                          "source": _s(entry.get("source"), 60)}
    ssvc = {}
    raw_ssvc = obs.get("ssvc") if isinstance(obs.get("ssvc"), dict) else {}
    for key, allowed in _SSVC.items():
        value = _enum(raw_ssvc.get(key), allowed)
        if value:
            ssvc[key] = value
    return {
        "type": "cve",
        "id": _cve_id(obs.get("id")),
        "state": _enum(obs.get("state"), _STATES),
        "assigner": _s(obs.get("assigner"), 80),
        "published": _ts(obs.get("published")),
        "updated": _ts(obs.get("updated")),
        "title": _s(obs.get("title"), 300),
        "description": _s(obs.get("description"), 2000),
        "affected": affected,
        "cvss": cvss,
        "ssvc": ssvc,
        "kev_adp": _date(obs.get("kev_adp")),
        "cwes": [c for c in (_s(c, 20) for c in _list(obs.get("cwes"), 20)) if c.startswith("CWE-")],
        "references": [u for u in (_url(u) for u in _list(obs.get("references"), 30)) if u],
        "src": src,
    }


def _kev(obs, src):
    return {
        "type": "kev",
        "cve": _cve_id(obs.get("cve")),
        "vendor": _s(obs.get("vendor"), 120),
        "product": _s(obs.get("product"), 160),
        "name": _s(obs.get("name"), 300),
        "date_added": _date(obs.get("date_added")),
        "due_date": _date(obs.get("due_date")),
        "ransomware": _s(obs.get("ransomware"), 20),
        "src": src,
    }


def _epss(obs, src):
    def ids(value):
        if not isinstance(value, list) or len(value) > 400000:
            raise Invalid("bad EPSS list")
        return sorted({v for v in value if isinstance(v, str) and common.CVE_RE.match(v)})

    p95, p80 = ids(obs.get("p95")), ids(obs.get("p80"))
    if not p95 and not p80:
        raise Invalid("empty EPSS lists")
    return {"type": "epss", "date": _date(obs.get("date")), "model": _s(obs.get("model"), 40),
            "p95": p95, "p80": p80, "src": src}


def _ghsa(obs, src):
    ghsa_id = _s(obs.get("id"), 30)
    if not common.GHSA_RE.match(ghsa_id):
        raise Invalid("bad GHSA ID")
    packages = []
    for item in _list(obs.get("packages"), 40):
        if isinstance(item, dict) and _s(item.get("name"), 200):
            packages.append({
                "ecosystem": _s(item.get("ecosystem"), 40),
                "name": _s(item.get("name"), 200),
                "range": _s(item.get("range"), 200),
                "patched": _s(item.get("patched"), 80),
            })
    return {
        "type": "ghsa",
        "id": ghsa_id,
        "cve": _cve_id(obs.get("cve"), required=False),
        "summary": _s(obs.get("summary"), 300),
        "severity": _enum(obs.get("severity"), ("low", "medium", "high", "critical", "unknown")),
        "published": _ts(obs.get("published")),
        "updated": _ts(obs.get("updated")),
        "withdrawn": obs.get("withdrawn") is True,
        "packages": packages,
        "src": src,
    }


def _news(obs, src):
    url = _url(obs.get("url"))
    title = _s(obs.get("title"), 300)
    if not url or not title:
        raise Invalid("news item needs a URL and a title")
    names = []
    for name in _list(obs.get("names"), 5):
        name = _s(name, 40)
        if name and name.replace("-", "").isalnum() and name.isascii():
            names.append(name)
    return {
        "type": "news",
        "url": url,
        "title": title,
        "published": _ts(obs.get("published")),
        "cves": sorted({c for c in (_cve_id(c, required=False) for c in _list(obs.get("cves"), 50)) if c}),
        "names": names,
        "src": src,
    }


def _coverage(obs, src):
    """A pointer to a public rule or exploit for a CVE: an identifier and a
    title, never content. The identifier must be a plain repository path or
    a number, because links are later built from it."""
    kind = _enum(obs.get("kind"), tuple(_COVERAGE_IDENT))
    ident = obs.get("ident")
    if not kind or not isinstance(ident, str) or not _COVERAGE_IDENT[kind].match(ident) or ".." in ident:
        raise Invalid("bad coverage entry")
    return {
        "type": "coverage",
        "kind": kind,
        "cve": _cve_id(obs.get("cve")),
        "ident": ident,
        "title": _s(obs.get("title"), 200),
        "note": _s(obs.get("note"), 40),
        "src": src,
    }


_VALIDATORS = {"cve": _cve, "kev": _kev, "epss": _epss, "ghsa": _ghsa, "news": _news, "coverage": _coverage}


def validate(obs: Any, manifest: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Return a cleaned copy of the observation, or raise Invalid."""
    if not isinstance(obs, dict):
        raise Invalid("observation is not an object")
    validator = _VALIDATORS.get(obs.get("type"))
    if validator is None:
        raise Invalid("unknown observation type")
    return validator(obs, _src(obs, manifest))
