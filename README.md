# vuln-intel

Collects public vulnerability intelligence on a schedule and commits clean, validated records to this repository's `data` branch. It runs entirely on GitHub Actions; the code uses only the Python standard library.

A separate private repository reads the `data` branch and scores it against an inventory. This repository holds nothing private.

## How a run works

Every 15 minutes the `collect` workflow runs three jobs. Each job gets a fresh virtual machine that GitHub destroys afterwards, and each has only the access it needs.

| Job | Network | Token | What it does |
|---|---|---|---|
| `collect` | Yes | Read-only | Downloads sources that are due. Stores the bytes by SHA-256 and never opens them. |
| `parse` | No | None | Reads the untrusted documents inside a systemd sandbox: no network, unprivileged user, read-only filesystem, syscall filter, resource limits. The parser refuses to start if it can reach the network. |
| `commit` | Yes | Write to `data` | Re-validates every field the parser produced, ties each record to a document the collector really fetched, and commits. |

The parser's output is treated as untrusted. A parser that was taken over by a malicious document can at worst emit records that still have to pass validation; it has no network, no credentials, and cannot name its own evidence.

## Sources

Listed in `config/sources.json`, each with its own interval. A source is fetched when its interval has passed since its last success, so a delayed or skipped run catches up by itself.

- **Backbone:** CVE.org cvelistV5 (changed records only).
- **Exploitation:** CISA KEV, FIRST EPSS, CISA's SSVC decisions inside CVE records.
- **Ecosystem:** GitHub Advisory Database.
- **News and early signal:** Hacker News search, BleepingComputer, The Hacker News, Unit 42, Talos, watchTowr, Wiz, Rapid7.
- **Vendors:** CISA advisories, Ubuntu, Debian, PHP, NGINX, Microsoft.

To add a feed, add an entry with `"kind": "http"` and `"parser": "feed"` (RSS 2.0, Atom and RDF all work). The collector only contacts hosts that appear in this file, and refuses redirects to any other host. The one exception is a source marked `"redirects": "any-https"` (EPSS, which is served through a redirect to a CDN).

## The `data` branch

```
cves/<year>/<n>xxx/<CVE>.json   one record per CVE
ghsa/<xx>/<GHSA>.json           one record per GitHub advisory
kev.json                        CISA KEV entries keyed by CVE
epss/current.json               CVEs at or above the 80th and 95th EPSS percentile
news/<day>.jsonl                news items, by the day they were first seen
state/heartbeat.json            last success and status of every source
state/cursors.json              where each source left off
```

Every record carries `src`: the source, the URL, the fetch time and the SHA-256 of the raw document it came from. Raw documents are kept for 90 days as the `raw` artifact of each workflow run.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests use hand-written fixtures and never touch the network.

## Operations

- `keepalive.yml` re-enables the schedules weekly, because GitHub disables scheduled workflows in public repositories after 60 days without activity.
- Actions are pinned to commit hashes. Update the hash and the version comment together.
- A source that keeps failing shows in `state/heartbeat.json`; the private scorer turns that into an alert.
