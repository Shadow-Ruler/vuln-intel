# vuln-intel

Collects public vulnerability intelligence on a schedule and commits clean, validated records to this repository's `data` branch. It runs entirely on GitHub Actions; the code uses only the Python standard library.

A separate private repository reads the `data` branch and scores it against an inventory. This repository holds nothing private.

## What keeps it running: the relay

GitHub's `schedule` trigger did not fire at all in this repository after it was created, a problem other new repositories have reported too. So the pipeline keeps its own clock in `relay.yml`:

1. A relay run waits 14 minutes. The wait is a timer on the `timer` environment, and waiting costs no runner time.
2. It then starts a `collect` run and the next relay run, and finishes.
3. The next relay run waits 14 minutes, and so on. Exactly one is ever waiting.

If the chain breaks, it repairs itself: every `collect` run starts the relay when none is waiting. The cron line in `collect.yml` is kept as an hourly safety net for the day GitHub's trigger works. To restart everything by hand, run the `relay` workflow once from the Actions tab. Starting it twice is harmless; extra chains merge back into one.

After every second collection, the `notify-scorer` job pushes an empty commit to the `trigger` branch of the separate scoring repository, which starts a scoring run there about every 30 minutes. Its SSH key and the repository's name are secrets of the `scorer` environment, which only the `main` branch may use.

## How a run works

About every 15 minutes the `collect` workflow runs three jobs. Each job gets a fresh virtual machine that GitHub destroys afterwards, and each has only the access it needs.

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
- **News and early signal:** Hacker News search, BleepingComputer, The Hacker News, Unit 42, Talos, watchTowr, Wiz, Rapid7, the oss-security list, CERT/CC, Zero Day Initiative, CERT-FR.
- **Linux distributions:** Red Hat, Ubuntu, Debian and Debian LTS, AlmaLinux, Amazon Linux, Arch Linux.
- **Network and infrastructure vendors:** Cisco, Fortinet, Palo Alto Networks, Kubernetes, Microsoft, PHP, NGINX, CISA advisories and CISA industrial-control advisories.

- **Public rules and exploit code:** the nuclei-templates CVE index, Exploit-DB, Metasploit module metadata, Emerging Threats Open and the SigmaHQ rule repository. Each is fetched whole once or twice a day and reduced to an identifier and a title per CVE; rule and exploit content is not kept.

Linux kernel CVEs arrive through the CVE list itself, where the kernel project publishes them. Juniper, F5, VMware and SonicWall publish no machine-readable feed; their bugs still arrive through the CVE list and the news sources.

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
state/wanted.json               CVE records to backfill, and CVEs confirmed unpublished
coverage/<kind>.json            public rules and exploits per CVE: [identifier, title, note]
coverage/recent.json            CVEs that recently gained their first rule or exploit
```

**Backfill.** The CVE source only reports records that changed since the last run, so a CVE published before the pipeline started has no record. When news or a recent KEV entry names such a CVE, the commit job marks it `pending` in `state/wanted.json` and the next CVE run fetches it once. If cvelistV5 has no such record it becomes `missing`, which downstream means the CVE is not published yet.

Every record carries `src`: the source, the URL, the fetch time and the SHA-256 of the raw document it came from. Raw documents are kept for 90 days as the `raw` artifact of each workflow run.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests use hand-written fixtures and never touch the network.

## Operations

- To fetch one source immediately, run the `collect` workflow by hand with `only` set to its id (for example `cvelist`).
- `keepalive.yml` re-enables the schedules weekly, because GitHub disables scheduled workflows in public repositories after 60 days without activity.
- Actions are pinned to commit hashes. Update the hash and the version comment together.
- A source that keeps failing shows in `state/heartbeat.json`; the private scorer turns that into an alert.
