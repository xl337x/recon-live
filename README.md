# recon-live

A live recon and attack-surface mapping engine with an interactive browser dashboard, plus an offline command-script generator. Built for authorized penetration testing engagements.

> WARNING: Authorized use only. Run this only against systems you own or have explicit written permission to test.

## What's inside

| File | What it is |
|------|------------|
| `recon-live.py` | Single-file (stdlib-only) engine that runs the recon pipeline and serves a real-time dashboard over SSE. Enter a scope in the page and watch every stage run. |
| `Recon Console.html` | Offline, self-contained HTML that generates a portable bash recon and testing script. No server, works from `file://`. |

## recon-live.py, the live dashboard

Pipeline (each stage streamed live to the browser):

```
enum > resolve > ports > probe > dirs > params > vulns > brain > intel > report
```

Features:

* Full surface map. Every enumerated host is shown with a state badge: LIVE (HTTP up), DNS (resolves, no HTTP), or DEAD (enumerated, no DNS).
* Discovery: subfinder, assetfinder and crt.sh in parallel, then dnsx (with wildcard-DNS filtering), then ProjectDiscovery httpx (status, title, tech), then katana, gau and waybackurls for parameters (scope-guarded), then feroxbuster for directories (bounded, quick wins first, tech-aware extension sets).
* Resume: every stage is recorded in `manifest.json`; re-running skips finished stages (per-host for dirs). `--fresh` redoes everything, `--fast` is a speed profile (45s ferox cap, smaller vuln queue).
* Vuln testing: confirmed-only LFI, SSTI, open-redirect, reflected-XSS and SQL injection (error-based + time-based blind, multi-DB), plus a signature-free differential probe. Tests GET params AND submits/tests HTML forms over POST (login username/password, project params) for SQLi and XSS — regardless of parameter name. Tracking params skipped, numeric-path duplicates deduped, time-based probes budget-capped.
* Access control & exposure: flags 3xx responses that still return a data body (silent-redirect / auth-bypass leak), autoindex directory listings and the unauthenticated endpoints they reveal, exposed files (.git/.env/backups/.sql/creds), and secrets/API endpoints extracted from JS.
* Port scan (`--ports`, naabu) so non-default ports are probed; subdomain-takeover sweep (subzy/nuclei); optional dalfox and sqlmap.
* Intel stage (smart, not hardcoded): nuclei `-as` (automatic template selection per detected tech) and nuclei `-dast` (fuzzing templates on discovered params). Detection logic lives in maintained YAML.
* Brain: tech-aware routing. File-upload forms go to uploadpwn, login forms are flagged, tech CVEs run via nuclei tags.
* Findings and report: structured `findings.jsonl`, auto-generated `REPORT.md` and `report.json` (also served at `/report` on the dashboard), and a per-host `hosts/<host>/` layout (ferox.json, urls.txt, params.txt).
* Auth: `--cookie` and `--header` flow to every tool and request. Adaptive User-Agent rotation and WAF or rate-limit backoff.
* Dashboard: colour-coded status table, tech badges, attack-surface score, per-host kill, rescan and nuclei actions, live filters (surface, status, text), radar pulse and row flash on discovery, and a Lists panel to dump all subs, live, params, full URLs and dirs (copy and download) at any time.

### Run

```bash
python3 recon-live.py                 # opens a scope-entry screen in the page
python3 recon-live.py example.com     # or start immediately
# then open http://127.0.0.1:8899
```

Useful flags: `--port`, `--cookie`, `--header 'Authorization: Bearer ...'`, `--time-limit 3m`,
`--fast` (speed profile), `--fresh` (ignore resume manifest), `--ferox-parallel 3`, `--wordlist <path>` (auto-falls back to dirb if SecLists is absent), `--out <dir>` (custom output dir), `--max-requests N` (global active-test budget), `--notify <webhook>` (POST on each high/crit finding), `--diff` (write `DIFF.md` vs the previous run), `--screens` (screenshot every live host, camera link in the dashboard), `--depth N` (feroxbuster recursion depth, default 2 — finds nested dirs like /dashboard/functions/), `--ports` + `--top-ports N` (naabu port scan so non-default ports are probed), `--sqli` (sqlmap on top-value params; built-in error+time-based blind SQLi and POST-form testing always run), `--uploadpwn "python3 /path/uploadpwn.py -u {url}"` with `--uploadpwn-auto` (intrusive; off by default — upload points are only reported otherwise), `--no-test` (discovery only).

## Recon Console.html

Open it in a browser (`file://` is fine). Enter a target, pick your options (speed profile, enum sources,
resolve and probe, dir-brute, parameter discovery and testing, auth), toggle Active testing and Deps install,
then Copy or Download the generated `.sh`. Runs the same pipeline offline as a script.

## Requirements

* Python 3.8 or newer.
* Recon toolchain on PATH: `subfinder`, `assetfinder`, `dnsx`, `httpx` (ProjectDiscovery), `feroxbuster`,
  `katana`, `gau`, `nuclei`. Optional: `uploadpwn`, `waybackurls`, `qsreplace`, `dalfox`, `sqlmap`, `x8`.

Self-bootstrapping: on first run the tool auto-installs any missing **go** tools (httpx, subfinder,
dnsx, katana, nuclei, gau, assetfinder, waybackurls, dalfox, subzy) — disable with `--no-autosetup`.
For a full install including the sudo/apt tools (feroxbuster, chromium, seclists) and nuclei templates,
run `python3 recon-live.py --setup` or `./setup.sh`.

> Note: ProjectDiscovery `httpx` must be resolvable (the Python `httpx` CLI shadows it). recon-live prefers `~/go/bin/httpx` automatically.

## License

For authorized security testing only. Use responsibly.
