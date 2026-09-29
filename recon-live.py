#!/usr/bin/env python3
"""
recon-live — interactive live recon dashboard (single file, stdlib only).

Usage:   python3 recon-live.py <domain> [--port 8899] [--wordlist PATH]
Then open the URL it prints (http://127.0.0.1:8899).

Pipeline: subfinder/assetfinder -> dnsx -> httpx(PD) -> feroxbuster (per host, watchdog)
          -> katana/gau parameter discovery.  Live progress + actions in the browser.
"""
import sys, os, json, time, threading, subprocess, shutil, queue, argparse, html, socket
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------- args ----------------
ap = argparse.ArgumentParser()
ap.add_argument("domain", nargs="?", default=None, help="scope (optional; if omitted, enter it in the page)")
ap.add_argument("--port", type=int, default=8899)
ap.add_argument("--wordlist", default="/usr/share/seclists/Discovery/Web-Content/common.txt")
ap.add_argument("--ferox-parallel", type=int, default=3)
ap.add_argument("--stall-secs", type=int, default=40, help="(legacy) unused; --time-limit bounds each host")
ap.add_argument("--time-limit", default=None, help="hard per-host ferox time cap (e.g. 90s, 3m)")
ap.add_argument("--no-test", dest="test", action="store_false", help="discovery only; skip active LFI/SSTI/redirect/XSS testing")
ap.add_argument("--cookie", default="", help="Cookie header value, flows to every authed tool + request")
ap.add_argument("--header", action="append", default=[], help="extra header 'Name: value' (repeatable)")
ap.add_argument("--uploadpwn", default="", help="path/command for uploadpwn (used only when auto-run is enabled)")
ap.add_argument("--uploadpwn-auto", dest="uploadpwn_auto", action="store_true",
                help="automatically run uploadpwn on detected upload forms (intrusive — OFF by default; otherwise upload points are only reported)")
ap.add_argument("--fast", action="store_true", help="speed profile: 45s ferox cap, smaller vuln queue")
ap.add_argument("--fresh", action="store_true", help="ignore manifest and rerun every stage")
ap.add_argument("--out", default=None, help="output dir (default ~/recon/<domain>/<date>)")
ap.add_argument("--max-requests", dest="max_requests", type=int, default=0,
                help="global cap on active HTTP test requests (0 = unlimited)")
ap.add_argument("--notify", default="", help="webhook URL POSTed a JSON payload on each high/crit finding")
ap.add_argument("--diff", action="store_true", help="also write DIFF.md: new hosts/findings vs the previous run of this domain")
ap.add_argument("--screens", action="store_true", help="capture a screenshot of every live host (httpx -ss, uses system chromium)")
ap.add_argument("--depth", type=int, default=2, help="feroxbuster recursion depth (1 disables recursion; default 2 finds nested dirs like /dashboard/functions/)")
ap.add_argument("--ports", action="store_true", help="port-scan resolved hosts (naabu) so httpx probes non-default ports too")
ap.add_argument("--top-ports", dest="top_ports", type=int, default=100, help="naabu top-ports count (default 100)")
ap.add_argument("--sqli", action="store_true", help="run sqlmap on the highest-value discovered params (heavy/noisy)")
ap.add_argument("--setup", action="store_true", help="install/repair ALL dependencies (go tools + apt + nuclei templates), then exit unless a domain is given")
ap.add_argument("--no-autosetup", dest="autosetup", action="store_false", help="do NOT auto-install missing go tools at startup")
ap.set_defaults(test=True, autosetup=True)
A = ap.parse_args()
A.time_limit = A.time_limit or ("45s" if A.fast else "3m")
# wordlist auto-fallback so it's correct out of the box even without SecLists installed
if not os.path.exists(A.wordlist):
    for _w in ("/usr/share/seclists/Discovery/Web-Content/common.txt",
               "/usr/share/wordlists/dirb/common.txt",
               "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"):
        if os.path.exists(_w):
            A.wordlist = _w; break
GOBIN = os.path.expanduser("~/go/bin")
# make tools resolvable no matter which shell launched us (go / pipx / cargo bin dirs)
for _d in (GOBIN, os.path.expanduser("~/.local/bin"), os.path.expanduser("~/.cargo/bin")):
    if os.path.isdir(_d) and _d not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = _d + os.pathsep + os.environ.get("PATH", "")

def tool(name, prefer_go=False):
    """Resolve a binary, preferring ~/go/bin (fixes the python-httpx shadow)."""
    g = os.path.join(GOBIN, name)
    if prefer_go and os.path.exists(g):
        return g
    return shutil.which(name) or (g if os.path.exists(g) else None)

HTTPX = tool("httpx", prefer_go=True)  # ProjectDiscovery httpx, not python httpx

# ---------------- self-bootstrap: install anything missing so the tool works out of the box ----------------
GO_TOOLS = {
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "dalfox": "github.com/hahwul/dalfox/v2@latest",
    "subzy": "github.com/PentestPad/subzy@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
}
APT_TOOLS = {"feroxbuster": "feroxbuster", "chromium": "chromium", "seclists": "seclists", "sqlmap": "sqlmap"}

def _have(name):
    return bool(shutil.which(name) or os.path.exists(os.path.join(GOBIN, name)))

def bootstrap(install=True, verbose=True, do_apt=False):
    """Install missing dependencies (go tools always; apt tools when do_apt). Re-resolves HTTPX."""
    global HTTPX
    if install and not shutil.which("go"):
        if verbose: print("[!] go not found — install golang first: sudo apt-get install -y golang-go")
    elif install:
        env = dict(os.environ, GOSUMDB="off", GOFLAGS="-mod=mod")
        for name, path in GO_TOOLS.items():
            if _have(name):
                continue
            if verbose: print(f"[+] installing {name} …", flush=True)
            r = subprocess.run(["go", "install", path], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            if verbose:
                print("    ok" if r.returncode == 0 else f"    FAILED: {(r.stderr or '').strip().splitlines()[-1:]}")
    if install and do_apt and shutil.which("apt-get"):
        for name, pkg in APT_TOOLS.items():
            if _have(name): continue
            if verbose: print(f"[+] apt-get install {pkg} (needs sudo)…", flush=True)
            subprocess.run(["sudo", "apt-get", "install", "-y", pkg])
    if install and _have("nuclei"):
        subprocess.run([shutil.which("nuclei") or os.path.join(GOBIN, "nuclei"), "-update-templates"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    HTTPX = tool("httpx", prefer_go=True)                       # re-resolve after any install
    return [n for n in list(GO_TOOLS) + list(APT_TOOLS) if not _have(n)]

# ---------------- scope (set at launch OR from the page via POST /start) ----------------
DOMAIN = ""
OUT = ""
AUTH_HEADERS = {}      # for urllib requests
HDR_ARGS = []          # repeated -H args for httpx/katana/feroxbuster

def set_scope(domain, cookie="", headers=None, uploadpwn=None, test=None, uploadpwn_auto=None):
    global DOMAIN, OUT, AUTH_HEADERS, HDR_ARGS
    DOMAIN = domain.strip().lower().lstrip("*.")
    OUT = os.path.expanduser(A.out) if A.out else os.path.expanduser(f"~/recon/{DOMAIN}/{date.today()}")
    os.makedirs(os.path.join(OUT, "hosts"), exist_ok=True)
    os.makedirs(os.path.join(OUT, "params"), exist_ok=True)
    AUTH_HEADERS = {}; HDR_ARGS = []
    if cookie:
        AUTH_HEADERS["Cookie"] = cookie; HDR_ARGS += ["-H", f"Cookie: {cookie}"]
    for _h in (headers or []):
        if ":" in _h:
            k, v = _h.split(":", 1); AUTH_HEADERS[k.strip()] = v.strip(); HDR_ARGS += ["-H", _h]
    if uploadpwn is not None: A.uploadpwn = uploadpwn
    if uploadpwn_auto is not None: A.uploadpwn_auto = uploadpwn_auto
    if test is not None: A.test = test

def _secs(s):
    s = str(s).strip().lower()
    try:
        if s.endswith("m"): return int(float(s[:-1]) * 60)
        if s.endswith("h"): return int(float(s[:-1]) * 3600)
        if s.endswith("s"): return int(float(s[:-1]))
        return int(float(s))
    except Exception:
        return 180

STAGE_NAMES = ["enum", "resolve", "ports", "probe", "dirs", "params", "vulns", "brain", "intel", "report"]
COUNT_KEYS = ["subs", "resolved", "live", "dirs", "params", "findings"]

# ---------------- event bus ----------------
subs_q = []            # SSE subscriber queues
buslock = threading.Lock()
STATE = {
    "domain": "", "out": "", "started": time.time(), "phase": "idle",
    "stages": {s: {"state": "pending", "pct": 0} for s in STAGE_NAMES},
    "counts": {k: 0 for k in COUNT_KEYS},
    "hosts": {},        # host -> {url,status,codes,title,tech,state,dirs,params,elapsed}
    "feed": [],         # recent findings
    "running": True,
}

def reset_state():
    STATE["domain"] = DOMAIN; STATE["out"] = OUT; STATE["started"] = time.time(); STATE["phase"] = "running"
    STATE["stages"] = {s: {"state": "pending", "pct": 0} for s in STAGE_NAMES}
    STATE["counts"] = {k: 0 for k in COUNT_KEYS}
    STATE["hosts"] = {}; STATE["feed"] = []; STATE["running"] = True

def _persist_state():
    """Periodically dump STATE to disk so a crash doesn't lose the dashboard view."""
    while STATE.get("running"):
        try: json.dump(STATE, open(os.path.join(OUT, "state.json"), "w"))
        except Exception: pass
        time.sleep(5)
    try: json.dump(STATE, open(os.path.join(OUT, "state.json"), "w"))
    except Exception: pass

def emit(ev):
    ev.setdefault("ts", time.time())
    with buslock:
        _apply(ev)
        dead = []
        for q in subs_q:
            try:
                q.put_nowait(ev)
            except Exception:
                dead.append(q)
        for q in dead:
            subs_q.remove(q)

def _apply(ev):
    t = ev.get("type")
    if t == "phase":
        STATE["phase"] = ev["phase"]
        if ev.get("domain"): STATE["domain"] = ev["domain"]
    elif t == "stage":
        STATE["stages"][ev["stage"]] = {"state": ev.get("state", "run"), "pct": ev.get("pct", STATE["stages"].get(ev["stage"], {}).get("pct", 0))}
    elif t == "count":
        STATE["counts"][ev["key"]] = ev["value"]
    elif t == "host":
        h = STATE["hosts"].setdefault(ev["host"], {"host": ev["host"], "dirs": [], "params": []})
        for k in ("url", "status", "codes", "title", "tech", "map", "shot"):
            if k in ev:
                h[k] = ev[k]
    elif t == "hoststate":
        h = STATE["hosts"].setdefault(ev["host"], {"host": ev["host"], "dirs": [], "params": []})
        h["state"] = ev["state"]
        if "elapsed" in ev: h["elapsed"] = ev["elapsed"]
        if "pct" in ev: h["pct"] = ev["pct"]
    elif t == "hostscore":
        h = STATE["hosts"].setdefault(ev["host"], {"host": ev["host"], "dirs": [], "params": []})
        h["score"] = ev["score"]
    elif t == "dir":
        h = STATE["hosts"].setdefault(ev["host"], {"host": ev["host"], "dirs": [], "params": []})
        h["dirs"].append({"path": ev["path"], "code": ev["code"], "size": ev.get("size")})
    elif t == "param":
        h = STATE["hosts"].setdefault(ev["host"], {"host": ev["host"], "dirs": [], "params": []})
        if ev["name"] not in h["params"]:
            h["params"].append(ev["name"])
    elif t == "feed":
        STATE["feed"].append(ev)
        STATE["feed"] = STATE["feed"][-200:]

def feed(msg, sev="info", host=None):
    emit({"type": "feed", "msg": msg, "sev": sev, "host": host})

def bump(key, n=1):
    STATE["counts"][key] = STATE["counts"].get(key, 0) + n
    emit({"type": "count", "key": key, "value": STATE["counts"][key]})

# ---------------- manifest (resume) + structured findings ----------------
def manifest_load():
    try: return json.load(open(os.path.join(OUT, "manifest.json")))
    except Exception: return {}

def manifest_save(m):
    m["domain"] = DOMAIN; m["updated"] = time.time()
    json.dump(m, open(os.path.join(OUT, "manifest.json"), "w"), indent=2)

def mark_stage(name, **extra):
    m = manifest_load(); m.setdefault("stages", {})[name] = {"done": True, "ts": time.time(), **extra}; manifest_save(m)

def stage_done(name):
    if A.fresh: return False
    return bool(manifest_load().get("stages", {}).get(name, {}).get("done"))

def mark_dir_host(host):
    m = manifest_load(); st = m.setdefault("stages", {}).setdefault("dirs", {"done": False}); st.setdefault("hosts", {})[host] = True; manifest_save(m)

def dir_host_done(host):
    if A.fresh: return False
    return bool(manifest_load().get("stages", {}).get("dirs", {}).get("hosts", {}).get(host))

def finding(sev, kind, host, msg, url=""):
    rec = {"ts": time.time(), "sev": sev, "kind": kind, "host": host, "msg": msg, "url": url}
    try:
        with open(os.path.join(OUT, "findings.jsonl"), "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception: pass
    emit({"type": "finding", "sev": sev, "host": host})
    feed(msg, sev, host); bump("findings")
    if sev in ("crit", "high"):
        threading.Thread(target=_notify, args=(rec,), daemon=True).start()

# ---------------- subprocess helpers ----------------
PROCS = {}   # host -> Popen (for kill/rescan)

def stream(cmd, on_line, key=None):
    try:
        p = subprocess.Popen(cmd, cwd=OUT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except FileNotFoundError:
        feed(f"missing tool: {cmd[0]}", "high"); return None
    if key:
        PROCS[key] = p
    for line in p.stdout:
        on_line(line.rstrip("\n"))
    p.wait()
    return p

# ---------------- pipeline stages ----------------
def _crtsh(domain):
    out = []
    try:
        u = "https://crt.sh/?q=%25." + urllib.parse.quote(domain) + "&output=json"
        req = urllib.request.Request(u, headers={"User-Agent": random.choice(UA_POOL)})
        with urllib.request.urlopen(req, timeout=25, context=_CTX) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        for row in data:
            for n in str(row.get("name_value", "")).splitlines():
                out.append(n)
    except Exception: pass
    return out

def stage_enum():
    emit({"type": "stage", "stage": "enum", "state": "run"})
    feed("enumerating subdomains…")
    found = set(); flock = threading.Lock()
    def add(l):
        l = l.strip().lower().strip(".")
        if l.startswith("*."): l = l[2:]
        l = "".join(c for c in l if c.isprintable())
        while ".." in l: l = l.replace("..", ".")
        if l and (l == DOMAIN or l.endswith("." + DOMAIN)):
            with flock:
                if l not in found:
                    found.add(l); bump("subs")
    def crt():
        names = _crtsh(DOMAIN)
        for n in names: add(n)
        if names: feed(f"crt.sh: {len(names)} names", "info")
    ths = [threading.Thread(target=crt, daemon=True)]
    if shutil.which("subfinder"): ths.append(threading.Thread(target=stream, args=(["subfinder", "-d", DOMAIN, "-all", "-silent"], add), daemon=True))
    if shutil.which("assetfinder"): ths.append(threading.Thread(target=stream, args=(["assetfinder", "--subs-only", DOMAIN], add), daemon=True))
    for t in ths: t.start()
    for t in ths: t.join()
    # fold www duplicates
    clean = sorted(h for h in found if not (h.startswith("www.") and h[4:] in found))
    open(os.path.join(OUT, "subs.txt"), "w").write("\n".join(clean) + "\n")
    for h in clean:                                   # map EVERY name (offline until proven otherwise)
        emit({"type": "host", "host": h, "map": "offline"})
    mark_stage("enum", count=len(clean))
    emit({"type": "stage", "stage": "enum", "state": "done", "pct": 100})
    feed(f"found {len(clean)} in-scope names (full surface map)", "good")
    return clean

def _wildcard_ips():
    ips = set()
    for _ in range(2):
        junk = f"rl{random.randint(100000,999999)}.{DOMAIN}"
        try:
            for res in socket.getaddrinfo(junk, None):
                ips.add(res[4][0])
        except Exception: pass
    return ips

def stage_resolve(subs):
    emit({"type": "stage", "stage": "resolve", "state": "run"})
    feed("resolving DNS (dnsx)…")
    res = []
    def _res(l):
        h = l.strip()
        if h:
            res.append(h); bump("resolved")
            emit({"type": "host", "host": h, "map": "resolved"})   # DNS ok (may still have no HTTP)
    wild = _wildcard_ips()
    if shutil.which("dnsx"):
        if wild:
            feed(f"⚠ wildcard DNS detected ({', '.join(sorted(wild))}) — filtering noise", "med")
            cur = {}
            def _resw(l):
                parts = l.strip().split()            # dnsx -a -resp: host [ip] ([ip2] …)
                if not parts: return
                h = parts[0].lower()
                ips = [x.strip("[]") for x in parts[1:] if x.startswith("[")]
                cur.setdefault(h, set()).update(ips)
            stream(["dnsx", "-l", os.path.join(OUT, "subs.txt"), "-a", "-resp", "-silent", "-retry", "2"], _resw)
            for h, ips in sorted(cur.items()):
                if ips and ips <= wild: continue     # every A record is the wildcard -> noise
                res.append(h); bump("resolved")
                emit({"type": "host", "host": h, "map": "resolved"})
        else:
            stream(["dnsx", "-l", os.path.join(OUT, "subs.txt"), "-silent", "-retry", "2"], _res)
    else:
        res = subs; feed("dnsx missing — skipping resolve", "med")
    res = sorted(set(res))
    open(os.path.join(OUT, "resolved.txt"), "w").write("\n".join(res) + "\n")
    mark_stage("resolve", count=len(res))
    emit({"type": "stage", "stage": "resolve", "state": "done", "pct": 100})
    feed(f"{len(res)} names resolve", "good")
    return res

def stage_ports(resolved):
    """naabu port scan so httpx later probes non-default ports (8080/8443/…), not just 80/443."""
    emit({"type": "stage", "stage": "ports", "state": "run"})
    if not (A.ports and shutil.which("naabu")):
        if A.ports: feed("naabu missing — skipping port scan (probe uses 80/443 only)", "med")
        emit({"type": "stage", "stage": "ports", "state": "done", "pct": 0}); return resolved
    feed(f"port-scanning {len(resolved)} hosts (naabu top-{A.top_ports})…")
    out = []
    def on(l):
        l = l.strip()
        if l: out.append(l)
    stream(["naabu", "-l", os.path.join(OUT, "resolved.txt"), "-top-ports", str(A.top_ports),
            "-s", "c", "-silent", "-retries", "1"], on)
    out = sorted(set(out)) or resolved
    open(os.path.join(OUT, "ports.txt"), "w").write("\n".join(out) + "\n")
    mark_stage("ports", count=len(out))
    emit({"type": "stage", "stage": "ports", "state": "done", "pct": 100})
    feed(f"{len(out)} host:port endpoints to probe", "good")
    return out

def stage_probe(resolved):
    emit({"type": "stage", "stage": "probe", "state": "run"})
    feed("probing live hosts (httpx)…")
    if not HTTPX:
        feed("ProjectDiscovery httpx not found in ~/go/bin — install it", "high")
        emit({"type": "stage", "stage": "probe", "state": "done"}); return []
    pin = os.path.join(OUT, "ports.txt")                          # probe scanned ports if we have them
    pin = pin if (os.path.exists(pin) and os.path.getsize(pin)) else os.path.join(OUT, "resolved.txt")
    live = []
    def on(l):
        try:
            o = json.loads(l)
        except Exception:
            return
        host = o.get("input") or o.get("host") or ""
        url = o.get("url", "")
        sc = o.get("status_code")
        chain = o.get("chain_status_codes") or ([o.get("status_code")] if o.get("status_code") else [])
        codes = ",".join(str(c) for c in chain) if chain else str(sc)
        tech = o.get("tech") or o.get("technologies") or []
        title = o.get("title", "") or ""
        emit({"type": "host", "host": host, "url": url, "status": sc, "codes": codes, "title": title, "tech": tech, "map": "live"})
        if url:
            live.append(url); bump("live")
    stream([HTTPX, "-l", pin, "-json", "-silent",
            "-sc", "-title", "-td", "-fr", "-nc"] + HDR_ARGS, on)
    open(os.path.join(OUT, "live.txt"), "w").write("\n".join(sorted(set(live))) + "\n")
    mark_stage("probe", count=len(live))
    emit({"type": "stage", "stage": "probe", "state": "done", "pct": 100})
    feed(f"{len(live)} live hosts", "good")
    return sorted(set(live))

def _safe(url):
    # strip scheme + ALL whitespace so a stray newline/blob can never build a monster filename,
    # then map unsafe chars to _ and hard-cap the length (defensive against bad inputs).
    s = url.replace("https://", "").replace("http://", "")
    s = "".join(c if c.isalnum() or c in ".-" else "_" for c in s if not c.isspace())
    return s[:120] or "host"

def host_dir(host):
    d = os.path.join(OUT, "hosts", _safe(host)); os.makedirs(d, exist_ok=True); return d

TECH_EXT = [
    (("php", "wordpress", "joomla", "drupal", "laravel", "magento"), "php,php.bak,txt,html"),
    (("asp.net", "aspnet", "iis", "microsoft"), "asp,aspx,ashx,config,txt"),
    (("java", "tomcat", "spring", "jenkins"), "jsp,do,action,xml,properties"),
    (("node", "express", "next.js", "nuxt"), "js,json,txt"),
    (("python", "django", "flask"), "json,txt,py"),
]
DEFAULT_EXT = "php,html,txt,json,bak"
def _exts_for(host):
    tech = " ".join(STATE["hosts"].get(host, {}).get("tech", [])).lower()
    for keys, exts in TECH_EXT:
        if any(k in tech for k in keys): return exts
    return DEFAULT_EXT

def ferox_host(url, done_ref):
    fero = shutil.which("feroxbuster")
    if not fero:
        feed("feroxbuster missing", "high"); return
    url = (url.strip().splitlines() or [url])[0].strip()   # one clean URL only — never a joined blob
    if not url:
        return
    host = url.replace("https://", "").replace("http://", "").split("/")[0]
    exts = _exts_for(host)
    outp = os.path.join(host_dir(host), "ferox.json")
    depth = max(1, A.depth)
    rec = ["-n"] if depth <= 1 else ["-d", str(depth), "--extract-links"]  # recurse + scrape links (autoindex → nested files)
    cmd = [fero, "-u", url, "-w", A.wordlist, "-x", exts, "-t", "40",
           "-C", "404", "-k", "-T", "5", "--time-limit", A.time_limit, "--json", "--silent",
           "--rate-limit", "150", "-o", outp] + rec + HDR_ARGS
    tl = _secs(A.time_limit)                      # hard per-host cap, in seconds
    emit({"type": "hoststate", "host": host, "state": "scanning", "pct": 0})
    feed(f"ferox → {host} (exts: {exts})", "info", host)
    t0 = time.time(); last = [time.time()]; hits = [0]
    try:
        p = subprocess.Popen(cmd, cwd=OUT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    except Exception as e:
        feed(f"ferox failed on {host}: {e}", "high"); return
    PROCS[host] = p
    def reader():
        for line in p.stdout:
            try:
                o = json.loads(line)
            except Exception:
                continue
            if o.get("type") == "response":
                code = o.get("status"); path = o.get("url", "")
                rel = path.split(host, 1)[-1] if host in path else path
                emit({"type": "dir", "host": host, "path": rel, "code": code, "size": o.get("content_length")})
                bump("dirs"); last[0] = time.time(); hits[0] += 1   # stream every hit immediately
                if code in (200, 401, 403, 500):
                    feed(f"{rel} [{code}] on {host}", "good" if code == 200 else "med", host)
    rt = threading.Thread(target=reader, daemon=True); rt.start()
    # time-based per-host progress bar (feroxbuster's --time-limit is the real bound; no dir-idle false kills)
    while p.poll() is None:
        time.sleep(2)
        el = time.time() - t0
        pct = min(99, int(el / tl * 100)) if tl else 0
        emit({"type": "hoststate", "host": host, "state": "scanning", "elapsed": int(el), "pct": pct})
        if el > tl + 45:                          # safety net if --time-limit is ignored
            p.terminate()
            try: p.wait(timeout=5)
            except Exception: p.kill()
            emit({"type": "hoststate", "host": host, "state": "stalled", "pct": 100})
            feed(f"⚠ {host} hit time cap — moved on ({hits[0]} hits)", "med", host)
            mark_dir_host(host); PROCS.pop(host, None); done_ref(); return
    rt.join(timeout=3)
    PROCS.pop(host, None)
    st = STATE["hosts"].get(host, {}).get("state")
    if st != "killed":
        emit({"type": "hoststate", "host": host, "state": "done", "elapsed": int(time.time() - t0)})
        feed(f"✓ {host} dir-brute done ({hits[0]} hits)", "good", host)
    mark_dir_host(host)
    done_ref()

def stage_dirs(live):
    emit({"type": "stage", "stage": "dirs", "state": "run"})
    feed(f"directory brute on {len(live)} hosts ({A.ferox_parallel} parallel)…")
    total = max(1, len(live)); done = [0]
    dlock = threading.Lock()
    def done_ref():
        with dlock:
            done[0] += 1
            emit({"type": "stage", "stage": "dirs", "state": "run", "pct": int(done[0] * 100 / total)})
    # scan interesting hosts first (2xx/3xx before 4xx/5xx) so meaningful hits appear immediately
    def _rank(u):
        h = u.replace("https://", "").replace("http://", "").split("/")[0]
        try: c = int(str(STATE["hosts"].get(h, {}).get("status") or 999).split(",")[-1])
        except Exception: c = 999
        return (0 if 200 <= c < 400 else 1, c)
    live = sorted(live, key=_rank)
    skipped = [u for u in live if dir_host_done(u.replace("https://", "").replace("http://", "").split("/")[0])]
    if skipped:
        feed(f"↻ dirs: {len(skipped)} host(s) already brute-forced — skipping (--fresh to redo)", "info")
    for u in skipped:
        h = u.replace("https://", "").replace("http://", "").split("/")[0]
        emit({"type": "hoststate", "host": h, "state": "done"})
        done_ref()
    live = [u for u in live if u not in skipped]
    sem = threading.Semaphore(A.ferox_parallel)
    threads = []
    def worker(u):
        with sem:
            if not STATE["running"]: return
            ferox_host(u, done_ref)
    for u in live:
        t = threading.Thread(target=worker, args=(u,), daemon=True); t.start(); threads.append(t)
    for t in threads: t.join()
    mark_stage("dirs")
    emit({"type": "stage", "stage": "dirs", "state": "done", "pct": 100})
    feed("directory brute complete", "good")

def stage_params(live):
    emit({"type": "stage", "stage": "params", "state": "run"})
    feed("discovering parameters (katana/gau/waybackurls)…")
    urls = set(); params = set(); per_host = {}; js = set()
    def add_url(l):
        l = l.strip()
        try: netloc = urllib.parse.urlsplit(l).netloc.lower()
        except Exception: return
        if netloc and netloc != DOMAIN and not netloc.endswith("." + DOMAIN): return   # scope guard
        if l.split("?", 1)[0].lower().endswith(".js"):
            js.add(l); return
        if "?" not in l or "=" not in l: return
        urls.add(l)
        d = per_host.setdefault(netloc, {"urls": set(), "params": set()})
        d["urls"].add(l)
        for m in _re.findall(r"[?&]([a-zA-Z0-9_.-]+)=", l):
            d["params"].add(m)
            if m not in params:
                params.add(m); bump("params")
                emit({"type": "param", "host": netloc, "name": m})
    if shutil.which("katana"):
        stream(["katana", "-list", os.path.join(OUT, "live.txt"), "-jc", "-d", "2", "-silent"] + HDR_ARGS, add_url)
    if shutil.which("gau"):
        stream(["gau", DOMAIN, "--subs"], add_url)
    if shutil.which("waybackurls"):
        stream(["waybackurls", DOMAIN], add_url)
    open(os.path.join(OUT, "params", "urls.txt"), "w").write("\n".join(sorted(urls)) + "\n")
    open(os.path.join(OUT, "params", "params.txt"), "w").write("\n".join(sorted(params)) + "\n")
    open(os.path.join(OUT, "params", "js.txt"), "w").write("\n".join(sorted(js)) + "\n")
    for host, d in per_host.items():
        hd = host_dir(host)
        open(os.path.join(hd, "urls.txt"), "w").write("\n".join(sorted(d["urls"])) + "\n")
        open(os.path.join(hd, "params.txt"), "w").write("\n".join(sorted(d["params"])) + "\n")
    mark_stage("params", count=len(params))
    emit({"type": "stage", "stage": "params", "state": "done", "pct": 100})
    feed(f"{len(params)} unique parameters discovered", "good")

# ---------------- active vulnerability testing (urllib, no external deps) ----------------
import urllib.request, urllib.parse, urllib.error, ssl, re as _re, random
_CTX = ssl.create_default_context(); _CTX.check_hostname = False; _CTX.verify_mode = ssl.CERT_NONE
class _NR(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None
_NOREDIR = urllib.request.build_opener(_NR(), urllib.request.HTTPSHandler(context=_CTX))

# global request budget for active testing (bounds total volume when --max-requests is set)
_REQN = [0]; _reqlock = threading.Lock(); _BUDGET_WARNED = [False]
def _budget_ok():
    if not A.max_requests: return True
    with _reqlock:
        if _REQN[0] >= A.max_requests:
            if not _BUDGET_WARNED[0]:
                _BUDGET_WARNED[0] = True
                feed(f"⚠ request budget reached ({A.max_requests}) — pausing further active probes", "med")
            return False
        _REQN[0] += 1; return True

def _notify(rec):
    """POST a finding to the configured webhook (fire-and-forget)."""
    if not A.notify: return
    try:
        text = f"[{rec.get('sev','').upper()}] {rec.get('kind','')} on {rec.get('host','')}: {rec.get('msg','')}"
        payload = json.dumps({"text": text, "domain": DOMAIN, **rec}).encode()
        req = urllib.request.Request(A.notify, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=8, context=_CTX)
    except Exception: pass

# adaptive brain: rotate UAs, detect WAF/rate-limit, back off automatically
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]
WAF = {"tripped": False, "hits": 0, "delay": 0.0}
def _waf_check(code, hdrs):
    fp = (str(hdrs.get("Server", "")) + str(hdrs.get("X-Powered-By", "")) + str(hdrs.get("cf-ray", ""))).lower()
    waffy = any(w in fp for w in ("cloudflare", "akamai", "sucuri", "incapsula", "imperva", "f5", "awselb", "mod_security"))
    if code in (403, 429, 503) or (code == 406):
        WAF["hits"] += 1
        if code in (429, 503) or WAF["hits"] >= 8:
            WAF["delay"] = min(WAF["delay"] + 0.5, 2.5)
            if not WAF["tripped"]:
                WAF["tripped"] = True
                feed(f"⚠ WAF/rate-limit signals ({code}{', ' + fp if waffy else ''}) — throttling + rotating UA", "med")

LFI_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//....//....//etc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "../../../../../../proc/self/environ",
    "php://filter/convert.base64-encode/resource=index.php",
]
LFI_MARKERS = [b"root:x:0:0", b"daemon:x:", b"/bin/bash", b"DOCUMENT_ROOT=", b"HTTP_USER_AGENT=", b"PD9waHA"]
LFI_RE = _re.compile(rb"root:[^:\n]*:0:0:")
SSTI_TOKEN = "recon7x7"; SSTI_PAYLOAD = "recon{{7*7}}"; SSTI_HIT = b"recon49"
XSS_PAYLOAD = "recon<b7>x"; XSS_HIT = b"recon<b7>x"

TRACK_PARAMS = {"utm_source","utm_medium","utm_campaign","utm_term","utm_content","gclid","fbclid","mc_cid","mc_eid","ref","_ga"}
def _norm_path(url):
    u = urllib.parse.urlsplit(url)
    return (u.scheme, u.netloc, _re.sub(r"/\d+(?=/|$)", "/{n}", u.path))

def _get(url, opener=None, timeout=8):
    if not _budget_ok():
        return None, {}, b""
    if WAF["delay"]:
        time.sleep(WAF["delay"] + random.uniform(0, 0.3))   # backoff + jitter when throttled
    hdrs = {"User-Agent": random.choice(UA_POOL)}; hdrs.update(AUTH_HEADERS)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        r = opener.open(req, timeout=timeout) if opener else urllib.request.urlopen(req, timeout=timeout, context=_CTX)
        with r:
            return getattr(r, "status", None), dict(r.headers), r.read(300000)
    except urllib.error.HTTPError as e:
        hd = dict(e.headers or {}); _waf_check(e.code, hd)
        try: body = e.read(300000)
        except Exception: body = b""
        return e.code, hd, body
    except Exception:
        return None, {}, b""

def _inject(url, param, value):
    u = urllib.parse.urlsplit(url); parts = []
    for kv in u.query.split("&"):
        if not kv: continue
        k = kv.split("=", 1)[0]
        parts.append(f"{k}={value}" if k == param else kv)
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, "&".join(parts), ""))

ERR_SIGS = [b"sql syntax", b"mysql_", b"ora-0", b"odbc", b"sqlite", b"psql", b"syntax error",
            b"unterminated", b"unexpected token", b"stack trace", b"traceback (most recent",
            b"exception in thread", b"java.lang.", b"system.web", b"fatal error", b"warning: "]
def anomaly_probe(url, param, host):
    """Signature-free differential: mutate the param and infer 'injectable/anomalous' from
    how the response CHANGES vs a benign baseline — not a fixed payload-per-bug."""
    b_sc, _, base = _get(_inject(url, param, "reconBASELINE1"))
    if base is None: return
    base_l = len(base); base_has_err = any(e in base.lower() for e in ERR_SIGS)
    for probe, label in (("'\"`\\", "quote/backslash"), ("{{7*7}}", "template"), ("<x>", "markup"), ("`;id;`", "cmd/os")):
        sc, _, body = _get(_inject(url, param, urllib.parse.quote(probe)))
        if body is None: continue
        bl = body.lower()
        # newly-appearing error/stack signature = strong injectable signal
        if not base_has_err and any(e in bl for e in ERR_SIGS):
            finding("med", "anomaly", host, f"⚑ anomalous error surfaced — {param} via {label} (possible injection) — {url[:70]}")
            return
        # large response-size swing on a mutated value = worth manual review
        if base_l and abs(len(body) - base_l) > max(400, base_l * 0.5) and sc == b_sc:
            finding("low", "anomaly", host, f"⚑ response diverges on {param} via {label} (Δ{len(body)-base_l}b) — review — {url[:60]}")
            return

def _redirects_to(loc, host):
    """True only if a Location header's TARGET host is exactly `host` (not a query echo)."""
    if not loc: return False
    l = loc.strip().lower()
    for pre in ("https://", "http://", "//"):
        if l.startswith(pre):
            rest = l[len(pre):]
            return rest == host or rest[:len(host) + 1] in (host + "/", host + ":", host + "?", host + "#")
    return False

AUTOINDEX_RE = _re.compile(rb"<title>\s*Index of\s*/|<h1>\s*Index of\s*/|Directory listing for", _re.I)
HREF_RE = _re.compile(rb'href=["\']([^"\'>]+)["\']', _re.I)
def _looks_dataish(body):
    """Heuristic: does this body carry real data (tables/records/currency/JSON rows)?"""
    if not body or len(body) < 1200: return False
    b = body.lower()
    hits = sum(1 for m in (b"<table", b"&euro;", b"addrows", b'"zusammenfassung', b'":"', b'","',
                           b"<tr", b"phpsessid", b"<td") if m in b)
    return hits >= 2

def exposure_checks(url, host):
    """Catch broken access control the redirect-follower is blind to:
    (1) a 3xx that STILL returns a data body, (2) autoindex listings + the
    unauthenticated endpoints they reveal. Pure urllib, no-follow."""
    sc, hd, body = _get(url, opener=_NOREDIR, timeout=10)
    # (1) redirect that still ships a real body = classic silent-redirect / auth-bypass leak
    if sc in (301, 302, 303, 307, 308) and _looks_dataish(body):
        finding("crit", "access-control", host,
                f"‼ {sc} redirect still returns a {len(body)}b data body (auth-bypass / silent-redirect leak) — {url}", url)
    # (2) directory listing / autoindex → flag, then harvest and probe the listed files unauthenticated
    if body and AUTOINDEX_RE.search(body):
        finding("high", "dir-listing", host, f"📂 directory listing (autoindex) exposed — {url}", url)
        base = url if url.endswith("/") else url.rsplit("/", 1)[0] + "/"
        probed = 0
        for m in HREF_RE.findall(body):
            name = m.decode("utf-8", "replace").strip()
            if not name or name in ("../", "/", "./") or name.startswith(("?", "#", "mailto:")) or "://" in name:
                continue
            child = urllib.parse.urljoin(base, name)
            csc, _, cbody = _get(child, opener=_NOREDIR, timeout=8)
            if csc in (200, 301, 302) and _looks_dataish(cbody):
                finding("crit", "unauth-data", host,
                        f"‼ unauthenticated data at {child} ({len(cbody)}b, {csc}) — no cookie/auth needed", child)
            probed += 1
            if probed >= 25: break

SENSITIVE_PATHS = [
    ("/.git/HEAD", b"ref:"), ("/.git/config", b"[core]"), ("/.env", b"="),
    ("/.svn/entries", b""), ("/.DS_Store", b"Bud1"), ("/config.php.bak", b"<?php"),
    ("/wp-config.php.bak", b"DB_"), ("/backup.zip", b"PK"), ("/backup.tar.gz", b"\x1f\x8b"),
    ("/db.sql", b""), ("/dump.sql", b""), ("/.htpasswd", b":"), ("/phpinfo.php", b"phpinfo()"),
    ("/server-status", b"Apache Server Status"), ("/.aws/credentials", b"aws_"),
    ("/composer.json", b'"require"'), ("/package.json", b'"dependencies"'), ("/.npmrc", b"_authToken"),
]
def check_exposed_files(url, host):
    """Targeted probe for high-severity exposed files, independent of the ferox wordlist."""
    base = url.rstrip("/")
    if "://" not in base: base = "https://" + base
    root = urllib.parse.urlunsplit(urllib.parse.urlsplit(base)[:2] + ("", "", ""))
    for path, sig in SENSITIVE_PATHS:
        sc, hd, body = _get(root + path, opener=_NOREDIR, timeout=7)
        if sc == 200 and body and (not sig or sig in body[:64] or sig in body):
            sev = "crit" if any(k in path for k in (".git", ".env", ".aws", "config", "backup", ".sql", "dump", "htpasswd", "npmrc")) else "high"
            finding(sev, "exposed-file", host, f"🔓 exposed {path} ({len(body)}b) — {root+path}", root + path)

SECRET_RE = [
    (_re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (_re.compile(rb"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (_re.compile(rb"gh[pousr]_[0-9A-Za-z]{36,}"), "GitHub token"),
    (_re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}"), "Slack token"),
    (_re.compile(rb"sk_live_[0-9a-zA-Z]{24,}"), "Stripe secret key"),
    (_re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "private key"),
    (_re.compile(rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "JWT"),
]
JS_ENDPOINT_RE = _re.compile(rb'["\'`](/(?:api|v\d|rest|graphql|admin|internal)[/a-zA-Z0-9_\-.]{2,})["\'`]')
def js_recon(host):
    """Fetch this host's JS files, extract API endpoints and leaked secrets."""
    try:
        jsurls = [l.strip() for l in open(os.path.join(OUT, "params", "js.txt"))
                  if l.strip() and urllib.parse.urlsplit(l).netloc == host]
    except Exception:
        jsurls = []
    eps = set()
    for u in jsurls[:20]:                                    # bound per host
        sc, hd, body = _get(u, timeout=8)
        if not body: continue
        for rx, label in SECRET_RE:
            if rx.search(body):
                finding("crit", "secret", host, f"🔑 {label} leaked in JS — {u}", u)
        for m in JS_ENDPOINT_RE.findall(body):
            eps.add(m.decode("utf-8", "replace"))
    if eps:
        hd = host_dir(host)
        open(os.path.join(hd, "js_endpoints.txt"), "w").write("\n".join(sorted(eps)) + "\n")
        feed(f"🧩 {len(eps)} endpoints extracted from JS on {host}", "info", host)

def _endpoint_score(url):
    """Cheap attack-surface score from data already gathered (params/dirs/status) —
    used to order the vuln queue so the best endpoints get tested before the cap bites."""
    h = urllib.parse.urlsplit(url).netloc
    hd = STATE["hosts"].get(h, {})
    s = len(hd.get("params", [])) * 2 + len(hd.get("dirs", []))
    for d in hd.get("dirs", []):
        if INTERESTING_PATH.search(d.get("path", "")): s += 3
    try:
        code = int(str(hd.get("status") or 0).split(",")[-1])
        if code in (200, 401, 403): s += 2
    except Exception: pass
    return s

def run_screens():
    """Best-effort screenshots of every live host via httpx -ss (system chromium)."""
    if not A.screens: return
    live = os.path.join(OUT, "live.txt")
    if not (HTTPX and os.path.exists(live) and os.path.getsize(live)): return
    chrome = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    sd = os.path.join(OUT, "screens"); os.makedirs(sd, exist_ok=True)
    feed("📸 capturing screenshots of live hosts…")
    cmd = [HTTPX, "-l", live, "-ss", "-srd", sd, "-json", "-silent", "-nc"] + \
          (["-system-chrome"] if chrome else []) + HDR_ARGS
    def on(l):
        try: o = json.loads(l)
        except Exception: return
        sp = o.get("screenshot_path") or ""
        host = _host_of(o.get("url") or o.get("input") or "")
        if sp and host:
            try: rel = os.path.relpath(sp, OUT)
            except Exception: rel = sp
            emit({"type": "host", "host": host, "shot": rel})
    stream(cmd, on, key="screens")
    feed("📸 screenshots complete", "good")

def stage_vulns():
    emit({"type": "stage", "stage": "vulns", "state": "run"})
    feed("active testing discovered params (LFI/SSTI/redirect/reflection)…")
    try:
        urls = [l.strip() for l in open(os.path.join(OUT, "params", "urls.txt")) if "?" in l and "=" in l]
    except Exception:
        urls = []
    seen = set(); tasks = []; skipped = 0
    for url in urls:
        u = urllib.parse.urlsplit(url)
        for kv in u.query.split("&"):
            if "=" not in kv: continue
            k = kv.split("=", 1)[0]
            if k.lower() in TRACK_PARAMS: skipped += 1; continue
            key = (_norm_path(url), k)
            if key in seen: skipped += 1; continue
            seen.add(key); tasks.append((url, k))
    tasks.sort(key=lambda t: -_endpoint_score(t[0]))   # test the juiciest hosts first
    cap = 80 if A.fast else 250              # bound the request volume
    skipped += max(0, len(tasks) - cap)
    tasks = tasks[:cap]
    feed(f"testing {len(tasks)} unique endpoint/param combos, highest-value first ({skipped} deduped/skipped)…")
    sem = threading.Semaphore(8)
    def test(url, param):
        with sem:
            if not STATE["running"]: return
            host = urllib.parse.urlsplit(url).netloc
            # 1) LFI / path traversal
            for pl in LFI_PAYLOADS:
                t = _inject(url, param, pl)
                sc, hd, body = _get(t)
                if body and (any(m in body for m in LFI_MARKERS) or LFI_RE.search(body)):
                    finding("crit", "lfi", host, f"‼ LFI/traversal — {param} → {t}", t); break
            # 2) SSTI
            t = _inject(url, param, urllib.parse.quote(SSTI_PAYLOAD))
            sc, hd, body = _get(t)
            if SSTI_HIT in (body or b""):
                finding("crit", "ssti", host, f"‼ SSTI (7*7=49) — {param} → {t}", t)
            # 3) reflected value (XSS candidate)
            t = _inject(url, param, urllib.parse.quote(XSS_PAYLOAD))
            sc, hd, body = _get(t)
            if XSS_HIT in (body or b""):
                finding("high", "xss", host, f"★ reflected unescaped — {param} (XSS candidate) → {t}", t)
            # 4) open redirect — CONFIRMED only: real 3xx whose Location TARGET is our host
            #    (not a substring match — that flags http->https canonical redirects that
            #     merely echo the query string, i.e. false positives)
            t = _inject(url, param, "https://recon.example/")
            sc, hd, body = _get(t, opener=_NOREDIR)
            loc = (hd.get("Location") or hd.get("location") or "").strip()
            if sc in (301, 302, 303, 307, 308) and _redirects_to(loc, "recon.example"):
                finding("high", "open-redirect", host, f"↪ open redirect CONFIRMED — {param} -> {loc[:80]}")
            # 5) behavioral / differential — signature-free anomaly (no fixed payload per bug)
            anomaly_probe(url, param, host)
    th = []
    for (url, param) in tasks:
        x = threading.Thread(target=test, args=(url, param), daemon=True); x.start(); th.append(x)
    for x in th: x.join()
    mark_stage("vulns", tasks=len(tasks))
    emit({"type": "stage", "stage": "vulns", "state": "done", "pct": 100})
    n = STATE["counts"].get("findings", 0)
    feed(f"active testing complete — {n} finding(s)", "good" if n == 0 else "crit")

# ---------------- the "brain": signal -> test routing ----------------
UPLOAD_RE = _re.compile(rb'type=["\']?\s*file|enctype=["\']?\s*multipart/form-data', _re.I)
LOGIN_RE = _re.compile(rb'type=["\']?\s*password', _re.I)

def _uploadpwn_path():
    if A.uploadpwn:
        return A.uploadpwn
    p = os.path.expanduser("~/tools/uploadpwn/uploadpwn.py")
    return p if os.path.exists(p) else ""

def run_uploadpwn(url, host, timeout=240):
    import shlex
    up = _uploadpwn_path()
    if not up:
        feed(f"⇪ upload point — install uploadpwn or pass --uploadpwn: {url}", "med", host); return
    report = os.path.join(OUT, "params", f"uploadpwn_{_safe(url)}.json")
    if "{url}" in up:
        cmd = shlex.split(up.replace("{url}", url))
    else:
        cmd = ["python3", up, "-t", url, "--discover", "--all", "--i-am-authorized",
               "--crawl-depth", "1", "-o", report]
        if A.cookie: cmd += ["--header", f"Cookie: {A.cookie}"]
        for h in A.header: cmd += ["--header", h]
    feed(f"uploadpwn → {host} (all bypass modules)", "info", host)
    def on(l):
        l = l.strip()
        if l and any(k in l.lower() for k in ("bypass", "success", "rce", "uploaded", "shell obtained", "vulnerable", "confirmed", "[+]")):
            feed(f"uploadpwn[{host}]: {l[:160]}", "crit", host); bump("findings")
    try:
        p = subprocess.Popen(cmd, cwd=OUT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        feed(f"uploadpwn failed on {host}: {e}", "med", host); return
    PROCS["upload:" + host] = p
    timer = threading.Timer(timeout, lambda: p.poll() is None and p.terminate())
    timer.start()
    for line in p.stdout:
        on(line)
    p.wait(); timer.cancel(); PROCS.pop("upload:" + host, None)
    # summarize JSON report if present
    try:
        rep = json.load(open(report))
        vulns = rep.get("vulnerabilities") or rep.get("findings") or rep.get("successes") or []
        if vulns:
            feed(f"‼ uploadpwn: {len(vulns)} upload bypass(es) on {host} → {os.path.basename(report)}", "crit", host)
    except Exception:
        pass

def run_nuclei_tags(url, host, tags):
    nuc = shutil.which("nuclei")
    if not nuc:
        feed(f"tech={tags} on {host} — install nuclei to auto-test", "med", host); return
    feed(f"nuclei ({tags}) → {host}", "info", host)
    def on(l):
        l = l.strip()
        if l:
            sev = "crit" if "critical" in l.lower() else "high" if "high" in l.lower() else "med"
            feed(f"nuclei: {l}", sev, host); bump("findings")
    stream([nuc, "-u", url, "-tags", tags, "-severity", "low,medium,high,critical", "-silent", "-nc"] + HDR_ARGS, on, key="nuclei:" + host)

INTERESTING_PATH = _re.compile(r"(admin|login|api|upload|dashboard|manage|config|backup|dev|staging|internal|graphql|swagger|actuator)", _re.I)
def score_host(host, upload=False, login=False, api=False, tech=""):
    """Attack-surface score → the brain focuses effort on the juiciest hosts."""
    h = STATE["hosts"].get(host, {})
    s = 0
    s += len(h.get("params", [])) * 2
    s += len(h.get("dirs", [])) * 1
    if upload: s += 12
    if login: s += 4
    if api: s += 5
    for d in h.get("dirs", []):
        if INTERESTING_PATH.search(d.get("path", "")): s += 3
    if any(t in tech for t in ("wordpress", "joomla", "drupal", "jenkins", "tomcat", "gitlab", "jira", "confluence")): s += 4
    try:
        code = int(str(h.get("status") or "0").split(",")[-1])
        if code in (401, 403): s += 2          # protected = interesting
    except Exception: pass
    emit({"type": "hostscore", "host": host, "score": s})

def cors_host_checks(url, host):
    """No-dep coverage: reflected-origin CORS + Host-header injection."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": random.choice(UA_POOL), "Origin": "https://recon.evil", **AUTH_HEADERS})
        with urllib.request.urlopen(req, timeout=8, context=_CTX) as r:
            acao = r.headers.get("Access-Control-Allow-Origin", "").strip(); acac = r.headers.get("Access-Control-Allow-Credentials", "").strip()
            # real finding: ACAO exactly reflects our injected Origin, OR wildcard + credentials
            if acao.lower() == "https://recon.evil" or (acao == "*" and acac.lower() == "true"):
                finding("high", "cors", host, f"↔ CORS misconfig on {host} (ACAO={acao}{' + creds' if acac.lower()=='true' else ''})")
    except Exception: pass
    try:
        # real finding: our injected Host actually controls an absolute redirect target
        req = urllib.request.Request(url, headers={"User-Agent": random.choice(UA_POOL), "Host": "recon.evil", **AUTH_HEADERS})
        r = _NOREDIR.open(req, timeout=8)
        loc = r.headers.get("Location", "").strip()
        if _redirects_to(loc, "recon.evil"):
            finding("med", "host-header", host, f"🧭 Host-header controls redirect on {host} -> {loc[:80]}")
    except Exception: pass

def check_session(live):
    """Auth scenario: if creds were supplied, verify the session is actually valid."""
    if not AUTH_HEADERS or not live: return
    sc, hd, body = _get(live[0], timeout=10)
    if body and LOGIN_RE.search(body):
        feed("⚠ session check: a login form still appears with your creds set — cookie may be expired/invalid", "med")
    elif sc in (401, 403):
        feed(f"⚠ session check: {live[0]} returns {sc} with your creds — auth may not be applying", "med")
    else:
        feed("✓ session looks valid (authenticated requests accepted)", "good")

# ---------- smart detection: nuclei (auto templates + DAST) — logic lives in maintained YAML ----------
def _host_of(s):
    try: return urllib.parse.urlsplit(s if "://" in s else "https://" + s).netloc or DOMAIN
    except Exception: return DOMAIN

def _nuclei_stream(cmd, tag):
    def on(line):
        try: o = json.loads(line)
        except Exception: return
        info = o.get("info", {}) or {}
        sev = (info.get("severity") or "info").lower()
        name = info.get("name") or o.get("template-id", "")
        at = o.get("matched-at") or o.get("matched") or o.get("host", "")
        m = {"critical": "crit", "high": "high", "medium": "med"}.get(sev, "info")
        if sev in ("critical", "high", "medium", "low"):
            finding(m, "nuclei", _host_of(at), f"nuclei[{sev}] {name} — {at}"[:150], at)
    stream(cmd, on, key=tag)

def stage_intel():
    emit({"type": "stage", "stage": "intel", "state": "run"})
    nuc = shutil.which("nuclei")
    if not nuc:
        feed("nuclei missing — smart detection unavailable; install it", "med")
        emit({"type": "stage", "stage": "intel", "state": "done", "pct": 0}); return
    live = os.path.join(OUT, "live.txt"); purls = os.path.join(OUT, "params", "urls.txt")
    # 1) auto template selection per target's detected tech (-as) — CVEs/misconfig/exposure/CORS/CRLF/takeover…
    if os.path.exists(live) and os.path.getsize(live):
        feed("nuclei -as: auto-selecting templates per host tech (maintained detection logic)…")
        _nuclei_stream([nuc, "-l", live, "-as", "-severity", "low,medium,high,critical",
                        "-jsonl", "-o", os.path.join(OUT, "nuclei_intel.jsonl"), "-silent", "-nc", "-rl", "80"] + HDR_ARGS, "nuclei-as")
    # 2) DAST fuzzing on discovered parameterised URLs — injection classes as templates, not hardcoded payloads
    if os.path.exists(purls) and os.path.getsize(purls):
        feed("nuclei -dast: fuzzing discovered parameters (SQLi/XSS/SSTI/LFI/redirect/CRLF via templates)…")
        _nuclei_stream([nuc, "-l", purls, "-dast", "-severity", "low,medium,high,critical",
                        "-jsonl", "-o", os.path.join(OUT, "nuclei_dast.jsonl"), "-silent", "-nc", "-rl", "60"] + HDR_ARGS, "nuclei-dast")
    # 3) subdomain-takeover sweep (subzy if present, else nuclei takeover templates)
    subs_all = os.path.join(OUT, "subs.txt")
    if shutil.which("subzy") and os.path.exists(subs_all):
        feed("subzy: subdomain-takeover sweep…")
        def _sz(l):
            if "VULNERABLE" in l.upper():
                finding("high", "takeover", _host_of(l), f"subdomain takeover: {l.strip()[:140]}")
        stream(["subzy", "run", "--targets", subs_all, "--hide_fails"], _sz, key="subzy")
    elif os.path.exists(subs_all) and os.path.getsize(subs_all):
        feed("nuclei takeover templates: subdomain-takeover sweep…")
        _nuclei_stream([nuc, "-l", subs_all, "-tags", "takeover", "-jsonl",
                        "-o", os.path.join(OUT, "nuclei_takeover.jsonl"), "-silent", "-nc", "-rl", "80"] + HDR_ARGS, "nuclei-takeover")
    # 3b) sqlmap on the highest-value parameterised URLs (opt-in; heavy/noisy)
    if A.sqli and shutil.which("sqlmap") and os.path.exists(purls) and os.path.getsize(purls):
        try:
            cand = sorted({l.strip() for l in open(purls) if "?" in l and "=" in l},
                          key=lambda u: -_endpoint_score(u))[:25]
        except Exception:
            cand = []
        if cand:
            mfile = os.path.join(OUT, "params", "sqli_targets.txt")
            open(mfile, "w").write("\n".join(cand) + "\n")
            feed(f"sqlmap: testing {len(cand)} highest-value URLs for SQL injection…")
            sq = ["sqlmap", "-m", mfile, "--batch", "--smart", "--level", "1", "--risk", "1",
                  "--random-agent", "--disable-coloring", "--output-dir", os.path.join(OUT, "sqlmap")]
            if A.cookie: sq += ["--cookie", A.cookie]
            def _sq(l):
                low = l.lower()
                if "is vulnerable" in low or "appears to be injectable" in low or "injectable" in low and "not" not in low:
                    finding("crit", "sqli", DOMAIN, f"sqlmap: {l.strip()[:150]}")
            stream(sq, _sq, key="sqlmap")
    # 4) dalfox XSS confirmation on discovered params (optional — only if installed)
    if shutil.which("dalfox") and os.path.exists(purls) and os.path.getsize(purls):
        feed("dalfox: confirming reflected/DOM XSS on discovered params…")
        def _dx(l):
            if "[POC]" in l or "[VULN]" in l:
                finding("high", "xss", _host_of(l), f"dalfox XSS confirmed: {l.strip()[:150]}")
        stream(["dalfox", "file", purls, "--silence", "--no-color", "--skip-bav"] + HDR_ARGS, _dx, key="dalfox")
    mark_stage("intel")
    emit({"type": "stage", "stage": "intel", "state": "done", "pct": 100})
    feed("nuclei intelligence complete", "good")

def stage_brain():
    emit({"type": "stage", "stage": "brain", "state": "run"})
    feed("smart routing: forms, upload points, tech-specific tests…")
    try:
        _live0 = [l.strip() for l in open(os.path.join(OUT, "live.txt")) if l.strip()]
    except Exception:
        _live0 = []
    check_session(_live0)
    try:
        live = [l.strip() for l in open(os.path.join(OUT, "live.txt")) if l.strip()]
    except Exception:
        live = []
    sem = threading.Semaphore(6); th = []
    def analyze(url):
        with sem:
            if not STATE["running"]: return
            host = urllib.parse.urlsplit(url).netloc
            sc, hd, body = _get(url, timeout=10)
            upload = login = api = False
            if body:
                if UPLOAD_RE.search(body):
                    upload = True
                    finding("high", "upload-form", host, f"⇪ file-upload form on {host}")
                    if getattr(A, "uploadpwn_auto", False):
                        run_uploadpwn(url, host)
                    else:
                        feed(f"⇪ upload point on {host} — not auto-exploited; use the host 'uploadpwn' "
                             f"action or relaunch with --uploadpwn-auto (intrusive)", "med", host)
                if LOGIN_RE.search(body):
                    login = True
                    feed(f"🔑 login form on {host} — auth / default-creds candidate", "med", host)
            ctype = str(hd.get("Content-Type", "")).lower()
            if "json" in ctype or "graphql" in url.lower() or "/api" in url.lower():
                api = True
                feed(f"🔌 API/JSON surface on {host} — param/JSON + GraphQL introspection candidate", "info", host)
            # cheap, no-dep scenario tests
            cors_host_checks(url, host)
            exposure_checks(url, host)               # broken access control / autoindex on the root
            check_exposed_files(url, host)           # .git/.env/backups/secrets independent of wordlist
            js_recon(host)                           # API endpoints + leaked secrets from JS
            hd0 = STATE["hosts"].get(host, {})       # + on discovered directories / interesting paths
            checked = 0
            for d in hd0.get("dirs", []):
                p = d.get("path", "")
                if p and (p.endswith("/") or INTERESTING_PATH.search(p)):
                    exposure_checks(urllib.parse.urljoin(url, p), host); checked += 1
                if checked >= 15: break
            tech = " ".join(STATE["hosts"].get(host, {}).get("tech", [])).lower()
            if "wordpress" in tech: run_nuclei_tags(url, host, "wordpress")
            elif "joomla" in tech: run_nuclei_tags(url, host, "joomla")
            elif "drupal" in tech: run_nuclei_tags(url, host, "drupal")
            elif "tomcat" in tech: feed(f"Apache Tomcat on {host} — check /manager, CVE-2020-1938 (Ghostcat)", "med", host)
            elif "jenkins" in tech: run_nuclei_tags(url, host, "jenkins")
            score_host(host, upload=upload, login=login, api=api, tech=tech)
    for url in live:
        x = threading.Thread(target=analyze, args=(url,), daemon=True); x.start(); th.append(x)
    for x in th: x.join()
    mark_stage("brain")
    emit({"type": "stage", "stage": "brain", "state": "done", "pct": 100})
    feed("smart routing complete", "good")

# ---------------- auto report ----------------
SEV_RANK = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}
def write_report():
    recs = []
    try:
        for l in open(os.path.join(OUT, "findings.jsonl")):
            l = l.strip()
            if l:
                try: recs.append(json.loads(l))
                except Exception: pass
    except Exception: pass
    recs.sort(key=lambda r: (SEV_RANK.get(r.get("sev", "info"), 9), r.get("host", "")))
    hosts = sorted(STATE["hosts"].values(), key=lambda h: -(h.get("score") or 0))
    rj = {"domain": DOMAIN, "generated": time.time(), "counts": dict(STATE["counts"]),
          "stages": manifest_load().get("stages", {}), "findings": recs,
          "hosts": [{"host": h.get("host", "?"), "url": h.get("url", ""), "status": h.get("status"),
                     "codes": h.get("codes", ""), "title": h.get("title", ""), "tech": h.get("tech", []),
                     "score": h.get("score", 0), "state": h.get("state", ""),
                     "dirs": len(h.get("dirs", [])), "params": h.get("params", [])} for h in hosts]}
    json.dump(rj, open(os.path.join(OUT, "report.json"), "w"), indent=2)
    c = STATE["counts"]; el = int(time.time() - STATE["started"])
    def esc(s): return str(s or "").replace("|", "\\|").replace("\n", " ")
    def hrow(h):
        return (f"| {esc(h.get('host', '?'))} | {esc(h.get('codes') or h.get('status') or '')} | {esc((h.get('title') or '')[:40])} "
                f"| {esc(', '.join(h.get('tech', [])[:4]))} | {h.get('score', 0)} | {len(h.get('dirs', []))} | {len(h.get('params', []))} |")
    L = [f"# recon-live report — {DOMAIN}",
         f"\nGenerated {time.strftime('%Y-%m-%d %H:%M')} · elapsed {el // 60}m{el % 60}s · output: `{OUT}`\n",
         "## Summary\n",
         "| subs | resolved | live | dirs | params | findings |",
         "|---|---|---|---|---|---|",
         f"| {c.get('subs',0)} | {c.get('resolved',0)} | {c.get('live',0)} | {c.get('dirs',0)} | {c.get('params',0)} | {c.get('findings',0)} |\n",
         "## Findings\n"]
    if recs:
        L += ["| sev | kind | host | msg | url |", "|---|---|---|---|---|"]
        L += [f"| {r.get('sev','')} | {esc(r.get('kind',''))} | {esc(r.get('host',''))} | {esc(r.get('msg',''))} | {esc(r.get('url',''))} |" for r in recs]
    else:
        L.append("(none)")
    live_hosts = [h for h in hosts if h.get("url")]
    L += ["\n## Top attack surface\n",
          "| host | code | title | tech | score | dirs | params |", "|---|---|---|---|---|---|---|"]
    L += [hrow(h) for h in live_hosts[:15]]
    L += ["\n## Live hosts\n",
          "| host | code | title | tech | score | dirs | params |", "|---|---|---|---|---|---|---|"]
    L += [hrow(h) for h in sorted(live_hosts, key=lambda h: h.get("host", ""))]
    L += ["\n---",
          "Output layout: `subs.txt`, `resolved.txt`, `live.txt`, `findings.jsonl`, "
          "`hosts/<host>/` (ferox.json, urls.txt, params.txt), `params/`, `nuclei_*.jsonl`, `manifest.json`, `report.json`."]
    open(os.path.join(OUT, "REPORT.md"), "w").write("\n".join(L) + "\n")

def _prev_run_dir():
    """Newest sibling run dir of this domain, excluding the current one."""
    base = os.path.dirname(OUT.rstrip("/"))
    cur = os.path.basename(OUT.rstrip("/"))
    try:
        sibs = sorted(d for d in os.listdir(base)
                      if d != cur and os.path.isdir(os.path.join(base, d))
                      and os.path.exists(os.path.join(base, d, "live.txt")))
    except Exception:
        return None
    return os.path.join(base, sibs[-1]) if sibs else None

def write_diff():
    prev = _prev_run_dir()
    if not prev:
        feed("--diff: no previous run to compare against", "info"); return
    def loadset(p):
        try: return set(l.strip() for l in open(p) if l.strip())
        except Exception: return set()
    def loadfind(p):
        out = []
        try:
            for l in open(p):
                l = l.strip()
                if l:
                    try: out.append(json.loads(l))
                    except Exception: pass
        except Exception: pass
        return out
    new_live = loadset(os.path.join(OUT, "live.txt")) - loadset(os.path.join(prev, "live.txt"))
    prev_keys = {(r.get("kind"), r.get("host"), r.get("msg")) for r in loadfind(os.path.join(prev, "findings.jsonl"))}
    new_find = [r for r in loadfind(os.path.join(OUT, "findings.jsonl"))
                if (r.get("kind"), r.get("host"), r.get("msg")) not in prev_keys]
    L = [f"# recon-live DIFF — {DOMAIN}",
         f"\nCurrent `{os.path.basename(OUT.rstrip('/'))}` vs previous `{os.path.basename(prev)}`\n",
         f"## New live hosts ({len(new_live)})\n"] + ([f"- {u}" for u in sorted(new_live)] or ["(none)"])
    L += [f"\n## New findings ({len(new_find)})\n"] + \
         ([f"- **[{r.get('sev')}]** {r.get('kind')} — {r.get('host')} — {r.get('msg')}" for r in new_find] or ["(none)"])
    open(os.path.join(OUT, "DIFF.md"), "w").write("\n".join(L) + "\n")
    feed(f"📑 diff → DIFF.md ({len(new_live)} new hosts, {len(new_find)} new findings)", "good")

def stage_report():
    emit({"type": "stage", "stage": "report", "state": "run"})
    write_report()
    if A.diff:
        try: write_diff()
        except Exception as e: feed(f"diff error: {e}", "med")
    emit({"type": "stage", "stage": "report", "state": "done", "pct": 100})
    feed(f"📄 report written → {OUT}/REPORT.md", "good")

def preflight_feed():
    need = ["subfinder", "assetfinder", "dnsx", "feroxbuster", "katana", "gau", "waybackurls", "nuclei"]
    present = [b for b in need if shutil.which(b)]
    missing = [b for b in need if not shutil.which(b)]
    hx = "httpx(pd)" if HTTPX else "httpx(MISSING)"
    feed(f"tools ready: {', '.join(present)}, {hx}", "good")
    if missing or not HTTPX:
        feed(f"⚠ missing: {', '.join(missing + ([] if HTTPX else ['httpx']))} — run in WSL/Kali (python3), not Windows python", "med")
    wl_ok = os.path.exists(A.wordlist)
    feed(f"config: wordlist={os.path.basename(A.wordlist)}{'' if wl_ok else ' (MISSING!)'} · "
         f"out={OUT} · budget={A.max_requests or '∞'} · notify={'on' if A.notify else 'off'} · "
         f"uploadpwn-auto={'ON' if A.uploadpwn_auto else 'off'} · diff={'on' if A.diff else 'off'} · "
         f"screens={'on' if A.screens else 'off'}",
         "info" if wl_ok else "med")

def _resume(name, path, count_key):
    """Replay a finished stage from its artifact. Returns loaded lines, or None to rerun."""
    p = os.path.join(OUT, path)
    if stage_done(name) and os.path.exists(p):
        lines = [l.strip() for l in open(p) if l.strip()]
        emit({"type": "stage", "stage": name, "state": "done", "pct": 100})
        if count_key: emit({"type": "count", "key": count_key, "value": len(lines)})
        feed(f"↻ resumed {name} ({len(lines)} items) — --fresh to redo", "info")
        return lines
    return None

def _skip_or_run(name, fn):
    if stage_done(name):
        emit({"type": "stage", "stage": name, "state": "done", "pct": 100})
        feed(f"↻ resumed {name} — --fresh to redo", "info")
    else:
        fn()

def _params_or_resume(live):
    purls = _resume("params", os.path.join("params", "urls.txt"), None)
    if purls is None:
        stage_params(live); return
    try: npar = len([l for l in open(os.path.join(OUT, "params", "params.txt")) if l.strip()])
    except Exception: npar = 0
    emit({"type": "count", "key": "params", "value": npar})

def run_pipeline():
    try:
        threading.Thread(target=_persist_state, daemon=True).start()   # crash-safe state.json
        preflight_feed()
        subs = _resume("enum", "subs.txt", "subs")
        if subs is None: subs = stage_enum()
        else:
            for h in subs: emit({"type": "host", "host": h, "map": "offline"})
        if not STATE["running"]: return
        res = _resume("resolve", "resolved.txt", "resolved")
        if res is None: res = stage_resolve(subs)
        else:
            for h in res: emit({"type": "host", "host": h, "map": "resolved"})
        if not STATE["running"]: return
        targets = res
        if A.ports:
            pr = _resume("ports", "ports.txt", None)
            targets = pr if pr is not None else stage_ports(res)
        else:
            emit({"type": "stage", "stage": "ports", "state": "done", "pct": 0})
        if not STATE["running"]: return
        live = _resume("probe", "live.txt", "live")
        if live is None: live = stage_probe(targets)
        else:
            for u in live: emit({"type": "host", "host": _host_of(u), "url": u, "map": "live"})
        if not STATE["running"]: return
        if A.screens:                                # non-blocking screenshots of live hosts
            threading.Thread(target=run_screens, daemon=True).start()
        # params + dirs in parallel (params is passive, dirs is heavy)
        tp = threading.Thread(target=_params_or_resume, args=(live,), daemon=True); tp.start()
        stage_dirs(live)
        tp.join()
        if A.test and STATE["running"]:
            _skip_or_run("vulns", stage_vulns)       # confirmed checks + signature-free differential anomaly probe
            if STATE["running"]:
                _skip_or_run("brain", stage_brain)   # signal routing: forms, upload points, tech notes
            if STATE["running"]:
                _skip_or_run("intel", stage_intel)   # nuclei auto-templates (-as) + DAST fuzzing — detection logic in maintained YAML
        else:
            for s in ("vulns", "brain", "intel"):
                if not stage_done(s): emit({"type": "stage", "stage": s, "state": "done", "pct": 0})
            if not A.test: feed("active testing skipped (--no-test)", "info")
        stage_report()                               # always regenerate
        feed("★ pipeline complete", "good")
    except Exception as e:
        feed(f"pipeline error: {e}", "high")
    finally:
        emit({"type": "phase", "phase": "done"})

def list_text(typ):
    """On-demand full lists — everything discovered so far, as plain text."""
    def readf(p):
        try: return open(os.path.join(OUT, p)).read().strip()
        except Exception: return ""
    if typ == "subs":
        rows = []
        for h in sorted(STATE["hosts"].values(), key=lambda x: x["host"]):
            rows.append(f'{h.get("map","offline"):9} {h["host"]}')
        return "\n".join(rows) or "(none yet)"
    if typ == "live":
        return "\n".join(sorted(h.get("url", "") for h in STATE["hosts"].values() if h.get("map") == "live" and h.get("url"))) or "(none yet)"
    if typ == "resolved":
        return readf("resolved.txt") or "(none yet)"
    if typ == "params":
        return readf(os.path.join("params", "params.txt")) or "(none yet)"
    if typ == "urls":       # full parameterised URLs
        return readf(os.path.join("params", "urls.txt")) or "(none yet)"
    if typ == "dirs":       # full discovered paths across all hosts
        out = []
        for h in sorted(STATE["hosts"].values(), key=lambda x: x["host"]):
            base = h.get("url") or ("https://" + h["host"])
            for d in h.get("dirs", []):
                out.append(f'{d.get("code","")} {base.rstrip("/")}{d.get("path","")}')
        return "\n".join(out) or "(none yet)"
    return "(unknown list type)"

def start_run(domain, cookie="", headers=None, uploadpwn=None, test=None, uploadpwn_auto=None):
    if STATE.get("phase") == "running":
        return False, "a scan is already running"
    if not domain.strip():
        return False, "no scope entered"
    set_scope(domain, cookie, headers, uploadpwn, test, uploadpwn_auto)
    reset_state()
    emit({"type": "phase", "phase": "running", "domain": DOMAIN})
    feed(f"◉ engagement started on {DOMAIN}", "good")
    threading.Thread(target=run_pipeline, daemon=True).start()
    return True, DOMAIN

# ---------------- actions ----------------
def action_nuclei(host):
    nuc = shutil.which("nuclei")
    if not nuc:
        feed("nuclei missing", "high"); return
    url = STATE["hosts"].get(host, {}).get("url") or ("https://" + host)
    feed(f"nuclei → {host}", "info", host)
    outp = os.path.join(OUT, f"nuclei_{_safe(url)}.txt")
    def on(l):
        l = l.strip()
        if l:
            sev = "crit" if "critical" in l.lower() else "high" if "high" in l.lower() else "med"
            feed(f"nuclei: {l}", sev, host); bump("findings")
    stream([nuc, "-u", url, "-severity", "low,medium,high,critical", "-silent", "-nc", "-o", outp], on, key="nuclei:" + host)

def do_action(act, host):
    if act == "kill":
        p = PROCS.get(host)
        if p:
            p.terminate()
            emit({"type": "hoststate", "host": host, "state": "killed"})
            feed(f"killed scan on {host}", "med", host)
    elif act == "rescan":
        u = STATE["hosts"].get(host, {}).get("url") or ("https://" + host)
        threading.Thread(target=ferox_host, args=(u, lambda: None), daemon=True).start()
    elif act == "nuclei":
        threading.Thread(target=action_nuclei, args=(host,), daemon=True).start()
    elif act == "stop":
        STATE["running"] = False
        for p in list(PROCS.values()):
            try: p.terminate()
            except Exception: pass
        feed("⏹ stopped by user", "med")

# ---------------- web server ----------------
DASH = r"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>recon-live · __DOMAIN__</title>
<style>
:root{--bg:#0d0f14;--panel:#141821;--panel2:#1b2130;--line:#252c3a;--line2:#333d4f;
--text:#e6e8ee;--muted:#8b93a7;--faint:#5b6376;--amber:#e8a13a;--teal:#39bdae;--ok:#3fb950;--warn:#e5484d;--cyan:#4aa8ff;
--mono:"JetBrains Mono",ui-monospace,Consolas,monospace;--sans:"Space Grotesk",system-ui,Segoe UI,sans-serif}
*{box-sizing:border-box}html,body{margin:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px}
a{color:var(--cyan)}
header{display:flex;align-items:center;gap:16px;padding:12px 18px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:10;flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:600;font-size:17px}
.brand b{color:var(--amber)}
.tgt{font-family:var(--mono);color:var(--muted);font-size:13px}
.counts{display:flex;gap:8px;margin-left:auto;flex-wrap:wrap}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:6px 11px;min-width:64px;text-align:center}
.kpi .n{font-family:var(--mono);font-weight:700;font-size:18px}
.kpi .l{font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.5px}
.kpi.live .n{color:var(--ok)}.kpi.dirs .n{color:var(--amber)}.kpi.params .n{color:var(--cyan)}.kpi.find .n{color:var(--warn)}
.btn{font:inherit;font-size:12px;cursor:pointer;background:var(--panel2);color:var(--muted);border:1px solid var(--line);border-radius:7px;padding:6px 11px}
.btn:hover{color:var(--text);border-color:var(--line2)}
.btn.stop{color:var(--warn);border-color:var(--warn)}
.pipe{display:flex;gap:8px;padding:10px 18px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.stg{flex:1;min-width:130px;background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:8px 10px}
.stg .h{display:flex;justify-content:space-between;font-family:var(--mono);font-size:11px;color:var(--muted)}
.stg .bar{height:5px;background:var(--panel2);border-radius:3px;margin-top:6px;overflow:hidden}
.stg .bar i{display:block;height:100%;width:0;background:var(--teal);transition:width .3s}
.stg.run{border-color:var(--teal)}.stg.run .h{color:var(--teal)}
.stg.done .bar i{background:var(--ok)}.stg.done .h{color:var(--ok)}
main{display:grid;grid-template-columns:1fr 380px;gap:1px;background:var(--line);min-height:calc(100vh - 150px)}
.left,.right{background:var(--bg);padding:14px 18px;overflow:auto}
.toolbar{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.toolbar input[type=text]{flex:1;min-width:160px;font-family:var(--mono);font-size:13px;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:8px 10px}
.chip{font-family:var(--mono);font-size:12px;cursor:pointer;background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:5px 11px;color:var(--muted)}
.chip.on{border-color:var(--amber);color:var(--amber)}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.5px;padding:6px 8px;border-bottom:1px solid var(--line);cursor:pointer}
td{padding:7px 8px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}
tr.host{cursor:pointer}tr.host:hover{background:var(--panel)}
.code{font-family:var(--mono);font-weight:700;font-size:12px;padding:2px 7px;border-radius:6px;display:inline-block;min-width:34px;text-align:center}
.c2{background:color-mix(in srgb,var(--ok) 20%,transparent);color:var(--ok)}
.c3{background:color-mix(in srgb,var(--teal) 20%,transparent);color:var(--teal)}
.c4{background:color-mix(in srgb,var(--amber) 20%,transparent);color:var(--amber)}
.c5{background:color-mix(in srgb,var(--warn) 22%,transparent);color:var(--warn)}
.c0{background:var(--panel2);color:var(--faint)}
.host-n{font-family:var(--mono);font-size:13px}
.title{color:var(--muted);font-size:12px}
.tech{display:inline-block;font-size:10px;font-family:var(--mono);background:var(--panel2);border:1px solid var(--line);border-radius:5px;padding:1px 6px;margin:1px 2px 0 0;color:var(--muted)}
.st{font-family:var(--mono);font-size:11px;padding:2px 7px;border-radius:6px}
.st.scanning{color:var(--teal)}.st.done{color:var(--ok)}.st.stalled,.st.killed{color:var(--warn)}.st.up{color:var(--faint)}
.hbar{height:4px;background:var(--panel2);border-radius:2px;margin-top:3px;overflow:hidden;min-width:70px}
.hbar i{display:block;height:100%;background:var(--teal);width:0;transition:width .4s}
.spin{display:inline-block;animation:sp 1s linear infinite}@keyframes sp{to{transform:rotate(360deg)}}
.acts{white-space:nowrap}
.acts button{font-size:11px;padding:3px 7px;margin-left:3px}
.exp{background:var(--panel);border-left:2px solid var(--teal)}
.exp .grp{margin:4px 0}
.exp .dir{font-family:var(--mono);font-size:12px;padding:1px 0}
.right h3{margin:0 0 8px;font-family:var(--mono);font-size:12px;color:var(--muted)}
.feed{display:flex;flex-direction:column;gap:4px}
.fi{font-family:var(--mono);font-size:12px;padding:5px 8px;border-radius:6px;background:var(--panel);border-left:2px solid var(--line)}
.fi.good{border-left-color:var(--ok)}.fi.med{border-left-color:var(--amber)}.fi.high,.fi.crit{border-left-color:var(--warn)}
.fi .t{color:var(--faint);font-size:10px}
@media(max-width:900px){main{grid-template-columns:1fr}}
.hide{display:none!important}
@keyframes pulse{0%{transform:scale(1)}35%{transform:scale(1.3);color:var(--ok)}100%{transform:scale(1)}}
.kpi .n.bump{animation:pulse .55s ease}
@keyframes flashrow{0%{background:color-mix(in srgb,var(--teal) 34%,transparent)}100%{background:transparent}}
tr.host.flash{animation:flashrow 1.1s ease}
.radar{position:relative;width:13px;height:13px;border-radius:50%;background:var(--faint);flex:none;transition:background .2s}
.radar.on{background:var(--ok)}
.radar.on::after{content:"";position:absolute;inset:-5px;border:2px solid var(--ok);border-radius:50%;animation:ring .8s ease-out}
@keyframes ring{0%{transform:scale(.5);opacity:.9}100%{transform:scale(2.4);opacity:0}}
#lists{position:fixed;inset:0;background:rgba(8,10,14,.9);z-index:90;display:none;align-items:center;justify-content:center}
#lists.on{display:flex}
#lists .card{background:var(--panel);border:1px solid var(--line2);border-radius:14px;padding:20px;width:min(920px,94vw);height:min(82vh,760px);display:flex;flex-direction:column}
#lists .tabs2{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap}
#lists .t2{font-family:var(--mono);font-size:12px;cursor:pointer;background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:6px 11px;color:var(--muted)}
#lists .t2.on{border-color:var(--amber);color:var(--amber)}
#lists textarea{flex:1;width:100%;font-family:var(--mono);font-size:12px;line-height:1.5;background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:9px;padding:11px;resize:none;box-sizing:border-box}
#lists .bar2{display:flex;gap:8px;margin-top:10px;align-items:center}
#scope{position:fixed;inset:0;background:rgba(8,10,14,.97);z-index:100;display:flex;align-items:center;justify-content:center}
#scope .card{background:var(--panel);border:1px solid var(--line2);border-radius:14px;padding:28px;width:min(560px,92vw)}
#scope h1{font-family:var(--mono);font-size:24px;margin:0 0 4px}#scope h1 b{color:var(--amber)}
#scope p{color:var(--muted);margin:0 0 14px;font-size:13px}
#scope label{display:block;font-size:12px;color:var(--muted);margin:12px 0 5px}
#scope input[type=text],#scope textarea{width:100%;font-family:var(--mono);font-size:14px;background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:9px;padding:11px;box-sizing:border-box}
#scope .go{margin-top:18px;width:100%;font-size:15px;font-weight:700;background:var(--amber);color:#111;border:0;border-radius:10px;padding:13px;cursor:pointer}
#scope .go:hover{filter:brightness(1.06)}
#scope .chk{display:flex;align-items:center;gap:8px;margin-top:12px;color:var(--muted);font-size:13px}
</style></head>
<body>
<div id="scope">
  <div class="card">
    <h1>recon<b>·</b>live</h1>
    <p>Enter a scope. Every brain — enum, resolve, probe, dirs, params, vulns, upload — spins up and this page becomes a live orchestration.</p>
    <label>Target domain</label>
    <input type="text" id="s_domain" placeholder="example.com" autofocus>
    <label>Cookie <span style="color:var(--faint)">— optional, for authenticated scans</span></label>
    <input type="text" id="s_cookie" placeholder="SESSION=...; token=...">
    <label>Extra headers <span style="color:var(--faint)">— optional, one per line</span></label>
    <textarea id="s_headers" rows="2" placeholder="Authorization: Bearer ..."></textarea>
    <label>uploadpwn command <span style="color:var(--faint)">— optional, {url} placeholder</span></label>
    <input type="text" id="s_upload" placeholder="auto: ~/tools/uploadpwn/uploadpwn.py">
    <label class="chk"><input type="checkbox" id="s_test" checked> Active testing (LFI/SSTI/redirect/nuclei) — authorized scope only</label>
    <label class="chk"><input type="checkbox" id="s_upload_auto"> Auto-run uploadpwn on upload forms <span style="color:var(--warn)">(intrusive — uploads payloads)</span></label>
    <button class="go" id="s_go">◉ Launch orchestration</button>
    <div id="s_msg" style="color:var(--warn);font-size:12px;margin-top:8px"></div>
  </div>
</div>
<header>
  <span class="radar" id="radar" title="discovery activity"></span>
  <span class="brand">recon<b>·</b>live</span>
  <span class="tgt" id="tgt">__DOMAIN__</span>
  <span class="tgt" id="elapsed"></span>
  <div class="counts">
    <div class="kpi"><div class="n" id="c_subs">0</div><div class="l">mapped</div></div>
    <div class="kpi"><div class="n" id="c_resolved">0</div><div class="l">resolves</div></div>
    <div class="kpi live"><div class="n" id="c_live">0</div><div class="l">live</div></div>
    <div class="kpi dirs"><div class="n" id="c_dirs">0</div><div class="l">dirs</div></div>
    <div class="kpi params"><div class="n" id="c_params">0</div><div class="l">params</div></div>
    <div class="kpi find"><div class="n" id="c_findings">0</div><div class="l">findings</div></div>
  </div>
  <button class="btn" id="listsBtn">▤ Lists</button>
  <a class="btn" href="/report" target="_blank">⬇ Report</a>
  <button class="btn stop" id="stopBtn">Stop</button>
</header>
<div id="lists"><div class="card">
  <div class="tabs2" id="listTabs">
    <span class="t2 on" data-t="subs">subdomains</span>
    <span class="t2" data-t="live">live URLs</span>
    <span class="t2" data-t="resolved">resolved</span>
    <span class="t2" data-t="params">params</span>
    <span class="t2" data-t="urls">param URLs</span>
    <span class="t2" data-t="dirs">directories</span>
  </div>
  <textarea id="listText" readonly spellcheck="false"></textarea>
  <div class="bar2">
    <button class="btn" id="listCopy">Copy</button>
    <button class="btn" id="listDownload">Download</button>
    <span id="listCount" style="color:var(--muted)"></span>
    <button class="btn" id="listClose" style="margin-left:auto">Close</button>
  </div>
</div></div>
<div class="pipe" id="pipe"></div>
<main>
  <section class="left">
    <div class="toolbar">
      <input type="text" id="q" placeholder="filter host / title / tech / path…">
      <span class="chip on" data-s2="live">live</span><span class="chip on" data-s2="resolved">resolved</span><span class="chip on" data-s2="offline">offline</span>
      <span style="color:var(--faint)">|</span>
      <span class="chip on" data-f="2xx">2xx</span><span class="chip on" data-f="3xx">3xx</span>
      <span class="chip on" data-f="4xx">4xx</span><span class="chip on" data-f="5xx">5xx</span>
      <span class="chip" data-f="dirs">has dirs</span>
    </div>
    <table><thead><tr>
      <th data-s="status">code</th><th data-s="host">host</th><th data-s="title">title / tech</th>
      <th data-s="dirs">dirs</th><th data-s="params">params</th><th data-s="score">score</th><th data-s="state">state</th><th>actions</th>
    </tr></thead><tbody id="rows"></tbody></table>
  </section>
  <aside class="right">
    <h3>findings feed</h3>
    <div class="feed" id="feed"></div>
  </aside>
</main>
<script>
const $=s=>document.querySelector(s), rowsEl=$("#rows"), feedEl=$("#feed");
let ST={hosts:{},counts:{},stages:{},feed:[],started:Date.now()/1000};
const STAGES=["enum","resolve","ports","probe","dirs","params","vulns","brain","intel","report"];
const filters={q:"",set:new Set(["2xx","3xx","4xx","5xx"]),surf:new Set(["live","resolved","offline"]),dirs:false,sort:"score"};

function cls(code){const c=parseInt(code);if(c>=200&&c<300)return"c2";if(c<400)return"c3";if(c<500)return"c4";if(c<600)return"c5";return"c0";}
function esc(s){return (s||"").replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));}

function renderPipe(){
  $("#pipe").innerHTML=STAGES.map(s=>{const st=ST.stages[s]||{state:"pending",pct:0};
    return `<div class="stg ${st.state}"><div class="h"><span>${s}</span><span>${st.state==="done"?"✓":st.pct?st.pct+"%":st.state}</span></div><div class="bar"><i style="width:${st.state==="done"?100:st.pct||0}%"></i></div></div>`;}).join("");
}
let _prevC={};
function renderCounts(){for(const k of["subs","resolved","live","dirs","params","findings"]){const e=$("#c_"+k);if(!e)continue;const v=ST.counts[k]||0;e.textContent=v;if(v>(_prevC[k]||0)){e.classList.remove("bump");void e.offsetWidth;e.classList.add("bump");}_prevC[k]=v;}}
function hmap(h){return h.map || (h.url?"live":"offline");}
let _radT=null;
function ping(){const r=$("#radar");if(!r)return;r.classList.add("on");clearTimeout(_radT);_radT=setTimeout(()=>r.classList.remove("on"),800);}
const flashHosts=new Set();
function firstCode(h){const c=(h.codes||String(h.status||"")).split(",").filter(Boolean);return c[c.length-1]||h.status||0;}
function passFilter(h){
  const m=hmap(h);
  if(!filters.surf.has(m))return false;                 // surface filter (live/resolved/offline)
  if(m==="live"){                                        // status bands only apply to live hosts
    const code=parseInt(firstCode(h))||0; const band=code>=500?"5xx":code>=400?"4xx":code>=300?"3xx":code>=200?"2xx":null;
    if(band&&!filters.set.has(band))return false;
  }
  if(filters.dirs&&!(h.dirs&&h.dirs.length))return false;
  if(filters.q){const q=filters.q.toLowerCase();
    const hay=(h.host+" "+(h.title||"")+" "+(h.tech||[]).join(" ")+" "+(h.dirs||[]).map(d=>d.path).join(" ")).toLowerCase();
    if(!hay.includes(q))return false;}
  return true;
}
function sortHosts(arr){const s=filters.sort;
  return arr.sort((a,b)=>{
    if(s==="status")return (parseInt(firstCode(a))||999)-(parseInt(firstCode(b))||999);
    if(s==="score")return (b.score||0)-(a.score||0);
    if(s==="dirs")return (b.dirs?.length||0)-(a.dirs?.length||0);
    if(s==="params")return (b.params?.length||0)-(a.params?.length||0);
    return (a.host||"").localeCompare(b.host||"");});
}
let expanded=new Set();
function renderRows(){
  const arr=sortHosts(Object.values(ST.hosts).filter(passFilter));
  rowsEl.innerHTML=arr.map(h=>{
    const code=firstCode(h);
    const tech=(h.tech||[]).slice(0,6).map(t=>`<span class="tech">${esc(t)}</span>`).join("");
    const stt=h.state||"up";
    const stlabel=stt==="scanning"?`<span class="spin">⟳</span> ${h.pct||0}%${h.elapsed?" · "+h.elapsed+"s":""}`:stt;
    const stbar=stt==="scanning"?`<div class="hbar"><i style="width:${h.pct||0}%"></i></div>`:"";
    const m=hmap(h);
    const badge = m==="live" ? `<span class="code ${cls(code)}">${esc(String(code))}</span>`
      : m==="resolved" ? `<span class="code c3" title="resolves, no HTTP">DNS</span>`
      : `<span class="code c0" title="enumerated, no DNS">DEAD</span>`;
    const fl=flashHosts.has(h.host)?" flash":"";
    let row=`<tr class="host${fl}" data-h="${esc(h.host)}"><td>${badge}</td>`+
      `<td><span class="host-n">${esc(h.host)}</span></td>`+
      `<td><div class="title">${esc((h.title||"").slice(0,60))}</div>${tech}</td>`+
      `<td>${h.dirs?.length||0}</td><td>${h.params?.length||0}</td>`+
      `<td><b style="color:${(h.score||0)>=12?'var(--warn)':(h.score||0)>=6?'var(--amber)':'var(--faint)'}">${h.score||0}</b></td>`+
      `<td><span class="st ${stt}">${stlabel}</span>${stbar}</td>`+
      `<td class="acts"><button class="btn" data-a="kill">kill</button><button class="btn" data-a="rescan">rescan</button><button class="btn" data-a="nuclei">nuclei</button>${h.shot?`<a class="btn" href="/shot?host=${encodeURIComponent(h.host)}" target="_blank" title="screenshot">📷</a>`:''}<a class="btn" href="${esc(h.url||('https://'+h.host))}" target="_blank">open</a></td></tr>`;
    if(expanded.has(h.host)){
      const dirs=(h.dirs||[]).map(d=>`<div class="dir"><span class="code ${cls(d.code)}">${d.code}</span> ${esc(d.path)} <span style="color:var(--faint)">${d.size??""}</span></div>`).join("")||'<span style="color:var(--faint)">no dirs yet</span>';
      const ps=(h.params||[]).map(p=>`<span class="tech">${esc(p)}</span>`).join("")||'<span style="color:var(--faint)">none</span>';
      row+=`<tr class="exp"><td colspan="8"><div class="grp"><b>dirs (${h.dirs?.length||0}):</b><br>${dirs}</div><div class="grp"><b>params:</b> ${ps}</div></td></tr>`;
    }
    return row;
  }).join("");
  flashHosts.clear();
}
function addFeed(f){
  const d=new Date((f.ts||Date.now()/1000)*1000).toLocaleTimeString();
  const el=document.createElement("div");el.className="fi "+(f.sev||"info");
  el.innerHTML=`<span class="t">${d}</span> ${esc(f.msg)}`;
  feedEl.prepend(el); while(feedEl.children.length>200)feedEl.lastChild.remove();
}
let rafP=null;function scheduleRender(){if(rafP)return;rafP=setTimeout(()=>{rafP=null;renderRows();renderCounts();renderPipe();},200);}

function setPhase(ph){
  const sc=$("#scope");
  if(ph==="idle"){sc.classList.remove("hide");}
  else{sc.classList.add("hide");}
  if(ph==="done"){document.querySelectorAll("#pipe .stg:not(.done)").forEach(e=>{});}
}
function launch(){
  const dom=$("#s_domain").value.trim();
  if(!dom){$("#s_msg").textContent="enter a domain";return;}
  $("#s_go").textContent="◉ launching…";
  fetch("/start",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({domain:dom,cookie:$("#s_cookie").value.trim(),headers:$("#s_headers").value,
      uploadpwn:$("#s_upload").value.trim(),test:$("#s_test").checked,
      uploadpwn_auto:$("#s_upload_auto").checked})})
   .then(r=>r.json()).then(d=>{ if(!d.ok){$("#s_msg").textContent=d.msg||"failed";$("#s_go").textContent="◉ Launch orchestration";}
     else{$("#tgt").textContent=d.msg;setPhase("running");} })
   .catch(e=>{$("#s_msg").textContent=""+e;$("#s_go").textContent="◉ Launch orchestration";});
}
function apply(ev){
  const t=ev.type;
  if(t==="phase"){ST.phase=ev.phase; if(ev.domain)$("#tgt").textContent=ev.domain; setPhase(ev.phase); return;}
  if(t==="snapshot"){ST=ev.state;ST.feed?.forEach(addFeed);setPhase(ST.phase||"idle");scheduleRender();return;}
  if(t==="stage")ST.stages[ev.stage]={state:ev.state,pct:ev.pct??ST.stages[ev.stage]?.pct??0};
  else if(t==="count")ST.counts[ev.key]=ev.value;
  else if(t==="host"){const h=ST.hosts[ev.host]||(ST.hosts[ev.host]={host:ev.host,dirs:[],params:[]});Object.assign(h,ev); if(ev.map==="live"){flashHosts.add(ev.host);ping();}}
  else if(t==="hoststate"){const h=ST.hosts[ev.host]||(ST.hosts[ev.host]={host:ev.host,dirs:[],params:[]});h.state=ev.state;if(ev.elapsed!=null)h.elapsed=ev.elapsed;if(ev.pct!=null)h.pct=ev.pct;}
  else if(t==="dir"){const h=ST.hosts[ev.host]||(ST.hosts[ev.host]={host:ev.host,dirs:[],params:[]});h.dirs.push({path:ev.path,code:ev.code,size:ev.size});flashHosts.add(ev.host);ping();}
  else if(t==="param"){const h=ST.hosts[ev.host]||(ST.hosts[ev.host]={host:ev.host,dirs:[],params:[]});if(!h.params.includes(ev.name))h.params.push(ev.name);ping();}
  else if(t==="hostscore"){const h=ST.hosts[ev.host]||(ST.hosts[ev.host]={host:ev.host,dirs:[],params:[]});h.score=ev.score;}
  else if(t==="finding"){if(ev.host)flashHosts.add(ev.host);ping();}
  else if(t==="feed")addFeed(ev);
  scheduleRender();
}
const es=new EventSource("/events");
es.onmessage=e=>{try{apply(JSON.parse(e.data));}catch(err){}};

function ctl(action,host){fetch("/control",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action,host})});}
rowsEl.addEventListener("click",e=>{
  const b=e.target.closest("button[data-a]");
  if(b){e.stopPropagation();const h=b.closest("tr").dataset.h;ctl(b.dataset.a,h);return;}
  const tr=e.target.closest("tr.host");if(tr){const h=tr.dataset.h;expanded.has(h)?expanded.delete(h):expanded.add(h);renderRows();}
});
$("#stopBtn").onclick=()=>ctl("stop","");
// ---- Lists panel: dump everything discovered, anytime ----
let listType="subs";
function loadList(t){listType=t;
  document.querySelectorAll("#listTabs .t2").forEach(x=>x.classList.toggle("on",x.dataset.t===t));
  $("#listText").value="loading…";
  fetch("/list?type="+t).then(r=>r.text()).then(txt=>{
    $("#listText").value=txt;
    const n=(txt.trim()&&txt!=="(none yet)")?txt.trim().split("\n").length:0;
    $("#listCount").textContent=n+" entries";});}
$("#listsBtn").onclick=()=>{$("#lists").classList.add("on");loadList(listType);};
$("#listClose").onclick=()=>$("#lists").classList.remove("on");
document.querySelectorAll("#listTabs .t2").forEach(x=>x.onclick=()=>loadList(x.dataset.t));
$("#listCopy").onclick=()=>{navigator.clipboard.writeText($("#listText").value);$("#listCopy").textContent="copied";setTimeout(()=>$("#listCopy").textContent="Copy",1000);};
$("#listDownload").onclick=()=>{const blob=new Blob([$("#listText").value],{type:"text/plain"});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="recon-"+listType+".txt";a.click();};
$("#s_go").onclick=launch;
$("#s_domain").addEventListener("keydown",e=>{if(e.key==="Enter")launch();});
$("#q").oninput=e=>{filters.q=e.target.value;renderRows();};
document.querySelectorAll(".chip").forEach(c=>c.onclick=()=>{
  if(c.dataset.s2){const s=c.dataset.s2; filters.surf.has(s)?filters.surf.delete(s):filters.surf.add(s); c.classList.toggle("on");}
  else{const f=c.dataset.f; if(f==="dirs"){filters.dirs=!filters.dirs;c.classList.toggle("on",filters.dirs);}
    else{filters.set.has(f)?filters.set.delete(f):filters.set.add(f);c.classList.toggle("on");}}
  renderRows();});
document.querySelectorAll("th[data-s]").forEach(th=>th.onclick=()=>{filters.sort=th.dataset.s;renderRows();});
setInterval(()=>{const s=Math.floor(Date.now()/1000-(ST.started||Date.now()/1000));$("#elapsed").textContent="⏱ "+Math.floor(s/60)+"m "+(s%60)+"s";},1000);
renderPipe();
</script></body></html>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, ctype, body):
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-cache"); self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())
    def do_GET(self):
        if self.path == "/favicon.ico":
            self._send(204, "image/x-icon", b"")
        elif self.path == "/" or self.path.startswith("/index"):
            self._send(200, "text/html; charset=utf-8", DASH.replace("__DOMAIN__", html.escape(DOMAIN)))
        elif self.path == "/state":
            self._send(200, "application/json", json.dumps(STATE))
        elif self.path.startswith("/list"):
            q = urllib.parse.urlparse(self.path).query
            typ = (urllib.parse.parse_qs(q).get("type", ["live"])[0])
            self._send(200, "text/plain; charset=utf-8", list_text(typ))
        elif self.path.startswith("/shot"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            host = q.get("host", [""])[0]
            sp = STATE["hosts"].get(host, {}).get("shot")
            full = os.path.join(OUT, sp) if sp else ""
            if full and os.path.exists(full):
                self._send(200, "image/png", open(full, "rb").read())
            else:
                self._send(404, "text/plain", "no screenshot")
        elif self.path == "/report":
            try:
                self._send(200, "text/markdown; charset=utf-8", open(os.path.join(OUT, "REPORT.md")).read())
            except Exception:
                self._send(404, "text/plain", "report not generated yet — written at the end of the pipeline")
        elif self.path == "/events":
            self.send_response(200); self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache"); self.send_header("Connection", "keep-alive"); self.end_headers()
            q = queue.Queue(maxsize=1000)
            with buslock:
                subs_q.append(q)
            try:
                self.wfile.write(b"retry: 2000\n\n")
                self.wfile.write(("data: " + json.dumps({"type": "snapshot", "state": STATE}) + "\n\n").encode())
                self.wfile.flush()
                while True:
                    ev = q.get()
                    self.wfile.write(("data: " + json.dumps(ev) + "\n\n").encode()); self.wfile.flush()
            except Exception:
                pass
            finally:
                with buslock:
                    if q in subs_q: subs_q.remove(q)
        else:
            self._send(404, "text/plain", "nope")
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(n) or b"{}") if n else {}
        if self.path == "/control":
            do_action(data.get("action", ""), data.get("host", ""))
            self._send(200, "application/json", b'{"ok":true}')
        elif self.path == "/start":
            hdrs = [h for h in (data.get("headers") or "").splitlines() if h.strip()]
            ok, msg = start_run(data.get("domain", ""), data.get("cookie", ""), hdrs,
                                data.get("uploadpwn") or None, bool(data.get("test", True)),
                                bool(data.get("uploadpwn_auto", False)))
            self._send(200, "application/json", json.dumps({"ok": ok, "msg": msg}))
        else:
            self._send(404, "text/plain", "nope")

def main():
    if A.setup:
        print("[*] recon-live setup — installing/repairing all dependencies…")
        left = bootstrap(install=True, verbose=True, do_apt=True)
        print(f"[+] setup complete. still missing (install manually): {', '.join(left) or 'none'}")
        if not A.domain:
            return
    elif A.autosetup and shutil.which("go"):
        miss = [n for n in GO_TOOLS if not _have(n)]
        if miss:
            print(f"[*] auto-setup: installing {len(miss)} missing go tool(s): {', '.join(miss)}  (disable with --no-autosetup)")
            bootstrap(install=True, verbose=True, do_apt=False)
        apt_miss = [n for n in APT_TOOLS if not _have(n)]
        if apt_miss:
            print(f"[!] not auto-installed (need sudo — run ./setup.sh or --setup): {', '.join(apt_miss)}")
    if not HTTPX:
        print("WARNING: ProjectDiscovery httpx not found in ~/go/bin (python httpx will not work).")
    srv = ThreadingHTTPServer(("127.0.0.1", A.port), H)
    url = f"http://127.0.0.1:{A.port}"
    if A.domain:                                  # CLI scope -> auto-start
        start_run(A.domain, A.cookie, A.header, A.uploadpwn, A.test)
        print(f"\n  recon-live  →  {url}\n  target: {DOMAIN}   out: {OUT}\n")
    else:                                         # no scope -> wait for the page
        STATE["phase"] = "idle"
        print(f"\n  recon-live  →  {url}\n  open the page and enter a scope to begin.\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        do_action("stop", ""); print("\nstopped.")

if __name__ == "__main__":
    main()
