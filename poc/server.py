#!/usr/bin/env python3
"""Panther Rule Studio - minimal PoC skeleton (Python stdlib only).

Demonstrates: rule selection (P1), form-driven editing with live English + YAML (P2),
and background live analysis over a simulated CloudTrail stream pushed via SSE (P3).
Not production code: no auth, in-memory only, simplified renderer. Binds to 127.0.0.1.
Run: python3 server.py   then open http://127.0.0.1:8765
"""
import ipaddress, json, queue, random, threading, time, uuid
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HOST, PORT, WINDOW_MIN = "127.0.0.1", 8765, 60
LEXICON_VERSION = "1.0.0-poc"

# ---------------------------------------------------------------- lexicon (data, versioned separately)
LEX = {
    "fields": {
        "eventName": "the action", "responseElements.ConsoleLogin": "the login result",
        "userIdentity.userName": "the user", "sourceIPAddress": "the source IP address",
        "awsRegion": "the AWS region", "userIdentity.type": "the identity type",
    },
    "values": {"Failure": "failed", "Success": "successful", "ConsoleLogin": "a console login", "Root": "the root account"},
    "ops": {  # positive, negative
        "equals": ("is {v}", "is not {v}"), "not_equals": ("is not {v}", "is {v}"),
        "contains": ("contains {v}", "does not contain {v}"), "starts_with": ("starts with {v}", "does not start with {v}"),
        "in": ("is one of {v}", "is not one of {v}"),
        "in_cidr": ("is inside the network range {v}", "is outside the network range {v}"),
        "not_in_cidr": ("is outside the network range {v}", "is inside the network range {v}"),
    },
    "logtypes": {"AWS.CloudTrail": "AWS CloudTrail"},
    "groupby": {"userIdentity.userName": "the same user", "sourceIPAddress": "the same source IP address"},
    "numbers": "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty".split(),
}

def num(n):
    return LEX["numbers"][n] if 0 <= n < len(LEX["numbers"]) else str(n)

def duration(m):
    if m % 1440 == 0: d = m // 1440; return f"{num(d)} day" + ("s" if d > 1 else "")
    if m % 60 == 0: h = m // 60; return f"{num(h)} hour" + ("s" if h > 1 else "")
    return f"{num(m)} minute" + ("s" if m != 1 else "")

def join(items, conj):
    items = [i for i in items if i]
    if len(items) <= 1: return "".join(items)
    if len(items) == 2: return f"{items[0]} {conj} {items[1]}"
    return ", ".join(items[:-1]) + f", {conj} {items[-1]}"   # Oxford comma

def friendly_field(f):
    if f in LEX["fields"]: return LEX["fields"][f]
    import re
    words = re.sub(r"([a-z])([A-Z])", r"\1 \2", f.split(".")[-1]).lower()
    return "the " + words

def friendly_value(v):
    if isinstance(v, list): return join([friendly_value(x) for x in v], "or")
    return LEX["values"].get(str(v), f"“{v}”")

# ---------------------------------------------------------------- renderer: logic tree -> English
def to_tree(form):
    leaves = [{"kind": "cond", **c} for c in form.get("conditions", []) if c.get("field")]
    return {"kind": "group", "op": form.get("match", "all"), "children": leaves}

def phrase(node, negated=False):
    if node["kind"] == "cond":
        neg = negated != bool(node.get("negate"))
        pos, negp = LEX["ops"][node["op"]]
        tpl = negp if neg else pos
        return f"{friendly_field(node['field'])} {tpl.format(v=friendly_value(node['value']))}"
    op = node["op"]
    if negated:  # De Morgan
        op = {"all": "any", "any": "all"}[op]
    parts = [phrase(c, negated) for c in node["children"]]
    if op == "all": return join(parts, "and")
    return ("either " if len(parts) > 1 else "") + join(parts, "or")

def activity(form):
    conds = {c["field"]: c for c in form.get("conditions", []) if c.get("op") == "equals" and not c.get("negate")}
    if form.get("match", "all") == "all" and conds.get("eventName", {}).get("value") == "ConsoleLogin":
        res = conds.get("responseElements.ConsoleLogin", {}).get("value")
        rest = [c for c in form["conditions"] if c["field"] not in ("eventName", "responseElements.ConsoleLogin") or c.get("op") != "equals" or c.get("negate")]
        noun = {"Failure": "failed console logins", "Success": "successful console logins"}.get(res, "console logins")
        return noun, rest, ("fails" if res == "Failure" else "signs in")
    return None, form.get("conditions", []), "matches"

def render_english(form):
    src = join([LEX["logtypes"].get(t, t) for t in form.get("log_types", [])], "and") or "its log source"
    noun, rest, verb = activity(form)
    if noun:
        what = noun
        if rest:
            what += " where " + phrase({"kind": "group", "op": "all", "children": [{"kind": "cond", **c} for c in rest if c.get("field")]})
    else:
        logic = phrase(to_tree(form))
        what = f"events where {logic}" if logic else "every event"
    thr, dd = int(form.get("threshold", 1)), int(form.get("dedup_minutes", 60))
    who = LEX["groupby"].get(form.get("group_by") or "", None)
    if thr <= 1:
        trig = "triggers on the first match"
    elif who:
        trig = f"triggers when {who} {verb} {num(thr)} times within {duration(dd)}"
    else:
        trig = f"triggers after {num(thr)} matching events within {duration(dd)}"
    sev = form.get("severity", "Medium").lower()
    s = (f"This rule watches {src} for {what}, {trig}, and alerts at {sev} severity "
         f"with a {duration(dd).replace(' ', '-').rstrip('s')} dedup window.")
    nxt = (form.get("runbook") or "").strip().split(". ")[0].rstrip(".")
    s += f" Next, an analyst should {nxt[0].lower() + nxt[1:]}." if nxt else " Next, an analyst should review the alert."
    if thr > 1 and not who:
        s += " Note: events from different users are counted together."
    return s

# ---------------------------------------------------------------- generator: form -> Panther Simple Detection YAML
def q(v):
    s = str(v)
    return json.dumps(s) if (not s or any(ch in s for ch in ":#{}[],&*!|>'\"%@`") or s.strip() != s) else s

def render_yaml(form):
    out = ["AnalysisType: rule", f"RuleID: {q(form.get('id','Custom.Rule'))}"]
    if form.get("display_name"): out.append(f"DisplayName: {q(form['display_name'])}")
    out += ["Enabled: true", "LogTypes:"] + [f"  - {t}" for t in form.get("log_types", [])]
    out += [f"Severity: {form.get('severity','Medium')}", f"Threshold: {int(form.get('threshold',1))}",
            f"DedupPeriodMinutes: {int(form.get('dedup_minutes',60))}", "Detection:"]
    op_map = {"equals": "Equals", "not_equals": "DoesNotEqual", "contains": "Contains", "starts_with": "StartsWith",
              "in": "IsIn", "in_cidr": "IsIPAddressInCIDR", "not_in_cidr": "IsIPAddressNotInCIDR"}
    neg_map = {"equals": "DoesNotEqual", "not_equals": "Equals", "contains": "DoesNotContain", "starts_with": "DoesNotStartWith",
               "in": "IsNotIn", "in_cidr": "IsIPAddressNotInCIDR", "not_in_cidr": "IsIPAddressInCIDR"}
    conds = [c for c in form.get("conditions", []) if c.get("field")]
    ind = "  "
    if form.get("match") == "any":
        out.append("  - Any:"); ind = "      "
    for c in conds:
        key = "KeyPath" if "." in c["field"] else "Key"
        cond = (neg_map if c.get("negate") else op_map)[c["op"]]
        first = "- " if ind == "  " else "- "
        out.append(f"{ind}{first}{key}: {c['field']}")
        out.append(f"{ind}  Condition: {cond}")
        if isinstance(c["value"], list):
            out.append(f"{ind}  Values:"); out += [f"{ind}    - {q(v)}" for v in c["value"]]
        else:
            out.append(f"{ind}  Value: {q(c['value'])}")
    if form.get("group_by"):
        out += ["GroupBy:", f"  - KeyPath: {form['group_by']}"]
    if form.get("runbook"): out.append(f"Runbook: {q(form['runbook'])}")
    return "\n".join(out) + "\n"

# ---------------------------------------------------------------- validator (subset)
CHECKS = ["Has a rule ID", "Severity is a Panther level", "Numbers are whole and at least 1",
          "Dedup window is sensible", "Counting is grouped", "Has at least one check"]

def validate(form):
    f = []
    if not form.get("id"): f.append((0, "error", "The rule needs an ID (RuleID).", "Use a name like AWS.Console.FailedLogins.", "set_id"))
    if form.get("severity") not in ("Info", "Low", "Medium", "High", "Critical"):
        f.append((1, "error", "Severity must be Info, Low, Medium, High or Critical.", "Pick one of the five levels.", "set_sev"))
    try:
        thr, dd = int(form.get("threshold", 1) or 0), int(form.get("dedup_minutes", 60) or 0)
    except (TypeError, ValueError):
        thr, dd = 0, 0
    if thr < 1 or dd < 1: f.append((2, "error", "Threshold and dedup window must be at least 1.", "Use whole numbers of 1 or more.", "set_nums"))
    if 0 < dd < 5: f.append((3, "warning", "A dedup window under 5 minutes can flood analysts with alerts.", "Try 15 minutes or more.", "set_dedup"))
    if dd > 1440: f.append((3, "warning", "A dedup window over a day can hide new incidents.", "Keep it to 24 hours or less.", "set_dedup"))
    if thr > 1 and not form.get("group_by"):
        f.append((4, "warning", "Matches are counted across everyone because nothing is grouped.", "Group by the user so one person's activity is counted together.", "set_group"))
    if not [c for c in form.get("conditions", []) if c.get("field") and str(c.get("value", "")).strip()]:
        f.append((5, "error", "The rule has no complete checks, so it would match every event.", "Add at least one check with a value.", "add_check"))
    return [{"check": CHECKS[i], "level": l, "message": m, "fix": x, "action": a} for i, l, m, x, a in f]

# ---------------------------------------------------------------- safe evaluator (no eval/exec)
def get_path(ev, path):
    cur = ev
    for p in path.split("."):
        if not isinstance(cur, dict): return None
        cur = cur.get(p)
    return cur

def eval_cond(c, ev):
    v, val, op = get_path(ev, c["field"]), c["value"], c["op"]
    try:
        if op == "equals": r = v == val
        elif op == "not_equals": r = v != val
        elif op == "contains": r = isinstance(v, str) and str(val) in v
        elif op == "starts_with": r = isinstance(v, str) and v.startswith(str(val))
        elif op == "in": r = v in (val if isinstance(val, list) else [val])
        elif op in ("in_cidr", "not_in_cidr"):
            inside = v is not None and ipaddress.ip_address(v) in ipaddress.ip_network(val, strict=False)
            r = inside if op == "in_cidr" else not inside
        else: r = False
    except ValueError:
        r = False
    return (not r) if c.get("negate") else r

def analyze(form, events):
    conds = [c for c in form.get("conditions", []) if c.get("field")]
    types = set(form.get("log_types", []))
    evs = [e for e in events if e["log_type"] in types]
    if not conds: return None
    hits, leaf_hits = [], Counter()
    combine = all if form.get("match", "all") == "all" else any
    for e in evs:
        rs = [eval_cond(c, e["data"]) for c in conds]
        for i, r in enumerate(rs):
            if r: leaf_hits[i] += 1
        if combine(rs): hits.append(e)
    thr, dd = max(1, int(form.get("threshold", 1))), max(1, int(form.get("dedup_minutes", 60))) * 60
    gb = form.get("group_by")
    buckets, fired = {}, 0
    for e in sorted(hits, key=lambda x: x["t"]):
        k = get_path(e["data"], gb) if gb else "_title"
        b = buckets.get(k)
        if not b or e["t"] - b["start"] > dd:
            b = buckets[k] = {"start": e["t"], "n": 0, "fired": False}
        b["n"] += 1
        if b["n"] >= thr and not b["fired"]:
            b["fired"] = True; fired += 1
    now = time.time()
    spark = [0] * 30
    for e in hits:
        age = int((now - e["t"]) // 60)
        if age < 30: spark[29 - age] += 1
    fp = []
    if hits and evs and len(hits) / len(evs) > 0.05:
        fp.append("This rule matches a lot of normal activity (%d%% of events). It may be too broad." % round(100 * len(hits) / len(evs)))
    users = Counter(get_path(e["data"], "userIdentity.userName") for e in hits)
    if len(hits) >= 5 and users:
        top, n = users.most_common(1)[0]
        if n / len(hits) >= 0.6:
            fp.append({"text": f"{n} of {len(hits)} matches come from {top}. If that's expected (for example a service account), consider excluding it.",
                       "exclude": {"field": "userIdentity.userName", "op": "not_equals", "value": top}})
    for i, c in enumerate(conds):
        if evs and leaf_hits[i] / len(evs) > 0.5 and len(conds) > 1:
            fp.append(f"The check '{phrase({'kind':'cond', **c})}' is true for most events, so it doesn't narrow much.")
    latest = [{"t": time.strftime("%H:%M:%S", time.localtime(e["t"])),
               "summary": f"{get_path(e['data'],'userIdentity.userName')} · {get_path(e['data'],'eventName')} "
                          f"({get_path(e['data'],'responseElements.ConsoleLogin') or 'n/a'}) from {get_path(e['data'],'sourceIPAddress')}"}
              for e in sorted(hits, key=lambda x: -x["t"])[:6]]
    return {"fired": fired, "matches": len(hits), "checked": len(evs), "spark": spark, "fp": fp, "latest": latest,
            "leaf_rates": [round(100 * leaf_hits[i] / max(1, len(evs)), 1) for i in range(len(conds))]}

# ---------------------------------------------------------------- simulated data source (DataSource adapter)
USERS = ["alice", "bob", "carol", "dave", "erin"]
class SimulatedSource:
    name = "Simulated AWS CloudTrail"
    def __init__(self):
        self.window = deque(maxlen=50000)   # sliding window buffer
        self.lock = threading.Lock()
        self.outage = False
        self.health, self.message, self.retry_in, self.last_event = "live", "", 0, time.time()
        self.rng = random.Random(42)
        now = time.time()
        t = now - WINDOW_MIN * 60
        while t < now:                       # backfill the last hour
            self._emit(t); t += self.rng.uniform(1.0, 3.0)
    def _event(self, t):
        r = self.rng.random()
        if r < 0.035:   # noisy service account with failed logins (false-positive bait)
            d = {"eventName": "ConsoleLogin", "userIdentity": {"userName": "svc-backup", "type": "IAMUser"},
                 "responseElements": {"ConsoleLogin": "Failure"}, "sourceIPAddress": "10.1.2.3", "awsRegion": "us-east-1"}
        elif int(t) % 600 < 40 and r < 0.15:   # periodic brute-force burst against alice
            d = {"eventName": "ConsoleLogin", "userIdentity": {"userName": "alice", "type": "IAMUser"},
                 "responseElements": {"ConsoleLogin": "Failure"}, "sourceIPAddress": "203.0.113.7", "awsRegion": "us-east-1"}
        elif r < 0.12:
            d = {"eventName": "ConsoleLogin", "userIdentity": {"userName": self.rng.choice(USERS), "type": "IAMUser"},
                 "responseElements": {"ConsoleLogin": self.rng.choice(["Success"] * 19 + ["Failure"])},
                 "sourceIPAddress": self.rng.choice(["10.0.4.20", "10.0.7.9", "198.51.100.4"]), "awsRegion": "us-east-1"}
        else:
            d = {"eventName": self.rng.choice(["GetObject", "DescribeInstances", "AssumeRole", "PutObject", "ListBuckets"]),
                 "userIdentity": {"userName": self.rng.choice(USERS + ["svc-backup"]), "type": "IAMUser"},
                 "sourceIPAddress": self.rng.choice(["10.0.4.20", "10.0.7.9", "192.0.2.10"]),
                 "awsRegion": self.rng.choice(["us-east-1", "us-east-1", "us-west-2"])}
        return {"log_type": "AWS.CloudTrail", "t": t, "id": uuid.uuid4().hex[:12], "data": d}
    def _emit(self, t):
        with self.lock:
            self.window.append(self._event(t))
            cutoff = time.time() - WINDOW_MIN * 60
            while self.window and self.window[0]["t"] < cutoff: self.window.popleft()
    def snapshot(self):
        with self.lock: return list(self.window)
    def run(self):
        attempt, next_try = 0, 0
        while True:
            time.sleep(0.5)
            if self.outage:                  # simulate an unreachable feed: backoff + retry, then fall back to cached data
                now = time.time()
                if now >= next_try:
                    attempt += 1
                    delay = min(30, 2 * 2 ** attempt) * self.rng.uniform(0.5, 1.0)
                    next_try = now + delay
                self.retry_in = max(0, int(next_try - now))
                if attempt <= 3:
                    self.health = "degraded"
                    self.message = f"We can't reach the live feed right now. Retrying in {self.retry_in} second{'' if self.retry_in == 1 else 's'}. Your edits are safe."
                else:
                    self.health = "offline"
                    self.message = "Live data is off. Showing the last data we received so you can keep working. Your edits still update instantly."
                continue
            attempt, next_try, self.retry_in = 0, 0, 0
            self.health, self.message = "live", ""
            for _ in range(self.rng.choice([0, 1, 1, 2])):
                self._emit(time.time())
            self.last_event = time.time()

SOURCE = SimulatedSource()

# ---------------------------------------------------------------- rule library (P1)
LIBRARY = [
    {"id": "AWS.Console.BruteForceFailedLogins", "display_name": "Repeated failed AWS console logins", "log_types": ["AWS.CloudTrail"],
     "severity": "High", "threshold": 5, "dedup_minutes": 15, "group_by": "userIdentity.userName", "match": "all",
     "conditions": [{"field": "eventName", "op": "equals", "value": "ConsoleLogin"},
                    {"field": "responseElements.ConsoleLogin", "op": "equals", "value": "Failure"}],
     "runbook": "Check whether the user recognizes the attempts. If not, reset the password."},
    {"id": "AWS.Console.LoginOutsideOffice", "display_name": "Console login from outside the office network", "log_types": ["AWS.CloudTrail"],
     "severity": "Medium", "threshold": 1, "dedup_minutes": 60, "group_by": "userIdentity.userName", "match": "all",
     "conditions": [{"field": "eventName", "op": "equals", "value": "ConsoleLogin"},
                    {"field": "responseElements.ConsoleLogin", "op": "equals", "value": "Success"},
                    {"field": "sourceIPAddress", "op": "not_in_cidr", "value": "10.0.0.0/8"}],
     "runbook": "Confirm the user was traveling or on an approved network."},
    {"id": "AWS.S3.ObjectWritesOrBucketListing", "display_name": "S3 object writes or bucket listing", "log_types": ["AWS.CloudTrail"],
     "severity": "Low", "threshold": 1, "dedup_minutes": 60, "group_by": "sourceIPAddress", "match": "any",
     "conditions": [{"field": "eventName", "op": "equals", "value": "PutObject"},
                    {"field": "eventName", "op": "equals", "value": "ListBuckets"}],
     "runbook": ""},
]

# ---------------------------------------------------------------- sessions + background analysis (latest-wins)
SESSIONS = {}  # sid -> {"form", "revision", "dirty", "q"}
SLOCK = threading.Lock()

def analysis_loop():
    last_len = 0
    while True:
        time.sleep(1.0)
        events = SOURCE.snapshot()
        new_data = len(events) != last_len or events and events[-1]["t"] != getattr(analysis_loop, "_last_t", None)
        analysis_loop._last_t = events[-1]["t"] if events else None
        last_len = len(events)
        with SLOCK: items = list(SESSIONS.items())
        for sid, s in items:
            if s.get("form") and (s["dirty"] or new_data):
                rev, form = s["revision"], s["form"]
                s["dirty"] = False
                res = analyze(form, events)
                if res is None: continue
                if rev != s["revision"]: continue          # a newer edit arrived: drop stale result
                res.update(revision=rev, source=SOURCE.name, cached=SOURCE.health != "live")
                push(s, "live_result", res)
            push(s, "feed_status", {"health": SOURCE.health, "message": SOURCE.message, "retry_in": SOURCE.retry_in,
                                    "age": round(time.time() - SOURCE.last_event), "source": SOURCE.name})

def push(s, event, data):
    try: s["q"].put_nowait((event, data))
    except queue.Full: pass

# ---------------------------------------------------------------- HTTP
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/styles.css": ("styles.css", "text/css; charset=utf-8")}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        if n > 256 * 1024: raise ValueError("too large")
        return json.loads(self.rfile.read(n) or b"{}")
    def do_GET(self):
        u = urlparse(self.path); qs = parse_qs(u.query)
        if u.path in STATIC:
            name, ctype = STATIC[u.path]
            b = (Path(__file__).parent / name).read_bytes()
            self.send_response(200); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
            self.end_headers(); self.wfile.write(b)
        elif u.path == "/favicon.ico":
            self.send_response(204); self.end_headers()
        elif u.path == "/api/rules":
            self._json(LIBRARY)
        elif u.path.startswith("/api/rules/"):
            rid = u.path.rsplit("/", 1)[1]
            r = next((x for x in LIBRARY if x["id"] == rid), None)
            self._json(r if r else {"error": {"code": "NOT_FOUND", "message": "No rule with that ID."}}, 200 if r else 404)
        elif u.path == "/api/stream":
            sid = (qs.get("session") or [""])[0]
            with SLOCK:
                s = SESSIONS.setdefault(sid, {"form": None, "revision": 0, "dirty": False, "q": queue.Queue(maxsize=100)})
            self.send_response(200); self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache"); self.end_headers()
            n = 0
            try:
                while True:
                    try:
                        ev, data = s["q"].get(timeout=15)
                    except queue.Empty:
                        ev, data = "heartbeat", {"t": time.time()}
                    n += 1
                    self.wfile.write(f"id: {n}\nevent: {ev}\ndata: {json.dumps(data)}\n\n".encode()); self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self._json({"error": {"code": "NOT_FOUND", "message": "Not found"}}, 404)
    def do_POST(self):
        u = urlparse(self.path)
        try: body = self._body()
        except ValueError: return self._json({"error": {"code": "BAD_REQUEST", "message": "Request body is invalid or too large."}}, 400)
        if u.path == "/api/preview":            # fast lane: pure functions, no I/O
            form = body.get("form", {})
            try:
                t0 = time.perf_counter()
                out = {"revision": body.get("revision"), "english": render_english(form), "yaml": render_yaml(form),
                       "findings": validate(form), "checks": CHECKS, "lexicon_version": LEXICON_VERSION,
                       "leaves": [phrase({"kind": "cond", **c}) for c in form.get("conditions", []) if c.get("field")]}
                out["server_ms"] = round((time.perf_counter() - t0) * 1000, 2)
                self._json(out)
            except (KeyError, ValueError, TypeError) as e:
                self._json({"error": {"code": "INVALID_FORM", "message": "Some fields are incomplete.", "hint": str(e)}}, 422)
        elif u.path == "/api/draft":             # live lane: background analysis picks this up
            sid = body.get("session", "")
            with SLOCK:
                s = SESSIONS.setdefault(sid, {"form": None, "revision": 0, "dirty": False, "q": queue.Queue(maxsize=100)})
                s.update(form=body.get("form"), revision=int(body.get("revision", 0)), dirty=True)
            self._json({"ok": True})
        elif u.path == "/api/feed":              # demo toggle for graceful degradation
            SOURCE.outage = bool(body.get("outage"))
            self._json({"outage": SOURCE.outage})
        else:
            self._json({"error": {"code": "NOT_FOUND", "message": "Not found"}}, 404)

if __name__ == "__main__":
    threading.Thread(target=SOURCE.run, daemon=True).start()
    threading.Thread(target=analysis_loop, daemon=True).start()
    print(f"Panther Rule Studio PoC on http://{HOST}:{PORT}  (simulated data, no auth)")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
