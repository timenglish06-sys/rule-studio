// Panther Rule Studio PoC — vanilla JS, no frameworks, no CDN. All rendering is batched per animation frame.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const uid = () => (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2));

const FIELDS = { "eventName": "The action", "responseElements.ConsoleLogin": "The login result", "userIdentity.userName": "The user",
  "sourceIPAddress": "The source IP address", "awsRegion": "The AWS region" };
const FIELD_TIP = { "eventName": "What the person or system did, for example ConsoleLogin or PutObject.",
  "responseElements.ConsoleLogin": "Whether a console sign-in worked: Success or Failure.", "userIdentity.userName": "Who did it.",
  "sourceIPAddress": "The network address the request came from.", "awsRegion": "Which AWS region the activity happened in." };
const OPS = { equals: "is", not_equals: "is not", contains: "contains", starts_with: "starts with", in: "is one of", in_cidr: "is inside network", not_in_cidr: "is outside network" };
const SEVS = ["Info", "Low", "Medium", "High", "Critical"];
const GROUPS = { "": "Nothing (count everyone together)", "userIdentity.userName": "The same user", "sourceIPAddress": "The same source IP address" };
const TIP = {
  type: "Real-time rules check each event the moment it arrives. Scheduled queries run a search on a timer. Policies check cloud settings.",
  source: "The kind of log data the rule looks at (Panther calls this the log type).",
  severity: "How urgent the alert is. High and Critical usually page someone.",
  threshold: "How many matching events must happen before one alert fires. 1 means alert on the first match.",
  dedup: "Repeat matches inside this window are grouped into one alert instead of many.",
  group: "What counts as 'the same thing' when counting matches toward the threshold.",
  id: "A unique ID Panther uses for the rule, usually Vendor.Service.Behavior.",
  runbook: "One or two sentences telling the analyst what to do when this fires.",
  match: "ALL means every check must be true. ANY means one true check is enough.",
};
const tip = k => `<span class="tip" tabindex="0" data-tip="${esc(TIP[k] || k)}">?</span>`;

const S = { session: uid(), rules: [], sel: null, form: null, rev: 0, out: null, live: null, cache: {},
  feed: { health: "live", message: "", age: 0 }, view: "library", step: 1, kind: "rule", q: "", filter: "All" };
const params = new URLSearchParams(location.search);

// ---------- network: fast lane (coalesced, latest wins) + live lane (debounced) ----------
let inflight = false, pending = false;
function requestPreview() {
  if (inflight) { pending = true; return; }
  inflight = true; const rev = S.rev, t0 = performance.now(), form = S.form;
  fetch("/api/preview", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ form, revision: rev }) })
    .then(r => r.json()).then(r => {
      r.client_ms = Math.max(1, Math.round(performance.now() - t0));
      if (!r.error && rev === S.rev) { S.out = r; if (S.sel && form.id === S.sel && !S.dirty) S.cache[S.sel] = r; paint(); }
    }).catch(() => {}).finally(() => { inflight = false; if (pending) { pending = false; requestPreview(); } });
}
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
const sendDraft = debounce(() => fetch("/api/draft", { method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ session: S.session, form: S.form, revision: S.rev }) }), 300);
function changed(structural) {
  S.rev++; S.liveStale = true; requestPreview(); sendDraft();
  if (structural) renderView(); else paint();
}

// ---------- painting (batched with requestAnimationFrame so typing never janks) ----------
let raf = 0;
function paint() { if (!raf) raf = requestAnimationFrame(() => { raf = 0; paintNow(); }); }
function hlYaml(y) {
  return esc(y).split("\n").map(l => l.replace(/^(\s*-?\s*)([A-Za-z]+):/, '$1<span class="k">$2</span>:')
    .replace(/(&quot;.*&quot;)$/, '<span class="s">$1</span>')).join("\n");
}
function paintNow() {
  const o = S.out, L = S.live, f = S.feed;
  const set = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
  if (o) {
    set("o-eng", esc(o.english));
    set("o-meta", `<span class="fast">⚡ Updated in ${o.client_ms} ms</span><span>English lexicon ${esc(o.lexicon_version)}</span>`);
    set("o-yaml", hlYaml(o.yaml));
    const errs = o.findings.filter(x => x.level === "error").length, warns = o.findings.length - errs;
    set("o-sum", `<span class="${errs ? "s-err" : "s-ok"}">${errs ? "✖ " + errs + " problem" + (errs > 1 ? "s" : "") : "✓ No problems"}</span>` +
      (warns ? `<span class="s-warn">⚠ ${warns} tip${warns > 1 ? "s" : ""}</span>` : "") +
      `<span class="s-ok">✓ ${o.checks.length - new Set(o.findings.map(x => x.check)).size} checks passed</span>`);
    set("o-find", findingsHTML(o, !!document.getElementById("o-full")));
    set("o-tree", treeHTML(o));
  }
  // live panels
  const stale = S.liveStale && (!L || L.revision !== S.rev);
  if (L) {
    set("l-fired", stale ? "…" : L.fired); set("l-matches", stale ? "…" : L.matches); set("l-checked", L.checked.toLocaleString());
    const mx = Math.max(1, ...L.spark);
    set("l-spark", L.spark.map(v => `<i class="${v === mx ? "hi" : ""}" style="height:${Math.max(4, Math.round(100 * v / mx))}%" title="${v} matches"></i>`).join(""));
    set("l-fp", L.fp.length ? L.fp.map(fp => typeof fp === "string" ? `<div class="fp"><span class="i">⚠</span><span>${esc(fp)}</span></div>` :
      `<div class="fp"><span class="i">⚠</span><span>${esc(fp.text)}</span><button class="small" data-ex='${esc(JSON.stringify(fp.exclude))}'>Exclude ${esc(fp.exclude.value)}</button></div>`).join("")
      : `<div class="okmsg">✓ No signs of false positives in the last hour.</div>`);
    set("l-latest", L.latest.length ? `<table class="matches"><tr><th>Time</th><th>What happened</th></tr>${L.latest.map(m => `<tr><td>${m.t}</td><td>${esc(m.summary)}</td></tr>`).join("")}</table>` : `<div class="empty">No matches in the last hour.</div>`);
    if (S.out) set("l-rates", S.out.leaves.map((p, i) => `<tr><td>${esc(cap(p))}</td><td><div class="bar"><i style="width:${Math.min(100, L.leaf_rates[i] ?? 0)}%"></i></div></td><td>${L.leaf_rates[i] ?? 0}%</td></tr>`).join(""));
    set("l-src", `${esc(L.source)}${L.cached ? " · cached" : ""} · last 60 min`);
    $$("[data-ex]").forEach(b => b.onclick = () => { S.form.conditions.push(JSON.parse(b.dataset.ex)); S.dirty = true; toast("Excluded " + JSON.parse(b.dataset.ex).value + " · English and YAML updated"); changed(true); });
  }
  // feed
  const feed = $("#feed"); feed.className = "feed " + f.health;
  $("#feedtxt").textContent = f.health === "live" ? `Live · last event ${f.age}s ago` : f.health === "degraded" ? `Reconnecting · retry in ${f.retry_in}s` : "Offline · using cached data";
  $$(".l-banner").forEach(b => { b.className = "l-banner " + (f.health === "live" ? "" : "banner " + f.health); b.innerHTML = f.health === "live" ? "" : `<span>${f.health === "degraded" ? "⟳" : "⦸"}</span><span>${esc(f.message)}</span>`; });
  $("#outage").textContent = S.outage ? "Restore feed" : "Simulate outage";
}
const cap = s => s.charAt(0).toUpperCase() + s.slice(1);
function findingsHTML(o, full) {
  const failed = new Set(o.findings.map(x => x.check));
  let h = o.findings.map(x => `<div class="find ${x.level}"><div class="ic">${x.level === "error" ? "✖" : "!"}</div><div><div class="t">${esc(x.message)}</div><div class="x">How to fix: ${esc(x.fix)}</div></div>${x.action ? `<button class="small" data-fix="${x.action}">Fix it</button>` : ""}</div>`).join("");
  if (full) h += o.checks.filter(c => !failed.has(c)).map(c => `<div class="find pass"><div class="ic">✓</div><div>${esc(c)}</div></div>`).join("");
  
  return h;
}
function treeHTML(o) {
  const all = (S.form.match || "all") === "all";
  return `<ul class="tree"><li class="root">${all ? "ALL of these must be true" : "ANY one of these is enough"}</li>${o.leaves.map((p, i) =>
    `<li>${S.form.conditions[i]?.negate ? '<span class="pill not">NOT</span>' : ""}${esc(cap(p))}</li>`).join("")}</ul>`;
}
document.addEventListener("click", e => {
  const b = e.target.closest("[data-fix]"); if (!b) return;
  const f = S.form, a = b.dataset.fix;
  if (a === "set_id") f.id = (f.display_name || "Custom Rule").replace(/[^A-Za-z0-9 ]/g, "").split(" ").filter(Boolean).map(cap).join(".").slice(0, 60) || "Custom.Rule";
  if (a === "set_sev") f.severity = "High";
  if (a === "set_group") f.group_by = "userIdentity.userName";
  if (a === "set_dedup") f.dedup_minutes = 15;
  if (a === "set_nums") { f.threshold = Math.max(1, +f.threshold || 1); f.dedup_minutes = Math.max(1, +f.dedup_minutes || 60); }
  if (a === "add_check") f.conditions.push({ field: "eventName", op: "equals", value: "ConsoleLogin" });
  S.dirty = true; toast("Fixed · checks re-ran instantly"); changed(true);
});

// ---------- shared fragments ----------
const engCard = (title = "In plain English") => `<div class="card eng-card"><h3>${title}</h3><p class="eng" id="o-eng">…</p><div class="meta" id="o-meta"></div></div>`;
const yamlCard = () => `<div class="card"><h3>Generated Panther YAML <span class="note">read-only · written for you</span><span class="r"><button class="small" id="copy">Copy</button> <button class="small" id="dl">Download</button></span></h3><pre class="yaml" id="o-yaml"></pre></div>`;
const liveMini = () => `<div class="card"><h3>Live test on recent data <span class="r note" id="l-src"></span></h3><div class="l-banner"></div>
  <div class="kpis"><div class="kpi hl"><div class="v" id="l-fired">–</div><div class="l">alerts it would have fired</div></div>
  <div class="kpi"><div class="v" id="l-matches">–</div><div class="l">matching events</div></div><div class="kpi"><div class="v" id="l-checked">–</div><div class="l">events checked</div></div></div>
  <div class="spark" id="l-spark"></div><div class="note">Matches per minute, last 30 minutes · updates automatically</div><div id="l-fp"></div></div>`;
const sevColor = s => `var(--sev-${SEVS.includes(s) ? s : "Info"})`;

function formHTML(parts) {
  const f = S.form; let h = "";
  if (parts.includes("basics")) h += `
    <div class="field"><label>Rule name</label><input class="w100" data-f="display_name" value="${esc(f.display_name)}" placeholder="e.g. Repeated failed console logins"></div>
    <div class="field"><label>Rule ID ${tip("id")}</label><input class="w100" data-f="id" value="${esc(f.id)}" placeholder="Vendor.Service.Behavior"></div>`;
  if (parts.includes("checks")) h += `
    <div class="field"><label>What should it look for? ${tip("match")}</label>
    <div class="inl" style="margin-bottom:10px"><span>Match</span><div class="seg" data-seg="match">${["all", "any"].map(v => `<button data-v="${v}" class="${(f.match || "all") === v ? "on" : ""}">${v.toUpperCase()}</button>`).join("")}</div><span>of these checks</span></div>
    ${f.conditions.map((c, i) => `${i ? `<div class="join">${(f.match || "all") === "all" ? "AND" : "OR"}</div>` : ""}<div class="cond" data-i="${i}">
      <select data-c="field" title="${esc(FIELD_TIP[c.field] || "")}">${Object.entries(FIELDS).map(([k, v]) => `<option value="${k}" ${k === c.field ? "selected" : ""}>${v}</option>`).join("")}</select>
      <select data-c="op">${Object.entries(OPS).map(([k, v]) => `<option value="${k}" ${k === c.op ? "selected" : ""}>${v}</option>`).join("")}</select>
      <input data-c="value" value="${esc(Array.isArray(c.value) ? c.value.join(", ") : c.value)}" placeholder="${c.op === "in" ? "a, b, c" : c.op.includes("cidr") ? "10.0.0.0/8" : "value"}">
      <label class="negl" title="Flip this check (NOT)"><input type="checkbox" data-c="negate" ${c.negate ? "checked" : ""}>NOT</label>
      <button data-rm="${i}" title="Remove this check">✕</button></div>`).join("")}
    <button class="small" id="addc">＋ Add a check</button></div>`;
  if (parts.includes("alerting")) h += `
    <div class="field"><label>How urgent? ${tip("severity")}</label><div class="seg sev" data-seg="severity">${SEVS.map(v => `<button data-v="${v}" class="${f.severity === v ? "on" : ""}">${v}</button>`).join("")}</div></div>
    <div class="inl" style="gap:22px;align-items:flex-start">
      <div class="field"><label>Alert after ${tip("threshold")}</label><div class="inl"><input type="number" min="1" data-f="threshold" value="${esc(f.threshold)}" style="width:80px"> matches</div></div>
      <div class="field"><label>Within / dedup window ${tip("dedup")}</label><div class="inl"><input type="number" min="1" data-f="dedup_minutes" value="${esc(f.dedup_minutes)}" style="width:80px"> minutes</div></div></div>
    <div class="field"><label>Count matches for ${tip("group")}</label><select class="w100" data-f="group_by">${Object.entries(GROUPS).map(([k, v]) => `<option value="${k}" ${k === (f.group_by || "") ? "selected" : ""}>${v}</option>`).join("")}</select></div>
    <div class="field"><label>What should an analyst do? ${tip("runbook")}</label><input class="w100" data-f="runbook" value="${esc(f.runbook)}" placeholder="e.g. Check whether the user recognizes the attempts."></div>`;
  return h;
}
function bindForm(root) {
  const f = S.form;
  $$("[data-f]", root).forEach(el => el.addEventListener(el.tagName === "SELECT" ? "change" : "input", () => {
    f[el.dataset.f] = ["threshold", "dedup_minutes"].includes(el.dataset.f) ? (el.value === "" ? "" : +el.value) : el.value; S.dirty = true; changed(false); }));
  $$("[data-seg]", root).forEach(seg => $$("button", seg).forEach(b => b.onclick = () => {
    f[seg.dataset.seg] = b.dataset.v; S.dirty = true; changed(seg.dataset.seg === "match"); if (seg.dataset.seg !== "match") { $$("button", seg).forEach(x => x.classList.toggle("on", x === b)); } }));
  $$(".cond", root).forEach(row => { const c = f.conditions[+row.dataset.i];
    $$("[data-c]", row).forEach(el => el.addEventListener(el.type === "checkbox" || el.tagName === "SELECT" ? "change" : "input", () => {
      const k = el.dataset.c; let v = el.type === "checkbox" ? el.checked : el.value;
      if (k === "value" && c.op === "in") v = v.split(",").map(s => s.trim()).filter(Boolean);
      c[k] = v;
      if (k === "op") { if (c.op === "in" && !Array.isArray(c.value)) c.value = String(c.value).split(",").map(s => s.trim()).filter(Boolean); if (c.op !== "in" && Array.isArray(c.value)) c.value = c.value.join(", "); }
      S.dirty = true; changed(false); if (k === "field") el.title = FIELD_TIP[c.field] || ""; })); });
  $$("[data-rm]", root).forEach(b => b.onclick = () => { f.conditions.splice(+b.dataset.rm, 1); S.dirty = true; changed(true); });
  const add = $("#addc", root); if (add) add.onclick = () => { f.conditions.push({ field: "eventName", op: "equals", value: "" }); S.dirty = true; changed(true); setTimeout(() => { const ins = $$(".cond input[data-c=value]"); ins[ins.length - 1]?.focus(); }); };
}

// ---------- views ----------
const V = {};
V.library = () => {
  const rules = S.rules.filter(r => (S.filter === "All" || r.severity === S.filter) && (r.display_name + r.id).toLowerCase().includes(S.q.toLowerCase()));
  const r = S.rules.find(x => x.id === S.sel) || S.rules[0];
  return `<div class="h"><h1>Rule library</h1><p>Step 1 · Pick a rule to see what it does. Use <kbd>↑</kbd> <kbd>↓</kbd> and <kbd>Enter</kbd>.</p></div>
  <div class="grid g-lib"><div class="card"><input class="search" id="q" placeholder="Search rules   ( / )" value="${esc(S.q)}">
    <div class="filters">${["All", "Critical", "High", "Medium", "Low"].map(x => `<button class="chip ${S.filter === x ? "on" : ""}" data-filt="${x}">${x}</button>`).join("")}</div>
    <div class="lib">${rules.map(x => `<div class="item ${x.id === S.sel ? "sel" : ""}" data-id="${x.id}"><span class="n">${esc(x.display_name)}</span><span class="sev" style="background:${sevColor(x.severity)}">${x.severity}</span><span class="m">${esc(x.id)} · AWS CloudTrail</span></div>`).join("") || '<div class="empty">No rules match your search.</div>'}</div>
    <div class="note" style="margin-top:10px">${S.rules.length} rules · bundled sample library</div></div>
  <div class="col"><div class="card"><p class="title">${esc(r.display_name)}</p><div class="badges"><span class="b">Real-time rule</span><span class="b">AWS CloudTrail</span><span class="b" style="color:${sevColor(r.severity)}">● ${r.severity}</span><span class="b">${esc(r.id)}</span></div>
    <div class="inl"><button class="primary" data-go="analyze">Understand it →</button><button data-go="edit">✎ Edit a copy</button><button data-go="validate">✓ Validate</button></div></div>
    ${engCard()}${liveMini()}</div></div>`;
};
V.analyze = () => { const f = S.form; return `<div class="h"><h1>Analyze · ${esc(f.display_name)}</h1><p>Step 2 · A plain breakdown of what this rule does. No code needed.</p></div>
  <div class="grid g2"><div class="col"><div class="card"><h3>What it is</h3><table class="kv">
    <tr><td>Type ${tip("type")}</td><td><b>Real-time rule</b> — checks each event as it arrives</td></tr>
    <tr><td>Watches ${tip("source")}</td><td>AWS CloudTrail (AWS account activity)</td></tr>
    <tr><td>Severity ${tip("severity")}</td><td><span class="sev" style="background:${sevColor(f.severity)};display:inline-block">${esc(f.severity)}</span></td></tr>
    <tr><td>Alert after ${tip("threshold")}</td><td>${esc(f.threshold)} matching event${f.threshold == 1 ? "" : "s"}</td></tr>
    <tr><td>Dedup window ${tip("dedup")}</td><td>${esc(f.dedup_minutes)} minutes</td></tr>
    <tr><td>Counts matches for ${tip("group")}</td><td>${esc(GROUPS[f.group_by || ""])}</td></tr>
    <tr><td>Uses lookup data</td><td>None</td></tr><tr><td>Rule ID ${tip("id")}</td><td><code>${esc(f.id)}</code></td></tr></table></div>
    <div class="card"><h3>How the logic fits together</h3><div id="o-tree"></div></div></div>
  <div class="col">${engCard()}<div class="card"><h3>Checks</h3><div class="sum" id="o-sum"></div><div id="o-find"></div></div>
    <div class="card"><h3>Next</h3><div class="inl"><button class="primary" data-go="edit">✎ Edit &amp; test live →</button><button data-go="live">∿ See live results</button></div></div></div></div>`; };
V.edit = () => `<div class="h"><h1>Edit · ${esc(S.form.display_name || "Untitled rule")}</h1><p>Step 3 · Change anything on the left. English, YAML and live results update instantly.</p></div>
  <div class="grid g-ed"><div class="card" id="form"><h3>Rule settings</h3>${formHTML(["basics", "checks", "alerting"])}<div class="sum" id="o-sum"></div><div id="o-find"></div></div>
  <div class="col">${engCard()}${liveMini()}${yamlCard()}</div></div>`;
const STEPS = [["Type", "What kind of rule"], ["Data source", "Which logs"], ["Look for", "The checks"], ["Alerting", "Urgency & grouping"], ["Review", "Check & save"]];
V.create = () => {
  const st = S.step, f = S.form;
  const bar = `<div class="steps">${STEPS.map(([a, b], i) => `<div data-step="${i + 1}" class="${i + 1 === st ? "on" : i + 1 < st ? "done" : ""}"><b>${i + 1 < st ? "✓" : i + 1}</b><span>${a}<small>${b}</small></span></div>`).join("")}</div>`;
  let left = "";
  if (st === 1) left = `<h3>Step 1 · What kind of rule? ${tip("type")}</h3><div class="cards">
    ${[["rule", "⚡", "Real-time rule", "Checks each event the moment it arrives.", "Example: alert on 5 failed logins in 15 minutes."],
       ["scheduled_query", "⏱", "Scheduled query", "Runs a search on a timer over stored logs.", "Example: daily list of new admin users."],
       ["policy", "☁", "Cloud policy", "Checks how a cloud resource is set up.", "Example: S3 bucket is public."]].map(([k, i, t, d, ex]) =>
      `<div class="pick ${S.kind === k ? "on" : ""} ${k !== "rule" ? "dis" : ""}" data-kind="${k}">${k !== "rule" ? '<span class="soon">After PoC</span>' : ""}<div class="ico">${i}</div><h4>${t}</h4><p>${d}</p><div class="ex">${ex}</div></div>`).join("")}</div>
    <p class="note" style="margin-top:12px">Not sure? Pick <b>Real-time rule</b>. It's the most common kind.</p>`;
  if (st === 2) left = `<h3>Step 2 · Which data should it watch? ${tip("source")}</h3><div class="cards">
    ${[["AWS.CloudTrail", "🟧", "AWS CloudTrail", "Sign-ins and API activity in your AWS accounts."], ["Okta.SystemLog", "🔵", "Okta System Log", "Sign-ins, MFA and admin changes in Okta."], ["GitHub.Audit", "⚫", "GitHub Audit", "Repository and org changes in GitHub."]].map(([k, i, t, d]) =>
      `<div class="pick ${(f.log_types || [])[0] === k ? "on" : ""} ${k !== "AWS.CloudTrail" ? "dis" : ""}" data-src="${k}">${k !== "AWS.CloudTrail" ? '<span class="soon">No sample data</span>' : ""}<div class="ico">${i}</div><h4>${t}</h4><p>${d}</p><div class="ex">Panther log type: ${k}</div></div>`).join("")}</div>`;
  if (st === 3) left = `<h3>Step 3 · The checks</h3>${formHTML(["checks"])}`;
  if (st === 4) left = `<h3>Step 4 · Alerting</h3>${formHTML(["basics", "alerting"])}`;
  if (st === 5) left = `<h3>Step 5 · Review &amp; save</h3><table class="kv" style="margin-bottom:14px"><tr><td>Name</td><td><b>${esc(f.display_name)}</b></td></tr><tr><td>Rule ID</td><td><code>${esc(f.id)}</code></td></tr>
    <tr><td>Type</td><td>Real-time rule</td></tr><tr><td>Watches</td><td>AWS CloudTrail</td></tr><tr><td>Checks</td><td>${f.conditions.length}</td></tr><tr><td>Severity</td><td>${esc(f.severity)}</td></tr></table>
    <div class="sum" id="o-sum"></div><div id="o-find"></div><div class="inl" style="margin-top:12px"><button class="primary" id="dl2">⬇ Download Panther YAML</button><button data-go="edit">Open in editor</button></div>`;
  const right = st <= 2 ? engCard("Your rule so far, in plain English") + yamlCard() : engCard("Your rule so far, in plain English") + liveMini() + yamlCard();
  return `<div class="h"><h1>Create a rule</h1><p>Five short steps. Everything on the right updates as you go.</p></div>${bar}
  <div class="grid g-ed"><div><div class="card" id="form">${left}<div class="nav2"><button ${st === 1 ? "disabled" : ""} id="back">← Back</button><span class="note">Step ${st} of 5</span>${st < 5 ? '<button class="primary" id="next">Next →</button>' : '<span></span>'}</div></div></div><div class="col">${right}</div></div>`;
};
V.validate = () => `<div class="h"><h1>Validate · ${esc(S.form.display_name || "Untitled rule")}</h1><p>Checks the rule against Panther's rules before anyone uploads it.</p></div>
  <div class="grid g2"><div class="card"><h3>Results <span class="r"><button class="small" id="recheck">Re-check</button></span></h3><div class="sum" id="o-sum"></div><div id="o-find"></div><span id="o-full"></span></div>
  <div class="col"><div class="card"><h3>Check with Panther</h3><div class="find"><div class="ic" style="background:var(--bg)">○</div><div><div class="t">Not connected</div><div class="x">An admin can connect a read-only Panther token so this also runs Panther's own upload checks. Your token never reaches the browser.</div></div></div></div>
  ${engCard()}${yamlCard()}</div></div>`;
V.live = () => `<div class="h"><h1>Live analysis · ${esc(S.form.display_name)}</h1><p>Runs by itself in the background on the last 60 minutes of events. No button needed.</p></div>
  <div class="l-banner"></div><div class="grid g2"><div class="col"><div class="card"><h3>If this rule had been on <span class="r note" id="l-src"></span></h3>
    <div class="kpis"><div class="kpi hl"><div class="v" id="l-fired">–</div><div class="l">alerts it would have fired in the last hour</div></div><div class="kpi"><div class="v" id="l-matches">–</div><div class="l">matching events</div></div><div class="kpi"><div class="v" id="l-checked">–</div><div class="l">events checked</div></div></div>
    <div class="spark" id="l-spark"></div><div class="note">Matches per minute, last 30 minutes</div></div>
    <div class="card"><h3>Possible false positives</h3><div id="l-fp"></div></div>${engCard()}</div>
  <div class="col"><div class="card"><h3>Latest matches</h3><div id="l-latest"></div></div><div class="card"><h3>Which checks match most</h3><table class="matches" id="l-rates"></table><div class="note" style="margin-top:8px">A check that is true for most events doesn't narrow the rule much.</div></div></div></div>`;

function renderView() {
  const v = S.view; $("#view").innerHTML = V[v]();
  $$("#nav a").forEach(a => a.classList.toggle("on", a.dataset.v === v));
  const order = ["library", "analyze", "edit"]; $$("#flow li").forEach(li => { const i = order.indexOf(li.dataset.v), c = order.indexOf(v);
    li.classList.toggle("on", li.dataset.v === v); li.classList.toggle("done", c > i); });
  const form = $("#form"); if (form) bindForm(form);
  $$("[data-go]").forEach(b => b.onclick = () => go(b.dataset.go));
  $$("[data-id]").forEach(el => el.onclick = () => select(el.dataset.id));
  $$("[data-filt]").forEach(b => b.onclick = () => { S.filter = b.dataset.filt; renderView(); });
  const q = $("#q"); if (q) q.oninput = debounce(() => { S.q = q.value; renderView(); const n = $("#q"); n.focus(); n.setSelectionRange(n.value.length, n.value.length); }, 60);
  $$("[data-step]").forEach(el => el.onclick = () => { S.step = +el.dataset.step; renderView(); });
  $$("[data-kind]").forEach(el => el.onclick = () => { if (el.classList.contains("dis")) return toast("This PoC builds real-time rules. The others come next."); S.kind = el.dataset.kind; renderView(); });
  $$("[data-src]").forEach(el => el.onclick = () => { if (el.classList.contains("dis")) return toast("No sample data for that source in the PoC yet."); S.form.log_types = [el.dataset.src]; changed(true); });
  const nx = $("#next"), bk = $("#back"); if (nx) nx.onclick = () => { S.step++; renderView(); }; if (bk) bk.onclick = () => { S.step--; renderView(); };
  const cp = $("#copy"); if (cp) cp.onclick = () => { navigator.clipboard?.writeText(S.out?.yaml || ""); toast("YAML copied"); };
  ["#dl", "#dl2"].forEach(id => { const b = $(id); if (b) b.onclick = download; });
  const rc = $("#recheck"); if (rc) rc.onclick = () => changed(false);
  paintNow();
}
function download() { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([S.out?.yaml || ""], { type: "text/yaml" }));
  a.download = (S.form.id || "rule") + ".yml"; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); toast("Saved " + a.download); }
function go(v) { if (v === "create") { newRule(); } S.view = v; history.replaceState(null, "", "#/" + v); renderView(); $("#view").scrollTop = 0; }
function select(id) {
  S.sel = id; S.dirty = false; S.form = structuredClone(S.rules.find(r => r.id === id));
  if (S.cache[id]) { S.out = S.cache[id]; } // instant: prefetched English + YAML
  S.live = null; changed(true);
}
function newRule() {
  S.step = 1; S.kind = "rule"; S.sel = null; S.dirty = true; S.live = null;
  S.form = { id: "Custom.NewRule", display_name: "My new rule", log_types: ["AWS.CloudTrail"], severity: "Medium", threshold: 1, dedup_minutes: 60,
    group_by: "userIdentity.userName", match: "all", conditions: [{ field: "eventName", op: "equals", value: "ConsoleLogin" }], runbook: "" };
  S.rev++; requestPreview(); sendDraft();
}
let tt; function toast(m) { const t = $("#toast"); t.textContent = m; t.hidden = false; clearTimeout(tt); tt = setTimeout(() => t.hidden = true, 1800); }

// ---------- live push (SSE) ----------
function connect() {
  const es = new EventSource("/api/stream?session=" + S.session);
  es.addEventListener("live_result", e => { const r = JSON.parse(e.data); if (r.revision !== S.rev) return; S.live = r; S.liveStale = false; paint(); });
  es.addEventListener("feed_status", e => { S.feed = JSON.parse(e.data); paint(); });
  es.onerror = () => { S.feed = { health: "offline", message: "Lost connection to the app. Reconnecting automatically…", age: 0 }; paint(); };
}

// ---------- keyboard ----------
document.addEventListener("keydown", e => {
  const typing = /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName);
  if (e.key === "Escape") { $("#help").hidden = true; if (typing) document.activeElement.blur(); return; }
  if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
  const k = e.key.toLowerCase();
  if (k === "/") { e.preventDefault(); if (S.view !== "library") go("library"); $("#q")?.focus(); }
  else if (k === "?") $("#help").hidden = false;
  else if (k === "l") go("library"); else if (k === "a") go("analyze"); else if (k === "e") go("edit");
  else if (k === "v") go("validate"); else if (k === "g") go("live"); else if (k === "n") go("create");
  else if ((k === "arrowdown" || k === "arrowup" || k === "j" || k === "k") && S.view === "library") {
    e.preventDefault(); const ids = $$("[data-id]").map(x => x.dataset.id); let i = ids.indexOf(S.sel) + (k === "arrowdown" || k === "j" ? 1 : -1);
    i = Math.max(0, Math.min(ids.length - 1, i)); select(ids[i]);
  } else if (k === "enter" && S.view === "library") go("analyze");
});
$("#helpclose").onclick = () => $("#help").hidden = true;
$$("#nav a, #flow li").forEach(a => a.onclick = () => go(a.dataset.v));
$("#newbtn").onclick = () => go("create");
$("#outage").onclick = async () => { S.outage = !S.outage; await fetch("/api/feed", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ outage: S.outage }) }); paint(); };

// ---------- boot: one request loads the whole library; previews are prefetched so selection is instant ----------
(async () => {
  connect();
  S.rules = await (await fetch("/api/rules")).json();
  await Promise.all(S.rules.map(r => fetch("/api/preview", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ form: r, revision: -1 }) })
    .then(x => x.json()).then(o => { o.client_ms = 1; S.cache[r.id] = o; })));
  const route = (location.hash.replace("#/", "") || "library").split("/");
  select(params.get("rule") || S.rules[0].id);
  if (params.get("demo") === "error") { Object.assign(S.form, { id: "", severity: "Urgent", group_by: "" }); S.dirty = true; S.rev++; requestPreview(); sendDraft(); }
  if (params.get("demo") === "edit") { S.form.conditions.push({ field: "sourceIPAddress", op: "not_in_cidr", value: "10.0.0.0/8" }); S.form.display_name = "Failed console logins from outside the office"; S.dirty = true; S.rev++; requestPreview(); sendDraft(); }
  if (route[0] === "create") { newRule(); S.step = +(route[1] || 1); if (S.step >= 3) { S.form.conditions.push({ field: "responseElements.ConsoleLogin", op: "equals", value: "Failure" }); }
    if (S.step >= 4) { Object.assign(S.form, { display_name: "Failed console logins", id: "AWS.Console.FailedLogins", severity: "High", threshold: 3, dedup_minutes: 30, runbook: "Ask the user if they recognize the sign-in attempts." }); } S.rev++; requestPreview(); sendDraft(); }
  S.view = V[route[0]] ? route[0] : "library";
  if (params.get("outage") === "1") { S.outage = true; fetch("/api/feed", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ outage: true }) }); }
  renderView();
  window.__ready = true;
})();
