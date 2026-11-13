"""The dashboard page (single file: HTML, CSS, JS). Every value from the agent is
inserted with textContent, never as HTML: titles, command lines and log lines are
attacker-controlled."""

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ThreatIntel Console</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--ink:#16191d;--muted:#5d6670;--line:#e2e5e9;--accent:#2457d6;
--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#4b5563;--ok:#15803d;--chip:#eef1f5;--shadow:0 1px 2px rgba(0,0,0,.06)}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--panel:#171b21;--ink:#e6e9ed;--muted:#97a1ad;--line:#2a3039;
--accent:#7aa2ff;--crit:#ff7b72;--high:#ffa657;--med:#e3b341;--low:#9ca3af;--ok:#56d364;--chip:#222833;--shadow:none}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;padding:14px 20px;
background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
h1{font-size:17px;margin:0;font-weight:650}h2{font-size:14px;margin:0 0 10px;font-weight:650;display:flex;gap:8px;align-items:center}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(420px,1fr));gap:16px;padding:16px 20px;max-width:1600px;margin:0 auto}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;box-shadow:var(--shadow);min-width:0}
section.wide{grid-column:1/-1}
.status{display:flex;flex-wrap:wrap;gap:8px;align-items:center;color:var(--muted);font-size:13px}
.chip{background:var(--chip);border-radius:999px;padding:2px 10px;font-size:12px;white-space:nowrap}
.chip.real{background:var(--crit);color:#fff}.chip.dry{background:var(--ok);color:#fff}
.switch{display:inline-flex;border:1px solid var(--line);border-radius:8px;overflow:hidden}
.switch button{border:0;border-radius:0;background:transparent;color:var(--ink);padding:6px 14px;cursor:pointer;font:inherit}
.switch button.on{background:var(--accent);color:#fff}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px}td.wrap{word-break:break-word}
.sev{font-weight:650;text-transform:uppercase;font-size:11px;letter-spacing:.03em}
.sev.critical{color:var(--crit)}.sev.high{color:var(--high)}.sev.medium{color:var(--med)}.sev.low{color:var(--low)}
button.b{font:inherit;font-size:12px;padding:4px 10px;border-radius:6px;border:1px solid var(--line);background:var(--panel);color:var(--ink);cursor:pointer}
button.b:hover{border-color:var(--accent)}button.ok{background:var(--accent);border-color:var(--accent);color:#fff}
button.warn{color:var(--crit)}
.muted{color:var(--muted)}.empty{color:var(--muted);padding:8px 0}
.row{cursor:pointer}.row:hover td{background:var(--chip)}
pre{white-space:pre-wrap;word-break:break-word;background:var(--chip);padding:10px;border-radius:8px;font-size:12px;max-height:60vh;overflow:auto;margin:6px 0}
dialog{border:1px solid var(--line);border-radius:12px;background:var(--panel);color:var(--ink);width:min(900px,94vw);padding:18px}
dialog::backdrop{background:rgba(0,0,0,.45)}
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
input{font:inherit;padding:4px 8px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:var(--ink);width:90px}
#err{color:var(--crit);font-size:12px}
.scroll{max-height:420px;overflow:auto}
@media (max-width:520px){main{grid-template-columns:1fr;padding:12px}header{padding:12px}}
</style>
</head>
<body>
<header>
  <div><h1>ThreatIntel Console</h1><div class="status" id="status">connecting to the agent...</div></div>
  <div class="status">
    <span>Who decides</span>
    <div class="switch"><button id="mode-human">Human</button><button id="mode-ai">AI</button></div>
    <span id="err"></span>
  </div>
</header>
<main>
  <section><h2>Pending actions <span class="chip" id="n-pending">0</span></h2><div id="pending"></div></section>
  <section><h2>Active responses <span class="chip" id="n-active">0</span></h2><div id="active" class="scroll"></div></section>
  <section class="wide"><h2>Incidents (one per attack)</h2><div id="incidents" class="scroll"></div></section>
  <section class="wide"><h2>Alerts <span class="muted">— click one for evidence and AI analysis</span></h2><div id="alerts" class="scroll"></div></section>
  <section><h2>Live SSH activity <span class="muted">(last 15 min)</span></h2><div id="ssh"></div></section>
  <section><h2>Port scans <span class="muted">(last hour)</span></h2><div id="scans"></div></section>
  <section class="wide"><h2>Incident report</h2>
    <div class="controls">Incident # <input id="r-inc" type="number" min="0" placeholder="all"> or last
      <input id="r-hours" type="number" min="1" value="24"> hours
      <button class="b ok" id="r-go">Generate</button><button class="b" id="r-dl" disabled>Download .md</button></div>
    <pre id="report" class="muted">Facts from the agent's records (alerts, actions, audit log) plus the saved AI analyses, labelled.</pre>
  </section>
  <section class="wide"><h2>Audit trail <span class="muted">(append-only)</span></h2><div id="audit" class="scroll"></div></section>
</main>
<dialog id="dlg"><div id="dlg-body"></div><div style="text-align:right;margin-top:10px"><button class="b" id="dlg-close">Close</button></div></dialog>
<script>
"use strict";
const TOKEN = "__TOKEN__";
const REVERSIBLE = new Set(["block_ip","sinkhole_domain","quarantine_file","block_feed_c2","lock_user"]);
let mode = null, reportText = "";

async function api(path, opts = {}) {
  const r = await fetch(path, {...opts, headers: {"X-Dashboard-Token": TOKEN, "Content-Type": "application/json"}});
  const j = await r.json().catch(() => ({error: "bad response"}));
  if (!r.ok || (j && j.error && typeof j.error === "string" && !Array.isArray(j))) throw new Error(j.error || r.status);
  return j;
}
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) { if (k === null || k === undefined) continue; e.append(k instanceof Node ? k : document.createTextNode(String(k))); }
  return e;
}
const $ = id => document.getElementById(id);
const t = iso => iso ? String(iso).slice(0, 19).replace("T", " ") : "-";
function left(iso) {
  if (!iso) return "no expiry";
  const s = Math.round((new Date(iso) - new Date()) / 1000);
  if (s <= 0) return "expiring";
  const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60);
  return h ? `${h} h ${m} min left` : `${m} min ${s % 60} s left`;
}
function table(headers, rows) {
  if (!rows.length) return el("div", {class: "empty"}, "Nothing here.");
  return el("table", {}, el("thead", {}, el("tr", {}, headers.map(h => el("th", {}, h)))), el("tbody", {}, rows));
}
function sev(s) { return el("span", {class: "sev " + s}, s); }
function err(e) { $("err").textContent = e ? String(e.message || e) : ""; }

async function doAction(id, verb) {
  let body = {};
  if (verb === "reject") { const r = prompt(`Reject action #${id}: reason?`, "false positive"); if (r === null) return; body.reason = r; }
  if (verb === "rollback" && !confirm(`Undo action #${id}?`)) return;
  try { await api(`/api/actions/${id}/${verb}`, {method: "POST", body: JSON.stringify(body)}); err(); refresh(); }
  catch (e) { err(e); }
}
async function setMode(m) {
  if (m === mode) return;
  if (m === "ai" && !confirm("AI mode: when you ask the local model to investigate an alert, it may EXECUTE that alert's reversible actions itself (block IP, sinkhole, quarantine). It never starts on its own. Continue?")) return;
  try { await api("/api/mode", {method: "POST", body: JSON.stringify({mode: m})}); err(); refresh(); } catch (e) { err(e); }
}

function renderStatus(s) {
  const st = $("status"); st.replaceChildren();
  st.append(el("span", {class: "chip " + (s.dry_run ? "dry" : "real")}, s.dry_run ? "DRY-RUN" : "REAL MODE"));
  const n = s.indicators_indexed || {};
  const total = Object.values(n).reduce((a, b) => a + (typeof b === "number" ? b : 0), 0);
  st.append(el("span", {class: "chip"}, `${total} indicators`));
  st.append(el("span", {class: "chip"}, `intel ${s.intel && s.intel.received_at ? "updated " + t(s.intel.received_at) : "not pushed yet"}`));
  st.append(el("span", {class: "chip"}, `last scan ${t(s.last_detection_run)}`));
  st.append(el("span", {class: "chip"}, `behavior: ${s.behavior_monitor}`));
  if (s.detection_error) st.append(el("span", {class: "chip warn"}, "detection error: " + s.detection_error));
  mode = s.decision && s.decision.mode;
  $("mode-human").classList.toggle("on", mode === "human");
  $("mode-ai").classList.toggle("on", mode === "ai");
}
function renderPending(list) {
  $("n-pending").textContent = list.length;
  $("pending").replaceChildren(table(["#", "Action", "Target", "Why", ""], list.map(a => el("tr", {},
    el("td", {}, a.id), el("td", {}, a.type, a.dry_run ? el("div", {class: "muted"}, "dry-run") : null),
    el("td", {class: "wrap"}, a.target), el("td", {class: "wrap muted"}, (a.reason || "").slice(0, 220), el("div", {}, "by " + a.requested_by)),
    el("td", {}, el("button", {class: "b ok", onclick: () => doAction(a.id, "approve")}, "Approve"), " ",
                 el("button", {class: "b warn", onclick: () => doAction(a.id, "reject")}, "Reject"))))));
}
function renderActive(list) {
  $("n-active").textContent = list.length;
  $("active").replaceChildren(table(["#", "Action", "Target", "Time left", ""], list.map(a => el("tr", {},
    el("td", {}, a.id), el("td", {}, a.type, a.dry_run ? el("div", {class: "muted"}, "dry-run") : null),
    el("td", {class: "wrap"}, a.target), el("td", {class: "muted"}, left(a.expires_at), el("div", {}, "by " + (a.approved_by || "-"))),
    el("td", {}, REVERSIBLE.has(a.type) ? el("button", {class: "b", onclick: () => doAction(a.id, "rollback")}, "Rollback") : el("span", {class: "muted"}, "irreversible"))))));
}
function renderIncidents(list) {
  $("incidents").replaceChildren(table(["#", "Severity", "Attack", "State", "Alerts", "Last activity"], list.map(i => el("tr", {},
    el("td", {}, i.id), el("td", {}, sev(i.severity)), el("td", {class: "wrap"}, i.title),
    el("td", {}, i.open ? el("span", {class: "sev high"}, "open") : el("span", {class: "muted"}, "handled")),
    el("td", {}, i.alert_count + (i.reopen_count ? ` (reopened ${i.reopen_count}x)` : "") + (i.blocked_attempts ? `, ${i.blocked_attempts} blocked` : "")),
    el("td", {class: "muted"}, t(i.last_seen))))));
}
function renderAlerts(list) {
  $("alerts").replaceChildren(table(["#", "Time", "Severity", "Alert", "Incident", "Actions", "AI"], list.map(a => el("tr", {class: "row", onclick: () => openAlert(a.id)},
    el("td", {}, a.id), el("td", {class: "muted"}, t(a.ts)), el("td", {}, sev(a.severity)),
    el("td", {class: "wrap"}, a.title, a.occurrences > 1 ? el("span", {class: "muted"}, ` (seen ${a.occurrences}x)`) : null),
    el("td", {}, a.incident_id ? `#${a.incident_id} ${a.incident_event || ""}` : "-"),
    el("td", {class: "muted"}, (a.actions || []).map(x => `#${x.id} ${x.type} ${x.status}`).join(", ") || "-"),
    el("td", {class: "muted"}, a.report ? "report" : (a.resolution || "-"))))));
}
function renderScans(list) {
  $("scans").replaceChildren(table(["Time", "Source", "Ports", "Note"], list.slice().reverse().map(s => el("tr", {},
    el("td", {class: "muted"}, t(new Date(s.observed_at * 1000).toISOString())), el("td", {}, s.src_ip),
    el("td", {}, `${s.distinct_ports} in ${s.window_s}s`, el("div", {class: "muted wrap"}, (s.sample_ports || []).join(", "))),
    el("td", {class: "muted"}, s.allowlisted ? "allowlisted (not blocked)" : "")))));
}
function renderAudit(list) {
  $("audit").replaceChildren(table(["Time", "Who", "Event", "Action", "Details"], list.map(e => el("tr", {},
    el("td", {class: "muted"}, t(e.ts)), el("td", {}, e.actor), el("td", {}, e.event), el("td", {}, e.action_id || "-"),
    el("td", {class: "wrap muted"}, JSON.stringify(e.details).slice(0, 240))))));
}
async function openAlert(id) {
  try {
    const a = await api(`/api/alerts/${id}`);
    const body = $("dlg-body"); body.replaceChildren();
    body.append(el("h2", {}, sev(a.severity), `Alert #${a.id}: ${a.title}`));
    body.append(el("div", {class: "muted"}, `${t(a.ts)} — ${a.kind}` + (a.incident_id ? ` — incident #${a.incident_id} (${a.incident_event})` : "")));
    body.append(el("h2", {style: "margin-top:12px"}, "Actions"));
    body.append(table(["#", "Action", "Target", "Status"], (a.actions || []).map(x => el("tr", {}, el("td", {}, x.id), el("td", {}, x.type), el("td", {class: "wrap"}, x.target), el("td", {}, x.status + (x.error ? ": " + x.error : ""))))));
    body.append(el("h2", {style: "margin-top:12px"}, "AI analysis (local model)"));
    if (a.report) body.append(el("pre", {}, a.report));
    else body.append(el("div", {class: "muted"}, "Not investigated yet. In the llama-server WebUI, ask: ",
      el("code", {}, `Investigate alert ${a.id}`), " ", el("button", {class: "b", onclick: () => navigator.clipboard.writeText(`Investigate alert ${a.id}`)}, "Copy")));
    if (a.resolution) body.append(el("div", {}, `Decision: ${a.resolution} by ${a.resolution_by || "-"} — ${a.resolution_note || ""}`));
    body.append(el("h2", {style: "margin-top:12px"}, "Evidence"));
    body.append(el("pre", {}, JSON.stringify(a.detail, null, 2)));
    $("dlg").showModal();
  } catch (e) { err(e); }
}
async function refresh() {
  try {
    const o = await api("/api/overview");
    renderStatus(o.status); renderPending(o.pending); renderActive(o.active); renderIncidents(o.incidents);
    renderAlerts(o.alerts); renderScans(o.port_scans || []); renderAudit(o.audit); err();
  } catch (e) { err(e); $("status").textContent = "agent unreachable"; }
}
async function refreshSsh() {
  try {
    const s = await api("/api/ssh?minutes=15");
    $("ssh").replaceChildren(el("div", {class: "muted", style: "margin-bottom:6px"}, `${s.lines_read} log lines (${s.log_source})`),
      table(["Source IP", "Failed", "Accepted", "Users", ""], (s.details || []).map(d => el("tr", {},
        el("td", {}, d.ip), el("td", {}, d.failures), el("td", {}, d.accepted), el("td", {class: "wrap muted"}, (d.users_tried || []).join(", ")),
        el("td", {}, d.known_malicious ? sev("high") : null, d.brute_force ? el("span", {class: "sev medium"}, " brute force") : null)))));
  } catch (e) { $("ssh").textContent = String(e.message || e); }
}
$("mode-human").onclick = () => setMode("human");
$("mode-ai").onclick = () => setMode("ai");
$("dlg-close").onclick = () => $("dlg").close();
$("r-go").onclick = async () => {
  const inc = $("r-inc").value, hours = $("r-hours").value || 24;
  $("report").textContent = "Generating...";
  try {
    const r = await api(`/api/report?hours=${encodeURIComponent(hours)}` + (inc && inc !== "0" ? `&incident_id=${encodeURIComponent(inc)}` : ""));
    reportText = r.markdown; $("report").textContent = reportText; $("report").classList.remove("muted"); $("r-dl").disabled = false;
  } catch (e) { $("report").textContent = String(e.message || e); }
};
$("r-dl").onclick = () => {
  const a = el("a", {href: URL.createObjectURL(new Blob([reportText], {type: "text/markdown"})), download: `incident-report-${Date.now()}.md`});
  document.body.append(a); a.click(); a.remove();
};
refresh(); refreshSsh();
setInterval(refresh, 3000); setInterval(refreshSsh, 10000);
</script>
</body>
</html>
"""
