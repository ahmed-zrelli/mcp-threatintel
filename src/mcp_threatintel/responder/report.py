"""Incident report (Markdown) built from the agent's own records.

Facts come only from responder.db: alerts (what was detected, with evidence),
actions (what was proposed, approved, executed, rolled back) and the
append-only audit log (who did what, when). The local model's analyses that
were saved with save_alert_report are added in their own, clearly labelled
section: they are interpretation, not recorded fact.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from .store import ResponderDB

SEV = ["critical", "high", "medium", "low"]

PROBLEM = {
    "c2_connection": "a process communicated with a known command-and-control (C2) server",
    "malicious_dns": "the server resolved a domain listed as malicious",
    "malicious_file": "a file matching a known malware hash was present on disk",
    "malicious_process": "a running process referenced a malicious IP, domain or URL",
    "ssh_bruteforce": "repeated failed SSH logins from one source (password guessing)",
    "ssh_login_from_malicious_ip": "a SUCCESSFUL SSH login came from a known-malicious IP (possible compromise)",
    "ssh_attempt_from_malicious_ip": "SSH login attempts from a known-malicious IP",
    "port_scan": "a host probed many ports of the server (reconnaissance)",
    "reverse_shell": "a shell was controlled over the network (reverse shell: interactive attacker access)",
    "suspicious_process": "a process showed attacker techniques (download-and-execute, temp-folder binary...)",
    "new_listener": "a new network service started listening (possible backdoor / bind shell)",
    "account_user_added": "a new local account was created",
    "account_uid_set_to_0": "an account was given root privileges (uid 0)",
    "account_login_shell_enabled": "a system account was given a login shell",
    "account_privileged_group_member_added": "an account was added to a privileged group",
    "account_password_changed": "an account password was changed",
    "account_sudoers_added": "a sudo rule file was added",
    "account_sudoers_modified": "the sudo configuration was modified",
    "account_ssh_key_added": "an SSH key was added to an account (persistent remote access)",
    "integrity_file_added": "a file was created in a system / persistence location",
    "integrity_file_modified": "a system / persistence file was modified",
}

SOLUTION = {
    "c2_connection": "Identify the binary behind the connection (investigate_host process), remove it and its "
                     "persistence, then check how it was installed. Keep the IP blocked until the host is clean.",
    "malicious_dns": "Find which process resolves the name (investigate_host domain); keep the sinkhole until "
                     "the cause is removed.",
    "malicious_file": "Keep the file in quarantine for analysis; look for how it was dropped (web upload, "
                      "download, SSH session) around its creation time.",
    "malicious_process": "Terminate the process, then remove its executable and any persistence it created.",
    "ssh_bruteforce": "Use key-only SSH (PasswordAuthentication no), fail2ban-style rate limiting, and restrict "
                      "SSH to the admin network.",
    "ssh_login_from_malicious_ip": "Treat the account as compromised: lock it, rotate its password and keys, "
                                   "review its sessions and commands, look for persistence.",
    "ssh_attempt_from_malicious_ip": "Keep the source blocked; verify no attempt succeeded.",
    "port_scan": "Review which services are exposed (ss -ltnp) and close the unnecessary ones; the source "
                 "often comes back with targeted attacks, keep it blocked.",
    "reverse_shell": "Assume interactive compromise: kill the shell, block the remote IP, find the entry point "
                     "(web app, service exploit), check for new accounts, keys, cron jobs and services.",
    "suspicious_process": "Check the command line and its parent process; remove downloaded payloads.",
    "new_listener": "Confirm whether the service is expected; if not, stop it and remove its binary and unit.",
    "account": "Confirm the change with the account owner/administrator; if unexpected, keep the account "
               "locked, remove it and its keys, and review sudo rights.",
    "integrity": "Compare with the package version (dpkg --verify) or a known-good copy; remove unexpected "
                 "cron jobs, units, preload entries; restore the original configuration.",
}


def _solution(kind: str) -> str:
    return SOLUTION.get(kind) or SOLUTION.get(kind.split("_", 1)[0], "Investigate and confirm with the owner.")


def _t(iso: str | None) -> str:
    return (iso or "")[:19].replace("T", " ")


def _md(text) -> str:
    """Attacker-controlled strings (titles, command lines) are shown inertly."""
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ").replace("`", "'")[:300]


def build_report(db: ResponderDB, incident_id: int | None = None, hours: int = 24, *,
                 dry_run: bool | None = None, decision_mode: str | None = None) -> str:
    now = datetime.now(timezone.utc)
    if incident_id:
        inc = db.get_incident(incident_id)
        if not inc:
            raise ValueError(f"no incident {incident_id}")
        incidents = [inc]
        alerts = db.incident_alerts(incident_id)
        scope = f"incident #{incident_id}"
        since = min([a["ts"] for a in alerts] or [inc["opened_at"]])
    else:
        since = (now - timedelta(hours=max(1, int(hours)))).isoformat(timespec="seconds")
        alerts = db.alerts_since(since)
        ids = sorted({a["incident_id"] for a in alerts if a.get("incident_id")})
        incidents = [i for i in (db.get_incident(x) for x in ids) if i]
        scope = f"last {hours} h (since {_t(since)} UTC)"
    action_ids = sorted({i for a in alerts for i in a["action_ids"]})
    actions = {a["id"]: a for a in (db.get_action(i) for i in action_ids) if a}
    for a in db.actions_since(since):  # rollbacks and manual actions in the period
        if not incident_id or a.get("rollback_of") in actions or a["id"] in actions:
            actions.setdefault(a["id"], a)
    audit = [e for e in db.audit_since(since)
             if not incident_id or e.get("action_id") in actions
             or e["details"].get("incident_id") == incident_id
             or e["details"].get("alert_id") in {a["id"] for a in alerts}]

    L: list[str] = []
    L.append("# Security incident report")
    L.append("")
    L.append(f"- Generated: {_t(now.isoformat())} UTC")
    L.append(f"- Scope: {scope}")
    if dry_run is not None:
        L.append(f"- Agent mode: {'DRY-RUN (actions only simulated)' if dry_run else 'real (actions applied)'}")
    if decision_mode:
        L.append(f"- Decision mode: {'AI (local model may execute reversible actions)' if decision_mode == 'ai' else 'human approval'}")
    L.append("- Sources: responder.db alerts, actions and append-only audit log (facts); saved model analyses "
             "(section 7, interpretation)")
    L.append("")

    # 1. summary
    sev = Counter(a["severity"] for a in alerts)
    st = Counter(a["status"] for a in actions.values() if a["type"] != "rollback")
    L.append("## 1. Summary")
    L.append("")
    L.append(f"- Incidents (attacks): **{len(incidents)}**; alerts: **{len(alerts)}** ("
             + ", ".join(f"{s} {sev[s]}" for s in SEV if sev[s]) + ")" if alerts else "- No alert in this period.")
    if actions:
        L.append("- Response actions: " + ", ".join(f"{k} {v}" for k, v in sorted(st.items())))
    blocked = sum(i.get("blocked_attempts") or 0 for i in incidents)
    if blocked:
        L.append(f"- Attempts stopped by existing blocks: {blocked}")
    open_items = [a for a in actions.values() if a["status"] == "pending"]
    if open_items:
        L.append(f"- **Waiting for a decision: {len(open_items)} action(s)** "
                 f"({', '.join('#' + str(a['id']) for a in open_items[:10])})")
    L.append("")

    # 2. timeline
    L.append("## 2. Timeline (UTC)")
    L.append("")
    L.append("| Time | Who | Event |")
    L.append("|---|---|---|")
    events = []
    for a in alerts:
        events.append((a["ts"], 0, "detection", f"ALERT #{a['id']} [{a['severity']}] {_md(a['title'])}"
                       + (f" (seen {a['occurrences']}x)" if (a.get("occurrences") or 1) > 1 else "")))
    labels = {"created": "proposed", "approved": "approved", "rejected": "rejected", "executed": "executed",
              "failed": "FAILED", "rolled_back": "rolled back", "expired": "expired",
              "rollback_requested": "rollback requested", "decision_mode": "decision mode changed",
              "alert_resolved": "alert resolved", "autonomy_recommendation": "AI recommendation for alert",
              "refused_at_creation": "refused by validation",
              "intel_received": "threat intel updated", "alert_report": "AI report saved"}
    for e in audit:
        if e["event"] not in labels:
            continue
        act = actions.get(e.get("action_id"))
        what = f"{labels[e['event']]}"
        if act:
            what += f" action #{act['id']} {act['type']} {_md(act['target'])}"
        d = e["details"]
        if e["event"] == "decision_mode":
            what += f" -> {d.get('mode')}"
        if e["event"] in ("rejected", "failed", "refused_at_creation") and d.get("error"):
            what += f" ({_md(d['error'])[:120]})"
        if e["event"] in ("alert_resolved", "autonomy_recommendation"):
            what += f" #{d.get('alert_id')}: {d.get('decision')}"
        events.append((e["ts"], 1, _md(e["actor"]), what))
    for ts, _rank, who, what in sorted(events)[:300]:
        L.append(f"| {_t(ts)} | {who} | {what} |")
    L.append("")

    # 3. incidents and findings
    L.append("## 3. Incidents and findings")
    L.append("")
    for inc in incidents:
        inc_alerts = [a for a in alerts if a.get("incident_id") == inc["id"]]
        L.append(f"### Incident #{inc['id']} [{inc['severity']}] {_md(inc['title'])}")
        L.append(f"- Opened {_t(inc['opened_at'])}, last activity {_t(inc['last_seen'])}; "
                 f"{inc['alert_count']} alert(s), reopened {inc['reopen_count']} time(s)")
        keys = [k for k in inc.get("keys", []) if k.split(":", 1)[0] in ("ip", "domain", "hash", "user", "path",
                                                                          "family", "port")]
        if keys:
            L.append("- Indicators: " + ", ".join(f"`{_md(k)}`" for k in keys[:15]))
        for a in inc_alerts:
            d = a["detail"]
            source = d.get("ioc") or ("behavior (no feed needed)" if a["kind"] in PROBLEM
                                      and not a["kind"].startswith(("c2_", "malicious_")) else "")
            L.append(f"  - #{a['id']} {_t(a['ts'])} **{a['kind']}**: {_md(a['title'])}"
                     + (f" — source: {_md(source)}" if source else ""))
        L.append("")

    # 4. problems
    L.append("## 4. Problems identified")
    L.append("")
    for kind, n in Counter(a["kind"] for a in alerts).most_common():
        L.append(f"- **{kind}** ({n}x): {PROBLEM.get(kind, kind)}")
    if not alerts:
        L.append("- None.")
    L.append("")

    # 5. response
    L.append("## 5. Response actions and outcome")
    L.append("")
    if actions:
        L.append("| # | Action | Target | Requested by | Decided by | Status | Executed | Expires |")
        L.append("|---|---|---|---|---|---|---|---|")
        for a in sorted(actions.values(), key=lambda x: x["id"]):
            res = a.get("result") or {}
            status = a["status"] + (" (dry-run)" if a["dry_run"] else "")
            if a["status"] in ("rejected", "failed") and res.get("error"):
                status += f": {_md(res['error'])[:80]}"
            L.append(f"| {a['id']} | {a['type']} | {_md(a['target'])[:60]} | {a['requested_by']} | "
                     f"{a.get('approved_by') or '-'} | {status} | {_t(a.get('executed_at')) or '-'} | "
                     f"{_t(a.get('expires_at')) or '-'} |")
    else:
        L.append("- No action.")
    L.append("")

    # 6. solutions
    L.append("## 6. Recommended follow-up")
    L.append("")
    seen = set()
    for a in alerts:
        sol = _solution(a["kind"])
        if sol not in seen:
            seen.add(sol)
            L.append(f"- *{a['kind']}*: {sol}")
    if open_items:
        L.append(f"- Decide the {len(open_items)} pending action(s) on the dashboard.")
    if not alerts:
        L.append("- Nothing to do.")
    L.append("")

    # 7. model analysis
    reports = [a for a in alerts if a.get("report") or (a.get("resolution_by") or "").startswith("qwen")]
    L.append("## 7. AI analysis (local model — interpretation, verify against sections 2-5)")
    L.append("")
    if not reports:
        L.append("- No model analysis was requested for these alerts.")
    for a in reports:
        L.append(f"### Alert #{a['id']} — analysed by {a.get('report_by') or a.get('resolution_by')} "
                 f"at {_t(a.get('report_at') or a.get('resolution_at'))}")
        if a.get("resolution"):
            L.append(f"Decision: **{a['resolution']}** — {_md(a.get('resolution_note'))}")
        if a.get("report"):
            L.append("")
            for line in str(a["report"]).splitlines():
                L.append("> " + line.replace("<", "&lt;"))
        L.append("")

    # 8. audit
    L.append("## 8. Audit trail")
    L.append("")
    L.append(f"- {len(audit)} audit record(s) in scope. The audit log is append-only: the database refuses "
             f"any update or deletion (SQLite triggers).")
    return "\n".join(L) + "\n"
