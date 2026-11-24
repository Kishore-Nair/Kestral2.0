# ruff: noqa: E501 - this module is an HTML template; long markup lines are intentional
"""Render the Guardian report as one self-contained, printable HTML file (logo embedded).

Every value from scans, repositories, advisories or models is HTML-escaped. The file has no
external requests, so it can be emailed, archived or printed to PDF from any browser.
"""

import base64
from functools import cache
from html import escape
from pathlib import Path

LOGO = Path(__file__).resolve().parent / "assets" / "kestral-logo.jpg"
MAX_ROWS = 60

VERDICT_LABEL = {
    "FIXED": "Fix verified",
    "FIXED_WITH_NEW_RISK": "Fixed, new risk introduced",
    "FIXED_TESTS_FAILED": "Fixed, tests regressed",
    "NOT_FIXED": "Not fixed",
    "FAILED": "Validation failed",
    "UNSUPPORTED": "Unsupported",
}


@cache
def logo_data_uri() -> str:
    data = base64.b64encode(LOGO.read_bytes()).decode("ascii")
    return f"data:image/jpeg;base64,{data}"


def e(value) -> str:
    if value is None or value == "":
        return '<span class="muted">—</span>'
    if isinstance(value, list):
        return escape(", ".join(str(v) for v in value)) if value else '<span class="muted">—</span>'
    return escape(str(value))


def badge(text: str | None, tone: str = "neutral") -> str:
    if not text:
        return ""
    return f'<span class="badge {tone}">{escape(str(text))}</span>'


def band_badge(band: str | None) -> str:
    tone = {"critical": "crit", "high": "high", "medium": "med", "low": "low"}.get(
        band or "", "neutral"
    )
    return badge(band, tone)


def verdict_badge(verdict: str | None) -> str:
    tone = {
        "FIXED": "good",
        "FIXED_WITH_NEW_RISK": "med",
        "FIXED_TESTS_FAILED": "med",
        "NOT_FIXED": "crit",
        "FAILED": "crit",
    }.get(verdict or "", "neutral")
    return badge(VERDICT_LABEL.get(verdict or "", verdict), tone)


def table(headers: list[str], rows: list[list[str]], empty: str) -> str:
    if not rows:
        return f'<p class="muted">{escape(empty)}</p>'
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def capped(headers, rows, empty, label) -> str:
    if len(rows) <= MAX_ROWS:
        return table(headers, rows, empty)
    return (
        table(headers, rows[:MAX_ROWS], empty)
        + f"<details><summary>Show the remaining {len(rows) - MAX_ROWS} {escape(label)}</summary>"
        + table(headers, rows[MAX_ROWS:], empty)
        + "</details>"
    )


def stat(label: str, value) -> str:
    return f'<div class="stat"><div class="v">{e(value)}</div><div class="l">{escape(label)}</div></div>'


def render_html(report: dict) -> str:
    scan = report["scan"]
    summary = report["summary"]
    bands = summary["vulnerability_bands"]
    vulns = report["findings"]["vulnerabilities"]
    suspicious = report["findings"]["suspicious"]
    pins = report["findings"]["workflow_pins"]

    vuln_rows = [
        [
            f"<strong>{e(f['package'])}</strong><br><span class='muted small'>{e(f['title'])}</span>",
            band_badge(f["band"])
            + (
                f"<br><span class='small'>{e(f['priority'])}</span>"
                if f["priority"] is not None
                else ""
            ),
            e(f["cvss"])
            + (
                f" <span class='muted small'>{e(f['cvss_severity'])}</span>"
                if f["cvss_severity"]
                else ""
            ),
            e(", ".join([*f["cves"][:2], *f["cwes"][:2]])),
            e(f["directness"]),
            e(f["fixed_versions"]),
            "<br>".join(e(p) for p in f["dependency_paths"][:2]) or e(None),
        ]
        for f in vulns
    ]
    suspicious_rows = [
        [
            f"<strong>{e(f['package'])}</strong><br><span class='muted small'>{e(f['title'])}</span>",
            badge((f["category"] or "").replace("_", " "), "neutral"),
            band_badge(f["band"]),
            e(f["risk_reason"]),
            "<br>".join(e(x) for x in f["evidence"][:2]),
        ]
        for f in suspicious
    ]
    pin_rows = [
        [e(f["package"]), e(f["title"]), "<br>".join(e(x) for x in f["evidence"][:1])] for f in pins
    ]

    proposals = report["actions"]["remediation_proposals"]
    proposal_rows = []
    for p in proposals:
        d = p.get("decision") or {}
        proposal_rows.append(
            [
                f"<strong>{e(p['subject_label'])}</strong><br><span class='small'>{e(p['recommendation'])}</span>",
                badge(p["action"]),
                badge(
                    p["status"],
                    {"APPROVED": "good", "REJECTED": "crit"}.get(p["status"], "neutral"),
                ),
                e(d.get("decided_by")),
                e(d.get("reason")),
            ]
        )
    ai_rows = [
        [
            f"<strong>{e(a['title'])}</strong><br><span class='muted small'>{e(a['summary'])}</span>",
            e(f"{a['strategy'] or ''} {a['target_version'] or ''}".strip()),
            badge("fixed version verified", "good")
            if a["fixed_version_verified"]
            else badge("not verified", "med"),
            e(a["status"]),
            e((a["decision"] or "pending").replace("_", " ")),
            e(a["model"]),
        ]
        for a in report["actions"]["ai_recommendations"]
    ]

    validation_blocks = []
    for v in report["validations"]:
        change = v["change"]
        result = v.get("result") or {}
        comparison = result.get("comparison") or {}
        steps = "".join(
            f"<li>{badge(s['status'], {'passed': 'good', 'failed': 'crit', 'warning': 'med'}.get(s['status'], 'neutral'))} "
            f"<strong>{e(s['label'])}</strong> — {e(s['detail'])}</li>"
            for s in result.get("steps", [])
        )
        diffs = "".join(
            f"<details><summary><code>{e(d['path'])}</code> +{d['lines_added']} −{d['lines_removed']}"
            f"{' (truncated)' if d['truncated'] else ''}</summary><pre>{escape(d['diff'])}</pre></details>"
            for d in result.get("diffs", [])
        )
        tests = "".join(
            f"<li>{e(t['phase'])}: {badge(t['status'], {'passed': 'good', 'failed': 'crit'}.get(t['status'], 'neutral'))} "
            f"{e(t.get('command'))} <span class='muted small'>{e(t.get('runtime'))} {e(t.get('image'))}</span></li>"
            for t in result.get("tests", [])
        )
        before, after = comparison.get("before_counts", {}), comparison.get("after_counts", {})
        count_rows = [
            [escape(k.replace("_", " ")), e(before.get(k)), e(after.get(k))]
            for k in ("critical", "high", "medium", "low", "suspicious", "workflow_pins")
        ]
        resolved = comparison.get("resolved", [])
        introduced = comparison.get("introduced", [])
        validation_blocks.append(
            f"""
<div class="card avoid-break">
  <div class="row"><h3>{e(change["package"])} {e(change["from_version"])} → {e(change["to_version"])}</h3>
  {verdict_badge(result.get("verdict")) if result else badge(v["status"])}</div>
  <p class="small muted">Validation {e(v["validation_id"])} · source: {e(change["source_type"])} {e(change["source_id"])}
  · approved by {e(change["approved_by"])} · finished {e(v["finished_at"])}</p>
  <p>{e(result.get("verdict_reason") or v.get("error"))}</p>
  <h4>Steps</h4><ul class="steps">{steps or '<li class="muted">No steps recorded</li>'}</ul>
  <h4>Proposed change (diff)</h4>{diffs or '<p class="muted">No file changes</p>'}
  <h4>Build and tests</h4><ul class="steps">{tests or '<li class="muted">Not run</li>'}</ul>
  <p class="small">{e(result.get("tests_detail"))}</p>
  <h4>Before / after risk</h4>
  {table(["Category", "Before", "After"], count_rows, "No comparison")}
  <p class="small">Target finding resolved: <strong>{e({True: "yes", False: "no", None: "n/a"}[comparison.get("target_resolved")])}</strong>
  · {len(resolved)} findings resolved · {len(introduced)} introduced
  · package changes: {e(", ".join(f"{k} {n}" for k, n in comparison.get("package_changes", {}).items() if n))}</p>
  {('<p class="small"><strong>Changed packages:</strong> ' + e(comparison.get("changed_packages", [])[:12]) + "</p>") if comparison.get("changed_packages") else ""}
  <h4>Remaining risk after this change</h4>
  <ul class="small">{"".join(f"<li>{e(r)}</li>" for r in result.get("residual_risks", [])) or '<li class="muted">None recorded</li>'}</ul>
</div>"""
        )

    remaining_rows = [
        [e(r["package"]), e(r["title"]), band_badge(r["band"]), e(r["state"]), e(r["reviewer"])]
        for r in report["remaining_risks"]
        if r["state"] != "Open" or r["band"] in ("critical", "high")
    ]
    open_lower = sum(
        1
        for r in report["remaining_risks"]
        if r["state"] == "Open" and r["band"] not in ("critical", "high")
    )
    audit_rows = [[e(a["at"]), e(a["event"]), e(a["detail"])] for a in report["audit_trail"]]
    source_rows = [
        [
            e(s["name"]),
            badge(s["status"], {"ok": "good", "failed": "crit"}.get(s["status"], "neutral")),
            e(s.get("message") or s.get("tool_version")),
        ]
        for s in report["sources"]
    ]
    eco_rows = [[e(k), e(v)] for k, v in sorted(report["inventory"]["ecosystems"].items())]
    changes = report.get("changes_since_previous_scan")
    changes_line = ""
    if changes:
        moved = ", ".join(f"{k} {v}" for k, v in changes["totals"].items() if v)
        if not moved:
            moved = "no package changes" + (" (same commit)" if changes.get("same_commit") else "")
        changes_line = (
            f'<p class="small"><strong>Changes since the previous scan</strong> '
            f"({e(changes['baseline_scan_id'])}): {e(moved)}</p>"
        )
    validations = summary["validations"]
    verified = validations.get("FIXED", 0)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kestral Guardian Report — {e(scan["repository"])}</title>
<style>
:root {{ --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --soft:#f8fafc; --accent:#9f1239; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font:14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color:var(--ink); background:#eef2f6; }}
.page {{ max-width:1080px; margin:24px auto; background:#fff; padding:40px 48px; box-shadow:0 1px 3px rgba(15,23,42,.08); }}
header.brand {{ display:flex; align-items:center; gap:18px; border-bottom:3px solid var(--ink); padding-bottom:18px; }}
header.brand img {{ width:72px; height:72px; mix-blend-mode:multiply; }}
header.brand h1 {{ margin:0; font-size:26px; letter-spacing:.2px; }}
header.brand .tag {{ color:var(--muted); font-size:13px; letter-spacing:2px; text-transform:uppercase; }}
.actions {{ margin-left:auto; }}
button.print {{ background:var(--ink); color:#fff; border:0; border-radius:6px; padding:9px 14px; font-weight:600; cursor:pointer; }}
.meta {{ display:grid; grid-template-columns:repeat(4,1fr); gap:6px 18px; margin:18px 0 6px; font-size:12.5px; }}
.meta div span {{ display:block; color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.6px; }}
h2 {{ font-size:18px; margin:30px 0 10px; padding-top:6px; border-top:1px solid var(--line); }}
h2 .n {{ color:var(--accent); margin-right:6px; }}
h3 {{ font-size:15px; margin:0; }} h4 {{ font-size:12px; text-transform:uppercase; letter-spacing:.6px; color:var(--muted); margin:14px 0 4px; }}
.stats {{ display:grid; grid-template-columns:repeat(6,1fr); gap:10px; }}
.stat {{ border:1px solid var(--line); border-radius:8px; padding:10px 12px; background:var(--soft); }}
.stat .v {{ font-size:22px; font-weight:700; }} .stat .l {{ font-size:11.5px; color:var(--muted); }}
table {{ width:100%; border-collapse:collapse; font-size:12.5px; margin:6px 0; }}
th {{ text-align:left; background:var(--soft); color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.5px; }}
th, td {{ border-bottom:1px solid var(--line); padding:7px 8px; vertical-align:top; overflow-wrap:break-word; }}
th {{ white-space:nowrap; }}
.scroll {{ overflow-x:auto; }} .scroll table {{ min-width:760px; }}
.badge {{ display:inline-block; border-radius:999px; padding:1px 8px; font-size:11px; font-weight:600; border:1px solid var(--line); white-space:nowrap; }}
.badge.crit {{ background:#881337; color:#fff; border-color:#881337; }} .badge.high {{ background:#be123c; color:#fff; border-color:#be123c; }}
.badge.med {{ background:#fef3c7; color:#92400e; border-color:#fcd34d; }} .badge.low {{ background:#f1f5f9; color:#334155; }}
.badge.good {{ background:#e2e8f0; color:#0f172a; border-color:#94a3b8; }} .badge.neutral {{ background:#fff; color:#334155; }}
.card {{ border:1px solid var(--line); border-radius:10px; padding:16px 18px; margin:12px 0; }}
.row {{ display:flex; align-items:center; justify-content:space-between; gap:12px; }}
.muted {{ color:var(--muted); }} .small {{ font-size:12px; }}
ul.steps {{ padding-left:18px; margin:4px 0; }} ul.steps li {{ margin:3px 0; }}
pre {{ background:#0f172a; color:#e2e8f0; padding:10px 12px; border-radius:6px; font-size:11.5px; overflow:auto; white-space:pre-wrap; }}
code {{ font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; }}
details summary {{ cursor:pointer; margin:6px 0; }}
.callout {{ border-left:4px solid var(--accent); background:#fff1f2; padding:10px 14px; border-radius:4px; font-size:13px; }}
footer {{ margin-top:30px; padding-top:12px; border-top:1px solid var(--line); color:var(--muted); font-size:11.5px; display:flex; justify-content:space-between; }}
@media (max-width:760px) {{ .page {{ padding:20px 16px; margin:0; }} .stats {{ grid-template-columns:repeat(2,1fr); }} .meta {{ grid-template-columns:1fr 1fr; }} }}
@page {{ size:A4; margin:14mm; }}
@media print {{
  .scroll {{ overflow:visible; }} .scroll table {{ min-width:0; }}
  body {{ background:#fff; }} .page {{ box-shadow:none; margin:0; padding:0; max-width:none; }}
  .actions {{ display:none; }} details {{ display:block; }} details > summary {{ list-style:none; }}
  .avoid-break, tr {{ break-inside:avoid; }} h2 {{ break-after:avoid; }}
  .badge.crit, .badge.high, pre {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
}}
</style></head>
<body><div class="page">
<header class="brand">
  <img src="{logo_data_uri()}" alt="Kestral logo">
  <div><h1>Kestral Guardian Report</h1><div class="tag">Know what you build. Trust what you ship.</div></div>
  <div class="actions"><button class="print" onclick="window.print()">Print / Save as PDF</button></div>
</header>
<div class="meta">
  <div><span>Repository</span>{e(scan["repository"])}</div>
  <div><span>Commit</span><code>{e((scan["commit"] or "")[:12])}</code> · {e(scan["resolved_ref"])}</div>
  <div><span>Scan</span><code>{e(scan["scan_id"])}</code></div>
  <div><span>Generated</span>{e(report["generated_at"][:19].replace("T", " "))} UTC</div>
</div>

<h2><span class="n">1</span>Executive summary</h2>
<div class="stats">
  {stat("Packages", summary["packages"])}{stat("Vulnerabilities", summary["vulnerabilities"])}
  {stat("Critical / high", f"{bands['critical']} / {bands['high']}")}{stat("Suspicious changes", summary["suspicious_changes"])}
  {stat("Fixes verified in sandbox", verified)}{stat("Open high-risk items", sum(1 for r in report["remaining_risks"] if r["state"] == "Open" and r["band"] in ("critical", "high")))}
</div>
<p class="small">{summary["projects"]} project(s), {e(summary["dependency_edges"])} dependency edges, {e(summary["cves_linked"])} CVEs linked through NVD,
{summary["workflow_pins"]} unpinned CI/CD references. Proposals: {e(", ".join(f"{k.lower()} {v}" for k, v in summary["proposals"].items() if v))}.
{("<strong>The assessment is partial</strong>; see warnings in section 9." if summary["partial"] else "")}</p>

<h2><span class="n">2</span>Component inventory</h2>
{table(["Ecosystem", "Packages"], eco_rows, "No packages discovered")}
<p class="small muted">The full component list (name, version, PURL, scope, project, directness) is in the JSON report.</p>
{changes_line}

<h2><span class="n">3</span>Vulnerabilities, ranked</h2>
<p class="small muted">Sorted by Kestral priority (50% CVSS, 20% EPSS, 20% exposure, 10% fix available). Sources: OSV, Grype, NVD. Not reachability-checked.</p>
{capped(["Package / advisory", "Priority", "CVSS", "CVE / CWE", "Directness", "Fixed in", "Dependency path"], vuln_rows, "No known vulnerabilities were reported.", "vulnerabilities")}

<h2><span class="n">4</span>Suspicious changes and supply-chain anomalies</h2>
{capped(["Subject", "Category", "Risk", "Why", "Evidence"], suspicious_rows, "No suspicious changes were found.", "findings")}
<h4>Unpinned CI/CD components</h4>
{table(["Action", "Finding", "Evidence"], pin_rows, "No mutable workflow references.")}

<h2><span class="n">5</span>Recommended actions and human decisions</h2>
<h4>Remediation proposals</h4>
{capped(["Proposal", "Action", "Status", "Reviewer", "Decision record"], proposal_rows, "No remediation proposals.", "proposals")}
<h4>AI-assisted recommendations (proposals only)</h4>
{table(["Recommendation", "Change", "Deterministic check", "Status", "Human decision", "Model"], ai_rows, "No AI analyses were requested.")}

<h2><span class="n">6</span>Sandbox validation results</h2>
<div class="callout">Each validation applies one approved change to a fresh copy of the exact scanned commit, runs the
project's tests only inside a locked-down container, rescans the patched copy and compares before and after.
Nothing is merged, pushed or deployed.</div>
{"".join(validation_blocks) or '<p class="muted">No validations have been run.</p>'}

<h2><span class="n">7</span>Remaining and accepted risk</h2>
{capped(["Package", "Finding", "Band", "State", "Reviewer"], remaining_rows, "No remaining critical/high or decided items.", "items")}
<p class="small muted">{open_lower} additional open medium/low findings are listed in the JSON report.</p>

<h2><span class="n">8</span>Audit trail</h2>
{capped(["When (UTC)", "Event", "Detail"], audit_rows, "No events.", "events")}

<h2><span class="n">9</span>Data sources, coverage and warnings</h2>
{table(["Source", "Status", "Detail"], source_rows, "No sources recorded.")}
<ul class="small">{"".join(f"<li>{e(w)}</li>" for w in report["warnings"]) or '<li class="muted">No warnings</li>'}</ul>

<h2><span class="n">10</span>Responsible AI and security note</h2>
<ul class="small">{"".join(f"<li>{e(x)}</li>" for x in report["responsible_ai"])}</ul>
<h4>Limitations</h4>
<ul class="small">{"".join(f"<li>{e(x)}</li>" for x in report["limitations"])}</ul>

<footer><span>Kestral Guardian · {e(report["schema"])}</span><span>Generated from recorded scan evidence and human decisions only.</span></footer>
</div></body></html>"""
