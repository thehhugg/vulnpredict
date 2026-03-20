"""HTML report formatter for VulnPredict scan results.

Generates a self-contained, single-file HTML report with:
- Executive summary with severity and file distribution charts
- Detailed findings table with code context and remediation guidance
- Inline CSS and JavaScript (no external dependencies)
"""

import html
import json
from collections import Counter
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
_SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
    "unknown": "#9ca3af",
}


def _classify_severity(finding: dict) -> str:
    """Derive a severity label from a finding dictionary."""
    sev = finding.get("severity", "").lower().strip()
    if sev in _SEVERITY_ORDER:
        return sev
    confidence = finding.get("confidence", "").lower().strip()
    if confidence in ("high",):
        return "high"
    if confidence in ("medium",):
        return "medium"
    return "medium"


def _escape(text) -> str:
    """HTML-escape a value, handling None."""
    return html.escape(str(text)) if text else ""


# ---------------------------------------------------------------------------
# Chart data helpers
# ---------------------------------------------------------------------------

def _severity_chart_data(findings: list) -> dict:
    """Build severity distribution data for the chart."""
    counter = Counter(_classify_severity(f) for f in findings)
    labels = []
    values = []
    colors = []
    for sev in ("critical", "high", "medium", "low", "info", "unknown"):
        count = counter.get(sev, 0)
        if count > 0:
            labels.append(sev.capitalize())
            values.append(count)
            colors.append(_SEVERITY_COLORS[sev])
    return {"labels": labels, "values": values, "colors": colors}


def _file_chart_data(findings: list, top_n: int = 10) -> dict:
    """Build top-N files by finding count."""
    counter = Counter(f.get("file", f.get("filename", "unknown")) for f in findings)
    most_common = counter.most_common(top_n)
    labels = [item[0].split("/")[-1] for item in most_common]  # basename only
    values = [item[1] for item in most_common]
    return {"labels": labels, "values": values}


def _type_chart_data(findings: list) -> dict:
    """Build finding type distribution."""
    counter = Counter(f.get("type", f.get("rule_id", "unknown")) for f in findings)
    most_common = counter.most_common(8)
    labels = [item[0] for item in most_common]
    values = [item[1] for item in most_common]
    return {"labels": labels, "values": values}


# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------

_REMEDIATION = {
    "eval_usage": "Replace eval() with ast.literal_eval() or a safe parser.",
    "exec_usage": "Avoid exec(). Use a restricted execution environment if dynamic code is required.",
    "hardcoded_secret": "Move secrets to environment variables or a secrets manager.",
    "subprocess_injection": "Use a list of arguments instead of shell=True. Validate all inputs.",
    "sql_injection": "Use parameterized queries or an ORM instead of string formatting.",
    "taint_flow": "Sanitize or validate all user inputs before passing to sensitive sinks.",
    "dangerous_function": "Avoid eval(), Function(), setTimeout/setInterval with string arguments.",
    "xss": "Sanitize user input with DOMPurify or equivalent before inserting into the DOM.",
    "high_complexity": "Refactor into smaller functions. Aim for cyclomatic complexity < 10.",
}


def _get_remediation(finding: dict) -> str:
    """Return remediation guidance for a finding type."""
    ftype = finding.get("type", finding.get("rule_id", "")).lower()
    for key, guidance in _REMEDIATION.items():
        if key in ftype:
            return guidance
    return "Review the finding and apply appropriate security controls."


def _build_findings_rows(findings: list) -> str:
    """Build HTML table rows for each finding."""
    rows = []
    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(_classify_severity(f), 99))
    for i, f in enumerate(sorted_findings, 1):
        sev = _classify_severity(f)
        color = _SEVERITY_COLORS.get(sev, "#9ca3af")
        filepath = _escape(f.get("file", f.get("filename", "—")))
        line = f.get("line", f.get("lineno", "—"))
        func = _escape(f.get("function", f.get("name", "—")))
        ftype = _escape(f.get("type", f.get("rule_id", "—")))
        detail = _escape(f.get("detail", f.get("message", f.get("issue_text", "—"))))
        remediation = _escape(_get_remediation(f))
        score = f.get("score", None)
        score_str = f"{score:.2f}" if isinstance(score, (int, float)) else "—"

        rows.append(f"""
        <tr>
          <td>{i}</td>
          <td><span class="severity-badge" style="background:{color}">{sev.upper()}</span></td>
          <td class="filepath">{filepath}</td>
          <td>{line}</td>
          <td>{func}</td>
          <td>{ftype}</td>
          <td>{detail}</td>
          <td>{remediation}</td>
          <td>{score_str}</td>
        </tr>""")
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# Main HTML template
# ---------------------------------------------------------------------------

def format_html(findings: list, scan_path: str = ".", scan_duration: float = 0.0, file_count: int = 0) -> str:
    """Format scan findings as a self-contained HTML report.

    Parameters
    ----------
    findings : list
        List of finding dictionaries from VulnPredict analyzers.
    scan_path : str
        The path that was scanned.
    scan_duration : float
        Scan duration in seconds.
    file_count : int
        Number of files scanned.

    Returns
    -------
    str
        Complete HTML document as a string.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sev_data = _severity_chart_data(findings)
    file_data = _file_chart_data(findings)
    type_data = _type_chart_data(findings)
    findings_rows = _build_findings_rows(findings)

    sev_summary = Counter(_classify_severity(f) for f in findings)
    critical_count = sev_summary.get("critical", 0)
    high_count = sev_summary.get("high", 0)
    medium_count = sev_summary.get("medium", 0)
    low_count = sev_summary.get("low", 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnPredict Scan Report</title>
<style>
  :root {{
    --bg: #f8fafc; --card-bg: #ffffff; --text: #1e293b;
    --border: #e2e8f0; --muted: #64748b;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ font-size: 1.75rem; margin-bottom: 0.25rem; }}
  .subtitle {{ color: var(--muted); margin-bottom: 2rem; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px;
           padding: 1.25rem; text-align: center; }}
  .card .number {{ font-size: 2rem; font-weight: 700; }}
  .card .label {{ color: var(--muted); font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  .charts {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }}
  .chart-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }}
  .chart-card h3 {{ margin-bottom: 1rem; font-size: 1rem; }}
  canvas {{ max-width: 100%; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card-bg);
           border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th {{ background: #f1f5f9; text-align: left; padding: 0.75rem 1rem; font-size: 0.8rem;
       text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); border-bottom: 2px solid var(--border); }}
  td {{ padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.875rem; vertical-align: top; }}
  tr:hover {{ background: #f8fafc; }}
  .severity-badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
                     color: #fff; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.03em; }}
  .filepath {{ font-family: 'SF Mono', Consolas, monospace; font-size: 0.8rem; word-break: break-all; }}
  .section-title {{ font-size: 1.25rem; margin: 2rem 0 1rem; }}
  .footer {{ text-align: center; color: var(--muted); font-size: 0.8rem; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); }}
  .filter-bar {{ margin-bottom: 1rem; }}
  .filter-bar input {{ padding: 0.5rem 1rem; border: 1px solid var(--border); border-radius: 6px;
                       font-size: 0.875rem; width: 300px; }}
  @media print {{
    body {{ padding: 0.5rem; }}
    .filter-bar {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="container">
  <h1>VulnPredict Scan Report</h1>
  <p class="subtitle">Scanned <strong>{_escape(scan_path)}</strong> on {now}</p>

  <div class="cards">
    <div class="card">
      <div class="number">{len(findings)}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="card">
      <div class="number" style="color:{_SEVERITY_COLORS['critical']}">{critical_count}</div>
      <div class="label">Critical</div>
    </div>
    <div class="card">
      <div class="number" style="color:{_SEVERITY_COLORS['high']}">{high_count}</div>
      <div class="label">High</div>
    </div>
    <div class="card">
      <div class="number" style="color:{_SEVERITY_COLORS['medium']}">{medium_count}</div>
      <div class="label">Medium</div>
    </div>
    <div class="card">
      <div class="number" style="color:{_SEVERITY_COLORS['low']}">{low_count}</div>
      <div class="label">Low</div>
    </div>
    <div class="card">
      <div class="number">{file_count}</div>
      <div class="label">Files Scanned</div>
    </div>
  </div>

  <div class="charts">
    <div class="chart-card">
      <h3>Severity Distribution</h3>
      <canvas id="sevChart" height="200"></canvas>
    </div>
    <div class="chart-card">
      <h3>Top Files by Findings</h3>
      <canvas id="fileChart" height="200"></canvas>
    </div>
    <div class="chart-card">
      <h3>Finding Types</h3>
      <canvas id="typeChart" height="200"></canvas>
    </div>
  </div>

  <h2 class="section-title">Detailed Findings</h2>
  <div class="filter-bar">
    <input type="text" id="filterInput" placeholder="Filter findings..." onkeyup="filterTable()">
  </div>
  <table id="findingsTable">
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>File</th><th>Line</th><th>Function</th>
        <th>Type</th><th>Detail</th><th>Remediation</th><th>Score</th>
      </tr>
    </thead>
    <tbody>
      {findings_rows}
    </tbody>
  </table>

  <div class="footer">
    Generated by <strong>VulnPredict</strong> &mdash; Predictive Vulnerability Intelligence Tool<br>
    Scan duration: {scan_duration:.2f}s &bull; {len(findings)} findings across {file_count} files
  </div>
</div>

<script>
// Minimal inline chart library (no external deps)
(function() {{
  function drawDoughnut(canvasId, labels, values, colors) {{
    var canvas = document.getElementById(canvasId);
    if (!canvas || !canvas.getContext) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width = canvas.parentElement.clientWidth - 40;
    var h = canvas.height = 220;
    var cx = w * 0.35, cy = h / 2, r = Math.min(cx, cy) - 10, ri = r * 0.55;
    var total = values.reduce(function(a, b) {{ return a + b; }}, 0);
    if (total === 0) return;
    var start = -Math.PI / 2;
    for (var i = 0; i < values.length; i++) {{
      var angle = (values[i] / total) * 2 * Math.PI;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, start, start + angle);
      ctx.closePath();
      ctx.fillStyle = colors[i] || '#ccc';
      ctx.fill();
      start += angle;
    }}
    ctx.beginPath();
    ctx.arc(cx, cy, ri, 0, 2 * Math.PI);
    ctx.fillStyle = '#fff';
    ctx.fill();
    // Legend
    var lx = w * 0.72, ly = 20;
    ctx.font = '12px -apple-system, sans-serif';
    for (var i = 0; i < labels.length; i++) {{
      ctx.fillStyle = colors[i] || '#ccc';
      ctx.fillRect(lx, ly + i * 22, 12, 12);
      ctx.fillStyle = '#1e293b';
      ctx.fillText(labels[i] + ' (' + values[i] + ')', lx + 18, ly + i * 22 + 11);
    }}
  }}

  function drawBar(canvasId, labels, values, color) {{
    var canvas = document.getElementById(canvasId);
    if (!canvas || !canvas.getContext) return;
    var ctx = canvas.getContext('2d');
    var w = canvas.width = canvas.parentElement.clientWidth - 40;
    var h = canvas.height = 220;
    var max = Math.max.apply(null, values) || 1;
    var barW = Math.min(40, (w - 60) / labels.length - 8);
    var baseY = h - 30;
    var chartH = baseY - 20;
    ctx.font = '11px -apple-system, sans-serif';
    ctx.textAlign = 'center';
    for (var i = 0; i < values.length; i++) {{
      var barH = (values[i] / max) * chartH;
      var x = 40 + i * (barW + 8);
      ctx.fillStyle = color || '#3b82f6';
      ctx.fillRect(x, baseY - barH, barW, barH);
      ctx.fillStyle = '#1e293b';
      ctx.fillText(values[i], x + barW / 2, baseY - barH - 5);
      ctx.save();
      ctx.translate(x + barW / 2, baseY + 5);
      ctx.rotate(-0.5);
      ctx.fillStyle = '#64748b';
      ctx.fillText(labels[i].substring(0, 12), 0, 10);
      ctx.restore();
    }}
  }}

  drawDoughnut('sevChart', {json.dumps(sev_data['labels'])}, {json.dumps(sev_data['values'])}, {json.dumps(sev_data['colors'])});
  drawBar('fileChart', {json.dumps(file_data['labels'])}, {json.dumps(file_data['values'])}, '#3b82f6');
  drawBar('typeChart', {json.dumps(type_data['labels'])}, {json.dumps(type_data['values'])}, '#8b5cf6');
}})();

function filterTable() {{
  var input = document.getElementById('filterInput').value.toLowerCase();
  var rows = document.querySelectorAll('#findingsTable tbody tr');
  rows.forEach(function(row) {{
    row.style.display = row.textContent.toLowerCase().indexOf(input) > -1 ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


def write_html(findings: list, scan_path: str = ".", output_path: str = "report.html",
               scan_duration: float = 0.0, file_count: int = 0) -> None:
    """Write an HTML report to a file.

    Parameters
    ----------
    findings : list
        List of finding dictionaries.
    scan_path : str
        The path that was scanned.
    output_path : str
        Destination file path.
    scan_duration : float
        Scan duration in seconds.
    file_count : int
        Number of files scanned.
    """
    report = format_html(findings, scan_path, scan_duration, file_count)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)
