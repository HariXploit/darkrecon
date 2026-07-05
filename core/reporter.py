import os
import json
from datetime import datetime


class ReportGenerator:
    """Generates a clean HTML + JSON report from recon results."""

    def __init__(self, results, out_dir, log):
        self.results = results
        self.out_dir = out_dir
        self.log     = log

    def run(self):
        # Save raw JSON
        json_path = os.path.join(self.out_dir, "recon_results.json")
        with open(json_path, "w") as f:
            json.dump(self.results, f, indent=2, default=str)

        # Build HTML report
        html_path = os.path.join(self.out_dir, "report.html")
        html = self._build_html()
        with open(html_path, "w") as f:
            f.write(html)

        self.log.info(f"JSON report : {json_path}")
        self.log.info(f"HTML report : {html_path}")
        return html_path

    def _build_html(self):
        r = self.results
        target    = r["target"]
        timestamp = r.get("timestamp", "")
        elapsed   = r.get("elapsed", 0)
        subdomains    = r.get("subdomains", [])
        live_hosts    = r.get("live_hosts", [])
        header_results = r.get("header_results", [])
        screenshots   = r.get("screenshots", [])

        # Stats
        total_missing = sum(len(h.get("missing_headers", [])) for h in header_results)
        total_leaky   = sum(len(h.get("leaky_headers", [])) for h in header_results)
        grade_counts  = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        for h in header_results:
            g = h.get("grade", "F")
            grade_counts[g] = grade_counts.get(g, 0) + 1

        SEVERITY_COLOR = {"High": "#e74c3c", "Medium": "#e67e22", "Low": "#3498db", "Info": "#95a5a6"}
        GRADE_COLOR    = {"A": "#27ae60", "B": "#2ecc71", "C": "#f39c12", "D": "#e67e22", "F": "#e74c3c"}

        # Build subdomain rows
        sub_rows = "".join(f"<tr><td>{s}</td></tr>" for s in subdomains)

        # Build host rows
        host_rows = ""
        for h in header_results:
            grade  = h.get("grade", "?")
            score  = h.get("score", 0)
            gc     = GRADE_COLOR.get(grade, "#999")
            missing_count = len(h.get("missing_headers", []))
            leaky_count   = len(h.get("leaky_headers", []))
            host_rows += f"""
            <tr>
                <td><a href="{h['url']}" target="_blank">{h['url']}</a></td>
                <td>{h.get('status','?')}</td>
                <td><span class="grade" style="background:{gc}">{grade}</span></td>
                <td>{score}/100</td>
                <td class="{'bad' if missing_count > 0 else 'good'}">{missing_count}</td>
                <td class="{'bad' if leaky_count > 0 else 'good'}">{leaky_count}</td>
            </tr>"""

        # Build detailed findings
        findings_html = ""
        for h in sorted(header_results, key=lambda x: x.get("score", 100)):
            if not h.get("missing_headers") and not h.get("leaky_headers"):
                continue
            grade = h.get("grade", "?")
            gc    = GRADE_COLOR.get(grade, "#999")
            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-url">{h['url']}</span>
                    <span class="grade" style="background:{gc}">{grade} ({h.get('score',0)}/100)</span>
                </div>"""

            if h.get("missing_headers"):
                findings_html += "<div class='finding-section'><h4>Missing Security Headers</h4><ul>"
                for mh in h["missing_headers"]:
                    sc = SEVERITY_COLOR.get(mh["severity"], "#999")
                    findings_html += f"""
                    <li>
                        <span class="severity-badge" style="background:{sc}">{mh['severity']}</span>
                        <strong>{mh['header']}</strong> — {mh['description']}<br>
                        <code>Recommendation: {mh['recommendation']}</code>
                    </li>"""
                findings_html += "</ul></div>"

            if h.get("leaky_headers"):
                findings_html += "<div class='finding-section'><h4>Tech Stack Leakage</h4><ul>"
                for lh in h["leaky_headers"]:
                    findings_html += f"<li><strong>{lh['header']}:</strong> {lh['value']} <em>— {lh['issue']}</em></li>"
                findings_html += "</ul></div>"

            if h.get("cookie_issues"):
                findings_html += "<div class='finding-section'><h4>Cookie Flag Issues</h4><ul>"
                for ci in h["cookie_issues"]:
                    findings_html += f"<li>{ci}</li>"
                findings_html += "</ul></div>"

            if h.get("weak_headers"):
                findings_html += "<div class='finding-section'><h4>Weak Header Values</h4><ul>"
                for wh in h["weak_headers"]:
                    findings_html += f"<li><strong>{wh['header']}:</strong> {wh['value']} — <em>{wh['issue']}</em></li>"
                findings_html += "</ul></div>"

            findings_html += "</div>"

        # Screenshot gallery
        gallery_html = ""
        if screenshots:
            gallery_html = "<div class='gallery'>"
            for s in screenshots:
                fname = os.path.basename(s)
                gallery_html += f'<div class="gallery-item"><img src="screenshots/{fname}" loading="lazy"><p>{fname}</p></div>'
            gallery_html += "</div>"
        else:
            gallery_html = "<p class='muted'>No screenshots captured (gowitness not installed or skipped)</p>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DarkRecon Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f1117; color: #e2e8f0; line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #1a1f2e, #0f1117); border-bottom: 1px solid #2d3748; padding: 2rem; }}
  .header h1 {{ font-size: 1.8rem; color: #63b3ed; }} .header p {{ color: #a0aec0; margin-top: 0.3rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 8px; padding: 1.2rem; text-align: center; }}
  .stat-card .number {{ font-size: 2rem; font-weight: 700; color: #63b3ed; }}
  .stat-card .label {{ font-size: 0.8rem; color: #a0aec0; text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; }}
  h2 {{ font-size: 1.2rem; color: #63b3ed; margin: 2rem 0 1rem; border-bottom: 1px solid #2d3748; padding-bottom: 0.5rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1f2e; border-radius: 8px; overflow: hidden; }}
  th {{ background: #2d3748; padding: 10px 14px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #a0aec0; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #2d3748; font-size: 13px; }}
  td a {{ color: #63b3ed; text-decoration: none; }} td a:hover {{ text-decoration: underline; }}
  tr:last-child td {{ border-bottom: none; }}
  .grade {{ display: inline-block; padding: 2px 10px; border-radius: 99px; font-size: 12px; font-weight: 700; color: #fff; }}
  .bad {{ color: #fc8181; }} .good {{ color: #68d391; }}
  .finding-card {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }}
  .finding-header {{ background: #2d3748; padding: 12px 16px; display: flex; justify-content: space-between; align-items: center; }}
  .finding-url {{ font-family: monospace; font-size: 13px; color: #63b3ed; }}
  .finding-section {{ padding: 14px 16px; border-top: 1px solid #2d3748; }}
  .finding-section h4 {{ font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #a0aec0; margin-bottom: 10px; }}
  .finding-section ul {{ list-style: none; }}
  .finding-section li {{ padding: 6px 0; border-bottom: 1px solid #2d3748; font-size: 13px; }}
  .finding-section li:last-child {{ border-bottom: none; }}
  .finding-section code {{ display: block; margin-top: 4px; font-size: 11px; color: #68d391; background: #0f1117; padding: 4px 8px; border-radius: 4px; }}
  .severity-badge {{ display: inline-block; font-size: 10px; padding: 1px 7px; border-radius: 99px; color: #fff; margin-right: 6px; font-weight: 600; }}
  .gallery {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 1rem; }}
  .gallery-item {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 8px; overflow: hidden; }}
  .gallery-item img {{ width: 100%; height: 140px; object-fit: cover; }}
  .gallery-item p {{ font-size: 11px; color: #a0aec0; padding: 6px 10px; word-break: break-all; }}
  .muted {{ color: #a0aec0; font-size: 13px; }}
  .footer {{ text-align: center; padding: 2rem; color: #4a5568; font-size: 12px; border-top: 1px solid #2d3748; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>DarkRecon Report</h1>
  <p>Target: <strong>{target}</strong> &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; Completed in {elapsed}s</p>
</div>
<div class="container">

  <div class="stats-grid">
    <div class="stat-card"><div class="number">{len(subdomains)}</div><div class="label">Subdomains Found</div></div>
    <div class="stat-card"><div class="number">{len(live_hosts)}</div><div class="label">Live Hosts</div></div>
    <div class="stat-card"><div class="number" style="color:#fc8181">{total_missing}</div><div class="label">Missing Headers</div></div>
    <div class="stat-card"><div class="number" style="color:#f6ad55">{total_leaky}</div><div class="label">Leaky Headers</div></div>
    <div class="stat-card"><div class="number">{len(screenshots)}</div><div class="label">Screenshots</div></div>
    <div class="stat-card"><div class="number">{elapsed}s</div><div class="label">Total Time</div></div>
  </div>

  <h2>Subdomains ({len(subdomains)})</h2>
  <table>
    <thead><tr><th>Subdomain</th></tr></thead>
    <tbody>{sub_rows if sub_rows else '<tr><td class="muted">No subdomains found</td></tr>'}</tbody>
  </table>

  <h2>Live Hosts — Security Header Overview</h2>
  <table>
    <thead><tr><th>URL</th><th>Status</th><th>Grade</th><th>Score</th><th>Missing Headers</th><th>Leaky Headers</th></tr></thead>
    <tbody>{host_rows if host_rows else '<tr><td colspan="6" class="muted">No live hosts found</td></tr>'}</tbody>
  </table>

  <h2>Detailed Security Findings</h2>
  {findings_html if findings_html else '<p class="muted">No findings — all hosts have good security headers!</p>'}

  <h2>Screenshots</h2>
  {gallery_html}

</div>
<div class="footer">Generated by DarkRecon v1.0 &nbsp;|&nbsp; github.com/yourname/recon-tool</div>
</body>
</html>"""
