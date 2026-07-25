"""
Sentinel Guard — Cyber Scan Report Generator
Generates beautiful cyberpunk-themed HTML reports, JSON logs, and CSV summaries.
"""
import os
import json
import csv
import time
import io
from pathlib import Path
from typing import Union, Dict, Any, List
from enum import Enum
from utils.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generates beautiful cyberpunk-themed HTML, JSON, and CSV reports for Sentinel Guard scans."""

    def generate_html(self, report: Any, output_path: str = None) -> str:
        """
        Generate a cyberpunk-themed HTML report.
        
        Args:
            report: A dict or ScanReport object with scan details.
            output_path: Optional path to save the generated HTML file.
            
        Returns:
            The generated HTML string.
        """
        content = self._html_template(report)
        if output_path:
            try:
                p = Path(output_path)
                p.parent.mkdir(parents=True, exist_ok=True)
                with open(p, "w", encoding="utf-8") as f:
                    f.write(content)
                logger.info(f"HTML report successfully saved to: {output_path}")
            except Exception as e:
                logger.error(f"Failed to write HTML report to {output_path}: {e}")
        return content

    def generate_json(self, report: Any, output_path: str = None) -> str:
        """
        Generate a JSON report containing all scan details.
        
        Args:
            report: A dict or ScanReport object with scan details.
            output_path: Optional path to save the generated JSON file.
            
        Returns:
            The generated JSON string.
        """
        norm = self._normalize_report(report)
        content = json.dumps(norm, indent=4, ensure_ascii=False)
        if output_path:
            try:
                p = Path(output_path)
                p.parent.mkdir(parents=True, exist_ok=True)
                with open(p, "w", encoding="utf-8") as f:
                    f.write(content)
                logger.info(f"JSON report successfully saved to: {output_path}")
            except Exception as e:
                logger.error(f"Failed to write JSON report to {output_path}: {e}")
        return content

    def generate_csv(self, report: Any, output_path: str = None) -> str:
        """
        Generate a CSV report containing a list of found threats.
        
        Args:
            report: A dict or ScanReport object with scan details.
            output_path: Optional path to save the generated CSV file.
            
        Returns:
            The generated CSV string.
        """
        norm = self._normalize_report(report)
        f_out = io.StringIO()
        writer = csv.writer(f_out)
        
        # Header columns
        writer.writerow(["Threat Name", "File Path", "Threat Type", "Severity", "SHA256", "Action Taken"])
        
        # Threat rows
        for threat in norm.get("threats", []):
            writer.writerow([
                threat.get("name", "Unknown Threat"),
                threat.get("file", "N/A"),
                threat.get("type", "Unknown"),
                threat.get("severity", "LOW"),
                threat.get("sha256", "N/A"),
                threat.get("action_taken", "Detected")
            ])
            
        content = f_out.getvalue()
        if output_path:
            try:
                p = Path(output_path)
                p.parent.mkdir(parents=True, exist_ok=True)
                with open(p, "w", encoding="utf-8", newline="") as f:
                    f.write(content)
                logger.info(f"CSV threat list successfully saved to: {output_path}")
            except Exception as e:
                logger.error(f"Failed to write CSV report to {output_path}: {e}")
        return content

    def _html_template(self, report: Any) -> str:
        """
        Generate full HTML content with embedded cyberpunk style, tables, timeline, and stats.
        
        Args:
            report: A dict or ScanReport object.
            
        Returns:
            Complete HTML string.
        """
        norm = self._normalize_report(report)
        
        # Determine theme styling variables based on threat status
        has_threats = norm["threats_found"] > 0
        threat_status_class = "danger" if has_threats else "safe"
        threat_status_text = "THREATS DETECTED" if has_threats else "SYSTEM SECURE"
        
        # Build threats rows
        threats_rows = ""
        if not norm["threats"]:
            threats_rows = """
            <tr>
                <td colspan="7" style="text-align: center; color: var(--text-dim); font-style: italic; padding: 25px;">
                    SYSTEM IS CLEAN: No malicious threat signatures or entities detected.
                </td>
            </tr>
            """
        else:
            for idx, t in enumerate(norm["threats"], 1):
                severity = t.get("severity", "LOW").upper()
                sev_class = severity.lower()
                if sev_class not in ["critical", "high", "medium", "low"]:
                    sev_class = "low"
                
                # Truncate SHA256 safely
                sha = t.get('sha256', 'N/A')
                sha_display = f"{sha[:16]}..." if sha and len(sha) > 16 else sha
                
                threats_rows += f"""
                <tr>
                    <td style="font-weight: bold; color: var(--danger);">{idx:02d}</td>
                    <td style="font-weight: bold; color: var(--text);">{t.get('name', 'Unknown')}</td>
                    <td><span style="font-size: 10px; background: rgba(255,255,255,0.05); padding: 3px 8px; border-radius: 4px; border: 1px solid var(--border);">{t.get('type', 'signature')}</span></td>
                    <td><span class="severity-pill {sev_class}">{severity}</span></td>
                    <td style="color: var(--text-dim); font-size: 11px; font-family: monospace; word-break: break-all;">{t.get('file', 'N/A')}</td>
                    <td style="color: var(--text-dim); font-size: 11px; font-family: monospace;" title="{sha}">{sha_display}</td>
                    <td class="action-taken">{t.get('action_taken', 'Detected')}</td>
                </tr>
                """

        # Build heuristic flags rows/section
        heuristic_section = ""
        if not norm["heuristic_flags"]:
            heuristic_section = """
            <div style="padding: 15px; border: 1px dashed var(--border); border-radius: 6px; text-align: center;">
                <p style="color: var(--text-dim); font-size: 12px; font-style: italic;">
                    No suspicious heuristic anomalies or behavioral rule triggers detected.
                </p>
            </div>
            """
        else:
            heuristic_rows = ""
            for h in norm["heuristic_flags"]:
                score = h.get("score", 0)
                score_color = "var(--danger)" if score >= 70 else ("var(--warn)" if score >= 40 else "var(--accent)")
                heuristic_rows += f"""
                <tr>
                    <td style="color: var(--text-dim); font-size: 11px; word-break: break-all;">{h.get('file', 'N/A')}</td>
                    <td style="color: var(--accent); font-weight: bold;">{h.get('flag', 'N/A')}</td>
                    <td style="font-weight: bold; color: {score_color}; text-align: right;">{score}/100</td>
                </tr>
                """
            heuristic_section = f"""
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 50%;">Resource Target</th>
                            <th style="width: 38%;">Heuristic Violation / Flag</th>
                            <th style="width: 12%; text-align: right;">Risk Rating</th>
                        </tr>
                    </thead>
                    <tbody>
                        {heuristic_rows}
                    </tbody>
                </table>
            </div>
            """

        # Build API Cloud Reputation results section
        api_section = ""
        api_res = norm["api_results"]
        if api_res.get("status") == "Inactive" or not api_res.get("details"):
            api_section = """
            <div style="display: flex; align-items: center; justify-content: space-between; padding: 15px; border: 1px dashed var(--border); border-radius: 6px;">
                <p style="color: var(--text-dim); font-size: 12px; font-style: italic; margin: 0;">
                    Cloud Intelligence checks were bypassed under current scan profile.
                </p>
                <span style="font-size: 10px; color: var(--text-dim); border: 1px solid var(--border); padding: 3px 10px; border-radius: 4px; letter-spacing: 1px; font-weight: bold;">API COLD</span>
            </div>
            """
        else:
            api_rows = ""
            for idx, d in enumerate(api_res["details"], 1):
                votes = d.get("malicious_votes", 0)
                total = d.get("total_votes", 0)
                status_text = "HARMFUL DETECTED" if votes > 0 else "NO MATCH / SECURE"
                status_style = "color: var(--danger); font-weight: bold;" if votes > 0 else "color: var(--safe);"
                
                sha = d.get('sha256', 'N/A')
                sha_display = f"{sha[:16]}..." if sha and len(sha) > 16 else sha
                
                api_rows += f"""
                <tr>
                    <td style="color: var(--text-dim);">{idx:02d}</td>
                    <td style="font-family: monospace; color: var(--text-dim);" title="{sha}">{sha_display}</td>
                    <td style="font-weight: bold; color: var(--accent);">{d.get('provider', 'Multi-API Cloud')}</td>
                    <td style="{status_style}">{status_text} ({votes}/{total})</td>
                </tr>
                """
            api_section = f"""
            <div style="margin-bottom: 15px; display: flex; justify-content: space-between; align-items: center; font-size: 11px; letter-spacing: 1px;">
                <div>Hashes Queried: <span style="color: var(--accent); font-weight: bold;">{api_res.get('queries', 0)}</span></div>
                <div>Cloud Threats: <span style="color: var(--danger); font-weight: bold;">{api_res.get('detections', 0)}</span></div>
                <div>API Node: <span style="color: var(--safe); font-weight: bold;">{api_res.get('status', 'Online')}</span></div>
            </div>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 5%;">#</th>
                            <th style="width: 55%;">Hash (SHA256)</th>
                            <th style="width: 20%;">Query Endpoint</th>
                            <th style="width: 20%;">Global Consensus</th>
                        </tr>
                    </thead>
                    <tbody>
                        {api_rows}
                    </tbody>
                </table>
            </div>
            """

        # Build timeline HTML
        timeline_items = ""
        for item in norm["timeline"]:
            timeline_items += f"""
            <div class="timeline-item">
                <div class="timeline-time">[{item.get('time', '')}]</div>
                <div class="timeline-event">{item.get('event', '')}</div>
            </div>
            """

        # Build recommendations HTML
        recommendations_items = ""
        for r in norm["recommendations"]:
            rec_class = "danger" if has_threats else ""
            recommendations_items += f"""
            <li class="{rec_class}">{r}</li>
            """

        # Render CLEAN stamp if no threats found
        clean_stamp_html = ""
        if not has_threats:
            clean_stamp_html = """
            <div style="text-align: center; margin: 15px 0 25px 0;">
                <div class="clean-stamp">SENTINEL CLEAN</div>
            </div>
            """

        scanned_val = norm["files_scanned"]
        threats_val = norm["threats_found"]
        duration_val = f"{norm['duration_seconds']:.2f}s"
        quarantined_val = norm["files_quarantined"]

        # Build the final HTML document string
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SENTINEL GUARD — Cyber Scan Report [{norm['scan_id']}]</title>
<style>
  :root {{
    --bg: #050810;
    --bg2: #0a0f1e;
    --panel: #0d1424;
    --panel2: #121d36;
    --accent: #00e5ff;
    --accent2: #00b8d4;
    --accent3: #7c4dff;
    --accent4: #ff00aa;
    --danger: #ff3b5c;
    --safe: #00e676;
    --warn: #ffc400;
    --text: #e8eef7;
    --text-dim: #5a6b80;
    --border: #1a2a45;
  }}
  * {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }}
  body {{
    background-color: var(--bg);
    color: var(--text);
    font-family: 'Courier New', Courier, monospace;
    line-height: 1.6;
    padding: 30px;
    background-image: linear-gradient(rgba(0, 229, 255, 0.015) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(0, 229, 255, 0.015) 1px, transparent 1px);
    background-size: 40px 40px;
  }}
  .container {{
    max-width: 1100px;
    margin: 0 auto;
    position: relative;
  }}
  /* Header section */
  .header {{
    text-align: center;
    border-bottom: 2px solid var(--border);
    padding-bottom: 25px;
    margin-bottom: 30px;
    position: relative;
  }}
  .header::after {{
    content: '';
    position: absolute;
    bottom: -2px;
    left: 20%;
    right: 20%;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
  }}
  .brand {{
    font-size: 32px;
    font-weight: 900;
    letter-spacing: 6px;
    text-transform: uppercase;
    color: var(--text);
    text-shadow: 0 0 15px rgba(0, 229, 255, 0.4);
    margin-bottom: 5px;
  }}
  .brand span {{
    color: var(--accent);
  }}
  .subtitle {{
    font-size: 11px;
    color: var(--text-dim);
    letter-spacing: 4px;
    text-transform: uppercase;
  }}
  .report-meta {{
    font-size: 11px;
    color: var(--accent);
    margin-top: 10px;
    letter-spacing: 1px;
  }}
  
  /* Grid dashboard for stats */
  .grid-stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 15px;
    margin-bottom: 30px;
  }}
  .stat-card {{
    background-color: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  .stat-card::before {{
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
  }}
  .stat-label {{
    font-size: 11px;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 2px;
    margin-bottom: 10px;
  }}
  .stat-val {{
    font-size: 28px;
    font-weight: bold;
    color: var(--accent);
  }}
  .stat-val.danger {{
    color: var(--danger);
    text-shadow: 0 0 10px rgba(255, 59, 92, 0.3);
  }}
  .stat-val.safe {{
    color: var(--safe);
  }}
  .stat-val.warn {{
    color: var(--warn);
  }}
  
  /* Panels */
  .panel {{
    background-color: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 25px;
    margin-bottom: 30px;
  }}
  .panel-title {{
    font-size: 14px;
    font-weight: bold;
    color: var(--accent);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 20px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .panel-title span.badge {{
    font-size: 10px;
    background-color: rgba(0, 229, 255, 0.1);
    color: var(--accent);
    padding: 2px 10px;
    border-radius: 12px;
    border: 1px solid var(--accent);
  }}
  .panel-title span.badge.danger {{
    background-color: rgba(255, 59, 92, 0.1);
    color: var(--danger);
    border-color: var(--danger);
  }}
  
  /* Tables */
  .table-responsive {{
    overflow-x: auto;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
    text-align: left;
  }}
  th {{
    color: var(--text-dim);
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 1px;
    padding: 12px 10px;
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 12px 10px;
    border-bottom: 1px solid rgba(26, 42, 69, 0.5);
    word-break: break-all;
  }}
  tr:last-child td {{
    border-bottom: none;
  }}
  
  /* Highlighting and Pills */
  .severity-pill {{
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: bold;
    text-transform: uppercase;
    display: inline-block;
  }}
  .severity-pill.critical, .severity-pill.high {{
    background-color: rgba(255, 59, 92, 0.15);
    color: var(--danger);
    border: 1px solid var(--danger);
  }}
  .severity-pill.medium {{
    background-color: rgba(255, 196, 0, 0.15);
    color: var(--warn);
    border: 1px solid var(--warn);
  }}
  .severity-pill.low {{
    background-color: rgba(0, 229, 255, 0.15);
    color: var(--accent);
    border: 1px solid var(--accent);
  }}
  .action-taken {{
    color: var(--safe);
    font-weight: bold;
  }}
  
  /* Timeline */
  .timeline {{
    position: relative;
    padding-left: 20px;
  }}
  .timeline::before {{
    content: '';
    position: absolute;
    top: 5px;
    bottom: 5px;
    left: 4px;
    width: 2px;
    background-color: var(--border);
  }}
  .timeline-item {{
    position: relative;
    padding-bottom: 15px;
  }}
  .timeline-item:last-child {{
    padding-bottom: 0;
  }}
  .timeline-item::before {{
    content: '';
    position: absolute;
    top: 6px;
    left: -20px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background-color: var(--accent);
    box-shadow: 0 0 8px var(--accent);
  }}
  .timeline-time {{
    font-size: 10px;
    color: var(--accent3);
    font-weight: bold;
    margin-bottom: 3px;
  }}
  .timeline-event {{
    font-size: 12px;
    color: var(--text);
  }}
  
  /* Lists */
  ul.custom-list {{
    list-style: none;
  }}
  ul.custom-list li {{
    position: relative;
    padding-left: 20px;
    margin-bottom: 10px;
    font-size: 12px;
  }}
  ul.custom-list li::before {{
    content: '▶';
    position: absolute;
    left: 0;
    color: var(--accent);
    font-size: 10px;
    top: 1px;
  }}
  ul.custom-list li.danger::before {{
    color: var(--danger);
  }}
  
  /* Footer */
  .footer {{
    text-align: center;
    font-size: 10px;
    color: var(--text-dim);
    margin-top: 50px;
    border-top: 1px solid var(--border);
    padding-top: 20px;
    letter-spacing: 1px;
  }}
  .clean-stamp {{
    border: 2px solid var(--safe);
    color: var(--safe);
    text-transform: uppercase;
    font-weight: bold;
    padding: 10px 20px;
    display: inline-block;
    border-radius: 4px;
    transform: rotate(-3deg);
    margin: 15px auto;
    font-size: 16px;
    letter-spacing: 2px;
    box-shadow: 0 0 15px rgba(0, 230, 118, 0.15);
  }}
</style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <div class="header">
      <div class="brand">SENTINEL <span>GUARD</span></div>
      <div class="subtitle">CYBER SCAN REPORT</div>
      <div class="report-meta">ID: {norm['scan_id']} | PATH: {norm['root_path']}</div>
    </div>

    {clean_stamp_html}

    <!-- Summary Stats -->
    <div class="grid-stats">
      <div class="stat-card">
        <div class="stat-label">Files Scanned</div>
        <div class="stat-val">{scanned_val}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Threats Detected</div>
        <div class="stat-val {threat_status_class}">{threats_val}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Isolated (Quarantine)</div>
        <div class="stat-val {threat_status_class if quarantined_val > 0 else 'safe'}">{quarantined_val}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Scan Duration</div>
        <div class="stat-val">{duration_val}</div>
      </div>
    </div>

    <!-- Threat Details Table -->
    <div class="panel">
      <div class="panel-title">
        Threat Analysis Results
        <span class="badge {threat_status_class}">{threat_status_text}</span>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th style="width: 4%;">#</th>
              <th style="width: 22%;">Threat Name</th>
              <th style="width: 10%;">Type</th>
              <th style="width: 10%;">Severity</th>
              <th style="width: 32%;">Infected Path</th>
              <th style="width: 12%;">SHA256</th>
              <th style="width: 10%;">Action Taken</th>
            </tr>
          </thead>
          <tbody>
            {threats_rows}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Heuristic Flags Panel -->
    <div class="panel">
      <div class="panel-title">
        Heuristic / Behavioral Telemetry
        <span class="badge">ANALYZER ACTIVE</span>
      </div>
      {heuristic_section}
    </div>

    <!-- API Cloud Intelligence Panel -->
    <div class="panel">
      <div class="panel-title">
        Cloud Intelligence & API Analysis
        <span class="badge">INTELLIGENCE SYNCED</span>
      </div>
      {api_section}
    </div>

    <!-- Two columns: Timeline and Recommendations -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 15px;">
      <!-- Timeline Panel -->
      <div class="panel">
        <div class="panel-title">System Scan Log Timeline</div>
        <div class="timeline">
          {timeline_items}
        </div>
      </div>

      <!-- Recommendations Panel -->
      <div class="panel">
        <div class="panel-title">Cybersecurity Guidelines</div>
        <ul class="custom-list">
          {recommendations_items}
        </ul>
      </div>
    </div>

    <!-- Footer -->
    <div class="footer">
      SENTINEL GUARD AV v3.8+ © {time.strftime('%Y')} | SECURING THE NETOSPHERE. ALL RIGHTS RESERVED.
    </div>
  </div>
</body>
</html>"""
        return html_content

    def _normalize_report(self, report: Any) -> Dict[str, Any]:
        """
        Normalize various input formats (dict, ScanReport objects) into a standard dictionary.
        
        Args:
            report: Input report.
            
        Returns:
            A standard dictionary schema with all report fields.
        """
        if isinstance(report, dict):
            # Already a dict, ensure all fields are present with correct schemas
            normalized = {}
            summary = report.get("summary", {})
            
            # Metadata & stats
            normalized["scan_id"] = report.get("scan_id") or summary.get("scan_id") or "SG-SCAN-" + str(int(time.time()))
            normalized["started_at"] = report.get("started_at") or summary.get("start_time") or summary.get("started_at") or time.strftime("%Y-%m-%d %H:%M:%S")
            normalized["finished_at"] = report.get("finished_at") or summary.get("end_time") or summary.get("finished_at") or time.strftime("%Y-%m-%d %H:%M:%S")
            normalized["root_path"] = report.get("root_path") or summary.get("root_path") or summary.get("scanned_path") or "/"
            normalized["duration_seconds"] = float(report.get("duration_seconds") or summary.get("duration_seconds") or summary.get("duration") or summary.get("scan_duration") or 0.0)
            normalized["files_scanned"] = int(report.get("files_scanned") or summary.get("files_scanned") or summary.get("scanned_files") or 0)
            normalized["threats_found"] = int(report.get("threats_found") or summary.get("threats_found") or summary.get("threats") or 0)
            normalized["files_quarantined"] = int(report.get("files_quarantined") or summary.get("files_quarantined") or summary.get("quarantined") or 0)
            normalized["clean_files"] = int(report.get("clean_files") or summary.get("clean_files") or max(0, normalized["files_scanned"] - normalized["threats_found"]))
            
            normalized["errors"] = list(report.get("errors") or [])
            normalized["threats"] = list(report.get("threats") or [])
            normalized["heuristic_flags"] = list(report.get("heuristic_flags") or [])
            
            api_res = report.get("api_results", {})
            if isinstance(api_res, dict):
                normalized["api_results"] = {
                    "status": api_res.get("status", "Inactive"),
                    "queries": int(api_res.get("queries", 0)),
                    "detections": int(api_res.get("detections", 0)),
                    "details": list(api_res.get("details", []))
                }
            else:
                normalized["api_results"] = {"status": "Inactive", "queries": 0, "detections": 0, "details": []}
                
            normalized["timeline"] = list(report.get("timeline") or [])
            normalized["recommendations"] = list(report.get("recommendations") or [])
            
            # If timeline or recommendations are empty, auto-generate them
            if not normalized["timeline"]:
                normalized["timeline"] = self._generate_default_timeline(normalized)
            if not normalized["recommendations"]:
                normalized["recommendations"] = self._generate_default_recommendations(normalized)
                
            return normalized

        # Handle dataclass objects (like ScanReport)
        normalized = {}
        normalized["scan_id"] = str(getattr(report, "scan_id", "SG-SCAN-" + str(int(time.time()))))
        normalized["started_at"] = str(getattr(report, "started_at", time.strftime("%Y-%m-%d %H:%M:%S")))
        normalized["finished_at"] = str(getattr(report, "finished_at", time.strftime("%Y-%m-%d %H:%M:%S")))
        normalized["root_path"] = str(getattr(report, "root_path", "/"))
        normalized["duration_seconds"] = float(getattr(report, "scan_duration", 0.0))
        normalized["files_scanned"] = int(getattr(report, "scanned_files", 0))
        normalized["threats_found"] = int(getattr(report, "threats_found", 0))
        normalized["files_quarantined"] = int(getattr(report, "files_quarantined", 0))
        normalized["clean_files"] = int(getattr(report, "clean_files", max(0, normalized["files_scanned"] - normalized["threats_found"])))
        normalized["errors"] = list(getattr(report, "errors", []))
        
        threats = []
        heuristic_flags = []
        api_details = []
        api_queries = 0
        api_detections = 0
        
        # Iterate scan results list to pull out threat rows and heuristics
        results = getattr(report, "results", [])
        for res in results:
            is_threat = False
            threat_level_val = "clean"
            
            # Extract threat level
            tl = getattr(res, "threat_level", None)
            if tl:
                if isinstance(tl, Enum):
                    threat_level_val = tl.value
                else:
                    threat_level_val = str(tl).lower()
                    
            if threat_level_val != "clean":
                is_threat = True
                
            is_threat_bool = bool(getattr(res, "is_threat", is_threat) or is_threat)
            
            # Extract basic threat attributes
            threat_name = getattr(res, "threat_name", "")
            file_path = getattr(res, "file_path", "")
            threat_type = getattr(res, "threat_type", "signature")
            sha256 = getattr(res, "sha256", "")
            
            if is_threat_bool:
                # Deduce quarantine vs checked status
                quarantined = normalized["files_quarantined"] > 0
                action = "Quarantined" if quarantined else "Detected/Blocked"
                
                threats.append({
                    "name": threat_name or "Generic.Malware",
                    "file": file_path,
                    "type": threat_type or "signature",
                    "severity": threat_level_val.upper(),
                    "sha256": sha256,
                    "action_taken": action
                })
                
            # Extract heuristic flags from results
            h_flags = getattr(res, "heuristic_flags", [])
            h_score = getattr(res, "heuristic_score", 0)
            if h_flags or h_score > 0 or threat_type == "heuristic":
                flags_list = h_flags if isinstance(h_flags, list) else [h_flags]
                for flag in flags_list:
                    heuristic_flags.append({
                        "file": file_path,
                        "flag": str(flag),
                        "score": h_score
                    })
                    
            # Extract API cloud results from detections
            if threat_type == "api_cloud" or "api_detection" in "".join(str(f) for f in h_flags).lower():
                api_queries += 1
                api_detections += 1
                api_details.append({
                    "sha256": sha256,
                    "malicious_votes": 1,
                    "total_votes": 1,
                    "provider": "Multi-API Cloud"
                })
                
        normalized["threats"] = threats
        normalized["heuristic_flags"] = heuristic_flags
        
        # Pull API results dictionary if custom attached
        api_results_attr = getattr(report, "api_results", None)
        if isinstance(api_results_attr, dict):
            normalized["api_results"] = {
                "status": api_results_attr.get("status", "Online" if api_queries > 0 else "Inactive"),
                "queries": int(api_results_attr.get("queries", api_queries)),
                "detections": int(api_results_attr.get("detections", api_detections)),
                "details": list(api_results_attr.get("details", api_details))
            }
        else:
            normalized["api_results"] = {
                "status": "Online" if api_queries > 0 else "Inactive",
                "queries": api_queries,
                "detections": api_detections,
                "details": api_details
            }
            
        normalized["timeline"] = list(getattr(report, "timeline", []))
        if not normalized["timeline"]:
            normalized["timeline"] = self._generate_default_timeline(normalized)
            
        normalized["recommendations"] = list(getattr(report, "recommendations", []))
        if not normalized["recommendations"]:
            normalized["recommendations"] = self._generate_default_recommendations(normalized)
            
        return normalized

    def _generate_default_timeline(self, norm: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate automatic, realistic chronologically logged events for the scan."""
        timeline = []
        started_time_str = norm["started_at"]
        
        # Safely extract time part HH:MM:SS
        try:
            time_only = started_time_str[-8:] if len(started_time_str) >= 8 else started_time_str
        except Exception:
            time_only = started_time_str

        timeline.append({"time": time_only, "event": f"Scanner Core initiated. Target path locked: {norm['root_path']}"})
        timeline.append({"time": time_only, "event": f"File discovery complete. Walked {norm['files_scanned']} directory node objects."})
        
        if norm["threats_found"] > 0:
            timeline.append({"time": time_only, "event": f"ALERT: Detected {norm['threats_found']} potential malware signature matches."})
            if norm["files_quarantined"] > 0:
                timeline.append({"time": time_only, "event": f"ACTION: Quarantined {norm['files_quarantined']} threat file payloads successfully."})
        else:
            timeline.append({"time": time_only, "event": "Heuristic & Signature lookup finished. Clean result."})
            
        if norm["api_results"]["queries"] > 0:
            timeline.append({"time": time_only, "event": f"Cloud Reputation Node queried. Detections: {norm['api_results']['detections']}"})
            
        timeline.append({"time": time_only, "event": f"Scan completed successfully in {norm['duration_seconds']:.2f} seconds."})
        return timeline

    def _generate_default_recommendations(self, norm: Dict[str, Any]) -> List[str]:
        """Generate context-aware cybersecurity guidelines."""
        recs = []
        if norm["threats_found"] == 0:
            recs.append("SYSTEM STATUS SECURE. No actions are required at this time.")
            recs.append("Recommend scheduling a weekly Full system scan to ensure ongoing security posture.")
            recs.append("Ensure regular threat signature updates are successfully downloaded.")
            recs.append("Keep Sentinel Guard Real-time Monitor active in the system background.")
        else:
            recs.append("CRITICAL: Isolate infected directories or files immediately to avoid risk of propagation.")
            recs.append("Action recommended: Permanently purge or shred files placed in the Quarantine directory.")
            recs.append("Initiate Sentinel Guard Process Scan to check memory for active hidden sub-processes.")
            recs.append("Perform a full network interface trace to audit connections made by unknown hosts.")
            recs.append("Execute a complete offline Sentinel Deep Scan to achieve maximum assurance.")
        return recs
