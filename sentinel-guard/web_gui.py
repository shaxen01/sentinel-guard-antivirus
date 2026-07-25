"""
Sentinel Guard — Web GUI Server v3.0
Flask-based modern web interface for the antivirus engine with all modules
"""
import os
import sys
import json
import time
import threading
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, send_file, Response
from engine.parallel_scanner import ParallelScanner
from engine.api_scanner import APIScanner
from engine.archive_scanner import ArchiveScanner
from engine.quarantine import QuarantineManager
from engine.signatures import SignatureDatabase
from engine.whitelist import Whitelist
from engine.scheduler import ScanScheduler
from engine.process_scanner import ProcessScanner
from engine.network_scanner import NetworkScanner
from engine.startup_scanner import StartupScanner
from engine.monitor import FileMonitor
from engine.scanner import ThreatLevel
from engine.url_scanner import URLScanner
from engine.yara_scanner import YaraScanner
from engine.document_scanner import DocumentScanner
from engine.script_deobfuscator import ScriptDeobfuscator
from engine.pe_analyzer import PEAnalyzer
from engine.hosts_scanner import HostsScanner
from engine.browser_scanner import BrowserScanner
from engine.rootkit_scanner import RootkitScanner
from engine.ml_detector import MLDetector
from engine.incident_response import IncidentResponse
from engine.notifier import Notifier
from engine.report_generator import ReportGenerator
from engine.scan_profile import ScanProfile
from engine.api_key_manager import APIKeyManager
from engine.threat_feed import ThreatFeedManager
from engine.db_tools import DBTools
from engine.string_extractor import StringExtractor
from engine.file_type_analyzer import FileTypeAnalyzer
from utils.logger import get_logger

logger = get_logger("sentinel-web")

app = Flask(__name__, static_folder='static', static_url_path='')

# Initialize all components
api_scanner = APIScanner()
scanner = ParallelScanner(enable_api_scan=True, api_scanner=api_scanner)
archive_scanner = ArchiveScanner(scanner)
quarantine = scanner.quarantine
sig_db = scanner.sig_db
whitelist = scanner.whitelist
scheduler = ScanScheduler()
process_scanner = ProcessScanner(sig_db)
network_scanner = NetworkScanner()
startup_scanner = StartupScanner()
url_scanner = URLScanner()
yara_scanner = YaraScanner()
doc_scanner = DocumentScanner()
deobfuscator = ScriptDeobfuscator()
pe_analyzer = PEAnalyzer()
hosts_scanner = HostsScanner()
browser_scanner = BrowserScanner()
rootkit_scanner = RootkitScanner()
ml_detector = MLDetector()
incident_resp = IncidentResponse()
notifier = Notifier()
report_gen = ReportGenerator()
scan_profile = ScanProfile()
api_key_mgr = APIKeyManager()
threat_feed_mgr = ThreatFeedManager("data/signatures.db")
string_extractor = StringExtractor()
file_type_analyzer = FileTypeAnalyzer()

scan_state = {
    "scanning": False, "progress": 0, "current_file": "",
    "threats": [], "scanned": 0, "total": 0, "start_time": 0,
    "log": [], "api_results": [], "scan_mode": "full",
}
monitor = None


@app.route('/')
def index():
    gui_path = Path(__file__).parent / 'static' / 'gui.html'
    if gui_path.exists():
        return send_file(str(gui_path))
    return jsonify({"error": "GUI file not found"}), 404


@app.route('/api/status')
def api_status():
    stats = sig_db.get_stats()
    q_stats = quarantine.get_stats()
    apis = api_scanner.get_available_apis()
    return jsonify({
        "engine": "SENTINEL-CORE v3.0.0",
        "scanning": scan_state["scanning"],
        "signatures": stats,
        "quarantine": q_stats,
        "whitelist_count": whitelist.count(),
        "apis": apis,
        "schedules": scheduler.list_schedules(),
        "modules": 31,
        "yara_loaded": yara_scanner.rules_loaded if hasattr(yara_scanner, 'rules_loaded') else 0,
        "ml_trained": ml_detector.is_trained if hasattr(ml_detector, 'is_trained') else False,
    })


@app.route('/api/scan', methods=['POST'])
def api_scan():
    if scan_state["scanning"]:
        return jsonify({"error": "Scan already in progress"}), 409
    data = request.json or {}
    path = data.get("path", os.path.expanduser("~"))
    profile_name = data.get("profile", "full")

    if profile_name and profile_name != "custom":
        prof = scan_profile.get_profile(profile_name)
        recursive = prof.recursive
        auto_quarantine = prof.auto_quarantine
        enable_api = prof.enable_api
        scan_archives = prof.scan_archives
        max_workers = prof.max_workers
    else:
        recursive = data.get("recursive", True)
        auto_quarantine = data.get("auto_quarantine", False)
        enable_api = data.get("enable_api", True)
        scan_archives = data.get("scan_archives", True)
        max_workers = int(data.get("max_workers", 8))

    if not os.path.exists(path):
        return jsonify({"error": f"Path not found: {path}"}), 400

    def run_scan():
        scan_state.update({"scanning": True, "progress": 0, "threats": [],
                           "scanned": 0, "log": [], "api_results": [], "start_time": time.time(),
                           "scan_mode": profile_name})
        scanner.enable_api_scan = enable_api
        scanner.max_workers = max_workers

        def progress(current, total, result):
            scan_state["scanned"] = current
            scan_state["total"] = total
            scan_state["progress"] = (current / total * 100) if total > 0 else 0
            scan_state["current_file"] = result.file_name
            if result.is_threat:
                scan_state["threats"].append({
                    "file": result.file_name, "path": result.file_path,
                    "threat": result.threat_name, "level": result.threat_level.value,
                    "type": result.threat_type, "sha256": result.sha256,
                    "flags": result.heuristic_flags,
                })
            scan_state["log"].append({
                "time": time.strftime("%H:%M:%S"), "file": result.file_name,
                "status": "threat" if result.is_threat else "clean",
                "threat": result.threat_name if result.is_threat else "",
            })
            if len(scan_state["log"]) > 200:
                scan_state["log"] = scan_state["log"][-200:]

        report = scanner.scan_directory_parallel(
            path, recursive=recursive, auto_quarantine=auto_quarantine,
            progress_callback=progress)

        if scan_archives:
            import glob
            for ext in ['*.zip', '*.tar', '*.tar.gz', '*.tgz']:
                for af in glob.glob(os.path.join(path, '**', ext), recursive=recursive):
                    arch_results = archive_scanner.scan_archive(af, auto_quarantine)
                    for r in arch_results:
                        if r.is_threat:
                            scan_state["threats"].append({
                                "file": r.file_name, "path": r.file_path,
                                "threat": r.threat_name, "level": r.threat_level.value,
                                "type": f"archive_{r.threat_type}", "sha256": r.sha256,
                                "flags": r.heuristic_flags,
                            })

        scan_state["scanning"] = False
        scan_state["progress"] = 100

        # API results
        for ar in scanner.get_api_results():
            if ar.is_threat:
                scan_state["api_results"].append({
                    "sha256": ar.sha256[:16] + "...",
                    "detected": ar.total_detected, "total": ar.total_queried,
                    "apis": [{"name": r.api_name, "detected": r.detected,
                              "threat": r.threat_name, "time": f"{r.response_time:.2f}s"}
                             for r in ar.results],
                })

        # Notify if threats found
        if scan_state["threats"]:
            notifier.send_alert(
                "Sentinel Guard — Tehdit Tespit Edildi",
                f"{len(scan_state['threats'])} tehdit tespit edildi.",
                "high"
            )

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    return jsonify({"status": "scan_started", "path": path, "profile": profile_name})


@app.route('/api/scan/progress')
def api_scan_progress():
    return jsonify({
        "scanning": scan_state["scanning"],
        "progress": round(scan_state["progress"], 1),
        "scanned": scan_state["scanned"], "total": scan_state["total"],
        "current_file": scan_state.get("current_file", ""),
        "threats_found": len(scan_state["threats"]),
        "threats": scan_state["threats"][-20:],
        "log": scan_state["log"][-30:],
        "api_results": scan_state.get("api_results", []),
        "elapsed": time.time() - scan_state["start_time"] if scan_state["scanning"] else 0,
        "speed": (scan_state["scanned"] / max(time.time() - scan_state["start_time"], 0.1))
                 if scan_state["scanning"] else 0,
        "scan_mode": scan_state.get("scan_mode", "full"),
    })


@app.route('/api/scan/stop', methods=['POST'])
def api_scan_stop():
    scanner.stop()
    return jsonify({"status": "stop_requested"})


# Quarantine
@app.route('/api/quarantine')
def api_quarantine():
    return jsonify({"items": quarantine.list_quarantined(), "stats": quarantine.get_stats()})

@app.route('/api/quarantine/restore', methods=['POST'])
def api_quarantine_restore():
    return jsonify({"success": quarantine.restore_file((request.json or {}).get("id", ""))})

@app.route('/api/quarantine/delete', methods=['POST'])
def api_quarantine_delete():
    return jsonify({"success": quarantine.delete_file((request.json or {}).get("id", ""))})

@app.route('/api/quarantine/clear', methods=['POST'])
def api_quarantine_clear():
    return jsonify({"deleted": quarantine.clear_all()})


# Processes
@app.route('/api/processes')
def api_processes():
    all_procs = process_scanner.scan_processes()
    suspicious = [p for p in all_procs if p.is_suspicious]
    return jsonify({
        "total": len(all_procs), "suspicious_count": len(suspicious),
        "suspicious": [{"pid": p.pid, "name": p.name, "path": p.path, "reason": p.reason,
                        "memory_mb": round(p.memory_mb, 1)} for p in suspicious],
        "all": [{"pid": p.pid, "name": p.name, "memory_mb": round(p.memory_mb, 1),
                 "suspicious": p.is_suspicious} for p in all_procs[:50]],
    })


# Network
@app.route('/api/network')
def api_network():
    all_conns = network_scanner.scan_connections()
    suspicious = [c for c in all_conns if c.is_suspicious]
    return jsonify({
        "total": len(all_conns), "suspicious_count": len(suspicious),
        "suspicious": [{"protocol": c.protocol, "remote_addr": c.remote_addr,
                        "remote_port": c.remote_port, "state": c.state, "pid": c.pid,
                        "reason": c.reason} for c in suspicious],
        "all": [{"protocol": c.protocol, "remote_addr": c.remote_addr,
                 "remote_port": c.remote_port, "state": c.state, "pid": c.pid,
                 "suspicious": c.is_suspicious} for c in all_conns[:50]],
    })


# Startup
@app.route('/api/startup')
def api_startup():
    all_entries = startup_scanner.scan_all()
    suspicious = [e for e in all_entries if e.is_suspicious]
    return jsonify({
        "total": len(all_entries), "suspicious_count": len(suspicious),
        "all": [{"name": e.name, "path": e.path, "type": e.type,
                 "suspicious": e.is_suspicious, "reason": e.reason} for e in all_entries],
    })


# Hosts
@app.route('/api/hosts')
def api_hosts():
    entries = hosts_scanner.scan()
    return jsonify({
        "total": len(entries),
        "suspicious_count": len([e for e in entries if e.is_suspicious]),
        "entries": [{"ip": e.ip, "hostname": e.hostname, "suspicious": e.is_suspicious,
                     "reason": e.reason} for e in entries],
    })


# Browser extensions
@app.route('/api/browser')
def api_browser():
    exts = browser_scanner.scan_all()
    return jsonify({
        "total": len(exts),
        "suspicious_count": len([e for e in exts if e.is_suspicious]),
        "extensions": [{"browser": e.browser, "name": e.name, "version": e.version,
                        "permissions": e.permissions, "suspicious": e.is_suspicious,
                        "reason": e.reason} for e in exts],
    })


# Rootkit
@app.route('/api/rootkit')
def api_rootkit():
    result = rootkit_scanner.scan()
    return jsonify({
        "checks_passed": result.checks_passed,
        "checks_failed": result.checks_failed,
        "indicators": result.indicators,
        "risk_score": result.risk_score,
    })


# URL Scanner
@app.route('/api/url/scan', methods=['POST'])
def api_url_scan():
    data = request.json or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL required"}), 400
    result = url_scanner.scan_url(url)
    return jsonify({
        "url": result.url, "is_malicious": result.is_malicious,
        "threat_name": result.threat_name, "source": result.source,
        "risk_score": result.risk_score, "flags": result.heuristic_flags,
    })


# Document Scanner
@app.route('/api/document/scan', methods=['POST'])
def api_doc_scan():
    data = request.json or {}
    path = data.get("path", "")
    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 400
    result = doc_scanner.scan_file(path)
    return jsonify({
        "file_path": result.file_path, "file_type": result.file_type,
        "has_macros": result.has_macros, "has_javascript": result.has_javascript,
        "has_embedded_files": result.has_embedded_files,
        "has_suspicious_actions": result.has_suspicious_actions,
        "risk_score": result.risk_score, "threats": result.threats,
    })


# Script Deobfuscator
@app.route('/api/deobfuscate', methods=['POST'])
def api_deobfuscate():
    data = request.json or {}
    content = data.get("content", "")
    script_type = data.get("type", "auto")
    if not content:
        return jsonify({"error": "Content required"}), 400
    result = deobfuscator.detect_obfuscation(content, script_type)
    return jsonify({
        "is_obfuscated": result.is_obfuscated, "techniques": result.techniques,
        "deobfuscated": result.deobfuscated_content[:2000],
        "iocs": result.iocs, "risk_score": result.risk_score,
    })


# PE Analyzer
@app.route('/api/pe/analyze', methods=['POST'])
def api_pe_analyze():
    data = request.json or {}
    path = data.get("path", "")
    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 400
    result = pe_analyzer.analyze(path)
    return jsonify({
        "is_pe": result.is_pe, "is_dll": result.is_dll, "is_64bit": result.is_64bit,
        "machine": result.machine, "timestamp": result.timestamp,
        "num_sections": result.num_sections, "imphash": result.imphash,
        "anomalies": result.anomalies, "risk_score": result.risk_score,
        "imports": [{"dll": i.dll, "functions": i.functions[:20]} for i in result.imports[:20]],
    })


# String Extractor
@app.route('/api/strings', methods=['POST'])
def api_strings():
    data = request.json or {}
    path = data.get("path", "")
    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 400
    with open(path, 'rb') as f:
        content = f.read(2 * 1024 * 1024)
    strings = string_extractor.extract(content)
    analysis = string_extractor.analyze_strings(strings)
    return jsonify({
        "total_strings": analysis.total_strings,
        "urls": analysis.contains_urls[:20],
        "ips": analysis.contains_ips[:20],
        "paths": analysis.contains_paths[:20],
        "registry_keys": analysis.contains_registry_keys[:20],
        "suspicious": analysis.suspicious_strings[:20],
    })


# File Type Analyzer
@app.route('/api/filetype', methods=['POST'])
def api_filetype():
    data = request.json or {}
    path = data.get("path", "")
    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 400
    result = file_type_analyzer.analyze(path)
    return jsonify({
        "extension": result.extension, "detected_type": result.detected_type,
        "mime_type": result.mime_type, "encoding": result.encoding,
        "entropy": result.entropy, "is_packed": result.is_packed,
        "packer_name": result.packer_name, "is_polyglot": result.is_polyglot,
        "is_suspicious": result.is_suspicious, "reasons": result.suspicion_reasons,
    })


# ML Detector
@app.route('/api/ml/predict', methods=['POST'])
def api_ml_predict():
    data = request.json or {}
    path = data.get("path", "")
    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 400
    with open(path, 'rb') as f:
        content = f.read(2 * 1024 * 1024)
    result = ml_detector.predict(content)
    return jsonify({
        "score": result.score, "is_malicious": result.is_malicious,
        "confidence": result.confidence, "top_features": result.top_features,
    })


@app.route('/api/ml/train', methods=['POST'])
def api_ml_train():
    # Train on existing threats in quarantine + clean files
    malware_samples = []
    for item in quarantine.list_quarantined():
        try:
            with open(item["quarantined_path"], 'rb') as f:
                malware_samples.append(f.read(1024 * 1024))
        except:
            pass
    # Use heuristic-detected files as malware samples
    if len(malware_samples) < 2:
        return jsonify({"error": "Not enough samples to train (need 2+)"}), 400
    benign_samples = [b"Hello World" * 100, b"print('hello')" * 100]
    ml_detector.train(malware_samples, benign_samples)
    ml_detector.save_model("data/ml_model.json")
    return jsonify({"status": "trained", "malware_samples": len(malware_samples)})


# Report
@app.route('/api/report/html', methods=['POST'])
def api_report_html():
    data = request.json or {}
    # Generate from current scan state
    class FakeReport:
        pass
    report = FakeReport()
    report.scan_id = f"scan_{int(time.time())}"
    report.started_at = time.strftime("%Y-%m-%d %H:%M:%S")
    report.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
    report.root_path = data.get("path", "")
    report.total_files = scan_state["total"]
    report.scanned_files = scan_state["scanned"]
    report.threats_found = len(scan_state["threats"])
    report.files_quarantined = quarantine.get_stats()["total_files"]
    report.scan_duration = 0
    report.results = []
    report.errors = []
    report.clean_files = scan_state["scanned"] - len(scan_state["threats"])

    output = f"reports/report_{int(time.time())}.html"
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    report_gen.generate_html(report, output)
    return send_file(output, as_attachment=True, download_name="sentinel_report.html")


# Update signatures
@app.route('/api/update', methods=['POST'])
def api_update():
    count = sig_db.update_from_malwarebazaar(limit=100)
    stats = sig_db.get_stats()
    return jsonify({"added": count, "total": stats["total_signatures"]})


# Threat feeds
@app.route('/api/feeds')
def api_feeds():
    return jsonify({"feeds": threat_feed_mgr.list_feeds()})

@app.route('/api/feeds/update', methods=['POST'])
def api_feeds_update():
    data = request.json or {}
    name = data.get("name", "")
    if name:
        count = threat_feed_mgr.update_feed(name)
    else:
        result = threat_feed_mgr.update_all()
        return jsonify(result)
    return jsonify({"added": count})


# API Keys
@app.route('/api/keys', methods=['GET', 'POST'])
def api_keys():
    if request.method == 'POST':
        data = request.json or {}
        api_key_mgr.set_key(data.get("service", ""), data.get("key", ""))
        return jsonify({"success": True})
    return jsonify({"services": api_key_mgr.list_services()})


# DB Tools
@app.route('/api/db/backup', methods=['POST'])
def api_db_backup():
    data = request.json or {}
    path = data.get("path", f"data/backup_{int(time.time())}.db")
    success = DBTools.backup("data/signatures.db", path)
    return jsonify({"success": success, "path": path})

@app.route('/api/db/optimize', methods=['POST'])
def api_db_optimize():
    result = DBTools.optimize("data/signatures.db")
    return jsonify(result)

@app.route('/api/db/stats')
def api_db_stats():
    return jsonify(DBTools.get_stats("data/signatures.db"))


# Whitelist
@app.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
def api_whitelist():
    if request.method == 'POST':
        data = request.json or {}
        if data.get("sha256"):
            whitelist.add(data["sha256"])
        elif data.get("file"):
            whitelist.add_file(data["file"])
        return jsonify({"success": True, "count": whitelist.count()})
    elif request.method == 'DELETE':
        whitelist.remove((request.json or {}).get("sha256", ""))
        return jsonify({"success": True})
    return jsonify({"hashes": whitelist.list_all(), "count": whitelist.count()})


# Scheduler
@app.route('/api/schedule', methods=['GET', 'POST'])
def api_schedule():
    if request.method == 'POST':
        data = request.json or {}
        scheduler.add_schedule(
            name=data.get("name", "scheduled_scan"),
            path=data.get("path", os.path.expanduser("~")),
            interval_minutes=data.get("interval_minutes", 60),
            auto_quarantine=data.get("auto_quarantine", False),
        )
        return jsonify({"success": True})
    return jsonify({"schedules": scheduler.list_schedules()})

@app.route('/api/schedule/<name>', methods=['DELETE'])
def api_schedule_delete(name):
    return jsonify({"success": scheduler.remove_schedule(name)})


# Monitor
@app.route('/api/monitor', methods=['POST'])
def api_monitor():
    global monitor
    data = request.json or {}
    action = data.get("action", "start")
    if action == "start":
        path = data.get("path", os.path.expanduser("~"))
        if monitor: monitor.stop()
        monitor = FileMonitor(scanner, [path])
        monitor.start()
        return jsonify({"status": "monitoring", "path": path})
    elif action == "stop":
        if monitor: monitor.stop()
        monitor = None
        return jsonify({"status": "stopped"})
    return jsonify({"status": monitor is not None})


# Scan profiles
@app.route('/api/profiles')
def api_profiles():
    return jsonify({
        "profiles": [{"name": p, **scan_profile.get_profile(p).__dict__}
                     for p in scan_profile.list_profiles()]
    })


# Incident response
@app.route('/api/incident', methods=['POST'])
def api_incident():
    data = request.json or {}
    action = data.get("action", "report")
    if action == "report":
        report = incident_resp.create_incident_report(scan_state.get("threats", []))
        return jsonify(report)
    elif action == "kill":
        pid = data.get("pid", 0)
        return jsonify({"success": incident_resp.kill_process(pid)})
    elif action == "block_ip":
        ip = data.get("ip", "")
        return jsonify({"success": incident_resp.block_ip(ip)})
    return jsonify({"error": "Unknown action"}), 400


def run_gui(host='0.0.0.0', port=8443):
    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║    🛡️  SENTINEL GUARD v3.0.0 — WEB GUI           ║")
    print("  ║    31 Engine Modules | Multi-API | Cyberpunk    ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()
    print(f"  🔗 http://localhost:{port}")
    print()
    print("  Modules: Signature | Heuristic | API(MBazaar+VT+HA+URLhaus)")
    print("           Archive | Process | Network | Startup | URL/Phish")
    print("           YARA | Document/Macro | Script Deobfuscation")
    print("           PE Analysis | Hosts | Browser | Rootkit")
    print("           ML Detection | Incident Response | Notifier")
    print("           Report Gen | Scan Profiles | Threat Feeds")
    print("           DB Tools | String Extractor | File Type Analyzer")
    print()
    print("  Press Ctrl+C to stop")
    print()
    try:
        app.run(host=host, port=port, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n  Sentinel Guard stopped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Sentinel Guard Web GUI v3.0")
    parser.add_argument('--port', '-p', type=int, default=8443)
    parser.add_argument('--host', '-H', default='0.0.0.0')
    args = parser.parse_args()
    run_gui(host=args.host, port=args.port)
