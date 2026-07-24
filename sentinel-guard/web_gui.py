"""
Sentinel Guard — Web GUI Server
Flask-based modern web interface for the antivirus engine
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
from utils.logger import get_logger

logger = get_logger("sentinel-web")

app = Flask(__name__, static_folder='static', static_url_path='')

# Initialize components
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

# Global scan state
scan_state = {
    "scanning": False,
    "progress": 0,
    "current_file": "",
    "threats": [],
    "scanned": 0,
    "total": 0,
    "start_time": 0,
    "log": [],
    "api_results": [],
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
        "engine": "SENTINEL-CORE v2.0.0",
        "scanning": scan_state["scanning"],
        "signatures": stats,
        "quarantine": q_stats,
        "whitelist_count": whitelist.count(),
        "apis": apis,
        "schedules": scheduler.list_schedules(),
    })


@app.route('/api/scan', methods=['POST'])
def api_scan():
    if scan_state["scanning"]:
        return jsonify({"error": "Scan already in progress"}), 409

    data = request.json or {}
    path = data.get("path", os.path.expanduser("~"))
    recursive = data.get("recursive", True)
    auto_quarantine = data.get("auto_quarantine", False)
    enable_api = data.get("enable_api", True)
    scan_archives = data.get("scan_archives", True)

    if not os.path.exists(path):
        return jsonify({"error": f"Path not found: {path}"}), 400

    def run_scan():
        scan_state["scanning"] = True
        scan_state["progress"] = 0
        scan_state["threats"] = []
        scan_state["scanned"] = 0
        scan_state["log"] = []
        scan_state["api_results"] = []
        scan_state["start_time"] = time.time()

        scanner.enable_api_scan = enable_api
        scanner.max_workers = int(data.get("max_workers", 8))

        def progress(current, total, result):
            scan_state["scanned"] = current
            scan_state["total"] = total
            scan_state["progress"] = (current / total * 100) if total > 0 else 0
            scan_state["current_file"] = result.file_name

            if result.is_threat:
                scan_state["threats"].append({
                    "file": result.file_name,
                    "path": result.file_path,
                    "threat": result.threat_name,
                    "level": result.threat_level.value,
                    "type": result.threat_type,
                    "sha256": result.sha256,
                    "flags": result.heuristic_flags,
                })

            entry = {
                "time": time.strftime("%H:%M:%S"),
                "file": result.file_name,
                "status": "threat" if result.is_threat else "clean",
                "threat": result.threat_name if result.is_threat else "",
            }
            scan_state["log"].append(entry)
            if len(scan_state["log"]) > 200:
                scan_state["log"] = scan_state["log"][-200:]

        report = scanner.scan_directory_parallel(
            path, recursive=recursive,
            auto_quarantine=auto_quarantine,
            progress_callback=progress,
        )

        # Archive scanning
        if scan_archives:
            import glob
            for ext in ['*.zip', '*.tar', '*.tar.gz', '*.tgz']:
                for archive_file in glob.glob(os.path.join(path, '**', ext), recursive=recursive):
                    arch_results = archive_scanner.scan_archive(archive_file, auto_quarantine)
                    for r in arch_results:
                        if r.is_threat:
                            scan_state["threats"].append({
                                "file": r.file_name,
                                "path": r.file_path,
                                "threat": r.threat_name,
                                "level": r.threat_level.value,
                                "type": f"archive_{r.threat_type}",
                                "sha256": r.sha256,
                                "flags": r.heuristic_flags,
                            })

        scan_state["scanning"] = False
        scan_state["progress"] = 100

        # API results
        for ar in scanner.get_api_results():
            if ar.is_threat:
                scan_state["api_results"].append({
                    "sha256": ar.sha256[:16] + "...",
                    "detected": ar.total_detected,
                    "total": ar.total_queried,
                    "apis": [{"name": r.api_name, "detected": r.detected,
                              "name": r.threat_name, "time": f"{r.response_time:.2f}s"}
                             for r in ar.results],
                })

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({"status": "scan_started", "path": path})


@app.route('/api/scan/progress')
def api_scan_progress():
    return jsonify({
        "scanning": scan_state["scanning"],
        "progress": round(scan_state["progress"], 1),
        "scanned": scan_state["scanned"],
        "total": scan_state["total"],
        "current_file": scan_state.get("current_file", ""),
        "threats_found": len(scan_state["threats"]),
        "threats": scan_state["threats"][-20:],
        "log": scan_state["log"][-30:],
        "api_results": scan_state.get("api_results", []),
        "elapsed": time.time() - scan_state["start_time"] if scan_state["scanning"] else 0,
        "speed": (scan_state["scanned"] / max(time.time() - scan_state["start_time"], 0.1))
                 if scan_state["scanning"] else 0,
    })


@app.route('/api/scan/stop', methods=['POST'])
def api_scan_stop():
    scanner.stop()
    return jsonify({"status": "stop_requested"})


@app.route('/api/quarantine')
def api_quarantine():
    return jsonify({"items": quarantine.list_quarantined(), "stats": quarantine.get_stats()})


@app.route('/api/quarantine/restore', methods=['POST'])
def api_quarantine_restore():
    data = request.json or {}
    success = quarantine.restore_file(data.get("id", ""))
    return jsonify({"success": success})


@app.route('/api/quarantine/delete', methods=['POST'])
def api_quarantine_delete():
    data = request.json or {}
    success = quarantine.delete_file(data.get("id", ""))
    return jsonify({"success": success})


@app.route('/api/quarantine/clear', methods=['POST'])
def api_quarantine_clear():
    count = quarantine.clear_all()
    return jsonify({"deleted": count})


@app.route('/api/processes')
def api_processes():
    all_procs = process_scanner.scan_processes()
    suspicious = [p for p in all_procs if p.is_suspicious]
    return jsonify({
        "total": len(all_procs),
        "suspicious_count": len(suspicious),
        "suspicious": [{
            "pid": p.pid, "name": p.name, "path": p.path,
            "reason": p.reason, "memory_mb": round(p.memory_mb, 1)
        } for p in suspicious],
        "all": [{
            "pid": p.pid, "name": p.name, "memory_mb": round(p.memory_mb, 1),
            "suspicious": p.is_suspicious
        } for p in all_procs[:50]],
    })


@app.route('/api/network')
def api_network():
    all_conns = network_scanner.scan_connections()
    suspicious = [c for c in all_conns if c.is_suspicious]
    return jsonify({
        "total": len(all_conns),
        "suspicious_count": len(suspicious),
        "suspicious": [{
            "protocol": c.protocol,
            "remote_addr": c.remote_addr,
            "remote_port": c.remote_port,
            "state": c.state,
            "pid": c.pid,
            "reason": c.reason,
        } for c in suspicious],
        "all": [{
            "protocol": c.protocol,
            "remote_addr": c.remote_addr,
            "remote_port": c.remote_port,
            "state": c.state,
            "pid": c.pid,
            "suspicious": c.is_suspicious
        } for c in all_conns[:50]],
    })


@app.route('/api/startup')
def api_startup():
    all_entries = startup_scanner.scan_all()
    suspicious = [e for e in all_entries if e.is_suspicious]
    return jsonify({
        "total": len(all_entries),
        "suspicious_count": len(suspicious),
        "all": [{
            "name": e.name, "path": e.path, "type": e.type,
            "suspicious": e.is_suspicious, "reason": e.reason
        } for e in all_entries],
    })


@app.route('/api/update', methods=['POST'])
def api_update():
    count = sig_db.update_from_malwarebazaar(limit=100)
    stats = sig_db.get_stats()
    return jsonify({"added": count, "total": stats["total_signatures"]})


@app.route('/api/whitelist', methods=['GET', 'POST'])
def api_whitelist():
    if request.method == 'POST':
        data = request.json or {}
        if data.get("sha256"):
            whitelist.add(data["sha256"])
            return jsonify({"success": True})
        elif data.get("file"):
            whitelist.add_file(data["file"])
            return jsonify({"success": True})
    elif request.method == 'DELETE':
        data = request.json or {}
        whitelist.remove(data.get("sha256", ""))
        return jsonify({"success": True})
    return jsonify({"hashes": whitelist.list_all(), "count": whitelist.count()})


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
    success = scheduler.remove_schedule(name)
    return jsonify({"success": success})


@app.route('/api/monitor', methods=['POST'])
def api_monitor():
    global monitor
    data = request.json or {}
    action = data.get("action", "start")
    if action == "start":
        path = data.get("path", os.path.expanduser("~"))
        if monitor:
            monitor.stop()
        monitor = FileMonitor(scanner, [path])
        monitor.start()
        return jsonify({"status": "monitoring", "path": path})
    elif action == "stop":
        if monitor:
            monitor.stop()
            monitor = None
        return jsonify({"status": "stopped"})
    return jsonify({"status": monitor is not None})


@app.route('/api/stats')
def api_stats():
    stats = sig_db.get_stats()
    q_stats = quarantine.get_stats()
    return jsonify({
        "signatures": stats,
        "quarantine": q_stats,
        "whitelist": whitelist.count(),
        "apis": api_scanner.get_available_apis(),
    })


def run_gui(host='0.0.0.0', port=8443):
    """Start the web GUI server."""
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║    🛡️  SENTINEL GUARD v2.0.0 — WEB GUI      ║")
    print("  ║    Modern Cyberpunk Antivirus Interface      ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()
    print(f"  🔗 http://localhost:{port}")
    print(f"  🔗 http://127.0.0.1:{port}")
    print()
    print("  Press Ctrl+C to stop")
    print()

    try:
        app.run(host=host, port=port, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n  Sentinel Guard stopped.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Sentinel Guard Web GUI")
    parser.add_argument('--port', '-p', type=int, default=8443, help='Port number')
    parser.add_argument('--host', '-H', default='0.0.0.0', help='Host')
    args = parser.parse_args()
    run_gui(host=args.host, port=args.port)
