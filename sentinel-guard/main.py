"""
Sentinel Guard — CLI Entry Point

Usage:
    python main.py scan <path> [--recursive] [--auto-quarantine]
    python main.py monitor <path> [--interval 2.0]
    python main.py update
    python main.py quarantine list
    python main.py quarantine restore <id>
    python main.py quarantine delete <id>
    python main.py quarantine clear
    python main.py stats
    python main.py report <path>
"""
import sys
import os
import time
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.scanner import Scanner, ScanReport
from engine.signatures import SignatureDatabase
from engine.monitor import FileMonitor
from engine.quarantine import QuarantineManager
from utils.logger import get_logger, set_log_level

logger = get_logger("sentinel")


def cmd_scan(args):
    """Scan a directory or file."""
    path = os.path.expanduser(args.path)

    if not os.path.exists(path):
        logger.error(f"Path not found: {path}")
        sys.exit(1)

    scanner = Scanner()

    def progress(current, total, result):
        pct = (current / total * 100) if total > 0 else 0
        status = "✅" if not result.is_threat else "⚠️"
        sys.stdout.write(f"\r   {status} [{pct:5.1f}%] {current}/{total} files scanned")
        sys.stdout.flush()

    if os.path.isfile(path):
        logger.info(f"🔍 Scanning single file: {path}")
        result = scanner.scan_file(path)
        if result.is_threat:
            logger.warning(f"⚠️  THREAT: {result.threat_name} ({result.threat_level.value})")
            logger.warning(f"   File: {result.file_name}")
            logger.warning(f"   SHA256: {result.sha256}")
            if result.heuristic_flags:
                logger.warning(f"   Flags: {', '.join(result.heuristic_flags)}")
        else:
            logger.info(f"✅ File is clean: {result.file_name}")
        return

    logger.info(f"🔍 Scanning: {path}")
    report = scanner.scan_directory(
        path,
        recursive=not args.no_recursive,
        auto_quarantine=args.auto_quarantine,
        progress_callback=progress,
    )
    print()

    # Print summary
    print()
    print("=" * 50)
    print(f"  TARAMA TAMAMLANDI")
    print("=" * 50)
    print(f"  Taranan dosya : {report.scanned_files}")
    print(f"  Temiz         : {report.clean_files}")
    print(f"  Tehdit        : {report.threats_found}")
    print(f"  Karantinaya   : {report.files_quarantined}")
    print(f"  Süre          : {report.scan_duration:.1f}s")
    print("=" * 50)

    if report.results:
        print()
        print("TEHDİTLER:")
        for i, r in enumerate(report.results, 1):
            print(f"  [{i}] {r.threat_name} ({r.threat_level.value})")
            print(f"      File: {r.file_name}")
            print(f"      Type: {r.threat_type}")
            if r.heuristic_flags:
                print(f"      Flags: {', '.join(r.heuristic_flags)}")
            print()

    # Save report to file
    report_txt = scanner.generate_report_txt(report)
    report_path = f"reports/scan_{int(time.time())}.txt"
    Path(report_path).parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_txt)
    logger.info(f"📄 Report saved: {report_path}")


def cmd_monitor(args):
    """Start real-time monitoring."""
    path = os.path.expanduser(args.path)
    if not os.path.exists(path):
        logger.error(f"Path not found: {path}")
        sys.exit(1)

    scanner = Scanner()
    monitor = FileMonitor(scanner, [path], poll_interval=args.interval)

    def on_threat(result):
        print()
        logger.warning(f"🚨 REAL-TIME ALERT: {result.threat_name}")
        logger.warning(f"   File: {result.file_path}")
        logger.warning(f"   Level: {result.threat_level.value}")

    monitor.on_threat_detected(on_threat)
    monitor.start()

    logger.info("Press Ctrl+C to stop monitoring...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        monitor.stop()
        logger.info("Monitoring stopped.")


def cmd_update(args):
    """Update signature database."""
    db = SignatureDatabase()
    stats_before = db.get_stats()
    logger.info(f"Current signatures: {stats_before['total_signatures']}")

    count = db.update_from_malwarebazaar(limit=args.limit)
    stats_after = db.get_stats()

    logger.info(f"✅ Added {count} new signatures")
    logger.info(f"Total signatures: {stats_after['total_signatures']}")


def cmd_quarantine(args):
    """Manage quarantined files."""
    qm = QuarantineManager()

    if args.q_action == "list":
        items = qm.list_quarantined()
        if not items:
            print("Karantina boş. 🔒")
            return
        print(f"Karantina: {len(items)} dosya\n")
        for item in items:
            print(f"  ID: {item['id']}")
            print(f"  File: {item['original_name']}")
            print(f"  Threat: {item['threat_name']}")
            print(f"  Date: {item['quarantined_at']}")
            print(f"  Size: {item['file_size']} bytes")
            print()

    elif args.q_action == "restore":
        if qm.restore_file(args.id):
            print(f"✅ Restored: {args.id}")
        else:
            print(f"❌ Not found: {args.id}")

    elif args.q_action == "delete":
        if qm.delete_file(args.id):
            print(f"🗑️ Deleted: {args.id}")
        else:
            print(f"❌ Not found: {args.id}")

    elif args.q_action == "clear":
        count = qm.clear_all()
        print(f"🗑️ Cleared {count} files")

    elif args.q_action == "stats":
        stats = qm.get_stats()
        print(f"Quarantined files: {stats['total_files']}")
        print(f"Total size: {stats['total_size_human']}")


def cmd_stats(args):
    """Show database statistics."""
    db = SignatureDatabase()
    stats = db.get_stats()
    print("=" * 40)
    print("  SENTINEL GUARD — İSTATİSTİKLER")
    print("=" * 40)
    print(f"  Toplam imza  : {stats['total_signatures']}")
    print(f"  Kaynaklar    :")
    for source, count in stats['by_source'].items():
        print(f"    {source}: {count}")
    print(f"  Risk dağılımı:")
    for sev, count in stats['by_severity'].items():
        print(f"    {sev}: {count}")
    print("=" * 40)


def cmd_hash(args):
    """Compute hash of a file."""
    from utils.hasher import compute_all_hashes
    path = os.path.expanduser(args.path)
    if not os.path.exists(path):
        print(f"File not found: {path}")
        sys.exit(1)
    hashes = compute_all_hashes(path)
    print(f"File: {path}")
    print(f"SHA256: {hashes['sha256']}")
    print(f"MD5   : {hashes['md5']}")
    print(f"SHA1  : {hashes['sha1']}")

    # Check against database
    db = SignatureDatabase()
    match = db.check_hash(hashes['sha256'])
    if match:
        print(f"\n⚠️  THREAT MATCH: {match['name']} ({match['severity']})")
    else:
        print("\n✅ No signature match")


def cmd_eicar(args):
    """Create an EICAR test file to verify the engine works."""
    eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_path = os.path.expanduser(args.path or "./eicar_test.txt")

    with open(eicar_path, 'wb') as f:
        f.write(eicar_content)

    print(f"EICAR test file created: {eicar_path}")

    # Scan it
    scanner = Scanner()
    result = scanner.scan_file(eicar_path)
    if result.is_threat:
        print(f"✅ Engine detected it: {result.threat_name} ({result.threat_level.value})")
    else:
        print("❌ Engine FAILED to detect EICAR test file!")


def main():
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="🛡️ Sentinel Guard — Real Antivirus Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py scan ~/Downloads
  python main.py scan ~/Downloads --auto-quarantine
  python main.py monitor ~/Downloads --interval 1.0
  python main.py update
  python main.py quarantine list
  python main.py stats
  python main.py hash ./suspicious.exe
  python main.py eicar  # Create test file and verify detection
        """
    )
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    sub = parser.add_subparsers(dest='command', help='Commands')

    # scan
    p_scan = sub.add_parser('scan', help='Scan a directory or file')
    p_scan.add_argument('path', help='Path to scan')
    p_scan.add_argument('--no-recursive', action='store_true', help='Do not scan subdirectories')
    p_scan.add_argument('--auto-quarantine', '-q', action='store_true', help='Auto-quarantine detected threats')
    p_scan.set_defaults(func=cmd_scan)

    # monitor
    p_monitor = sub.add_parser('monitor', help='Real-time file monitoring')
    p_monitor.add_argument('path', help='Path to monitor')
    p_monitor.add_argument('--interval', '-i', type=float, default=2.0, help='Poll interval in seconds')
    p_monitor.set_defaults(func=cmd_monitor)

    # update
    p_update = sub.add_parser('update', help='Update signature database from MalwareBazaar')
    p_update.add_argument('--limit', '-l', type=int, default=1000, help='Max signatures to fetch')
    p_update.set_defaults(func=cmd_update)

    # quarantine
    p_q = sub.add_parser('quarantine', help='Manage quarantined files')
    p_q.add_argument('q_action', choices=['list', 'restore', 'delete', 'clear', 'stats'], help='Action')
    p_q.add_argument('id', nargs='?', help='Quarantine ID (for restore/delete)')
    p_q.set_defaults(func=cmd_quarantine)

    # stats
    p_stats = sub.add_parser('stats', help='Show signature database statistics')
    p_stats.set_defaults(func=cmd_stats)

    # hash
    p_hash = sub.add_parser('hash', help='Compute file hashes and check against database')
    p_hash.add_argument('path', help='File path')
    p_hash.set_defaults(func=cmd_hash)

    # eicar
    p_eicar = sub.add_parser('eicar', help='Create EICAR test file and verify detection')
    p_eicar.add_argument('path', nargs='?', default='./eicar_test.txt', help='Output file path')
    p_eicar.set_defaults(func=cmd_eicar)

    args = parser.parse_args()

    if args.verbose:
        set_log_level('DEBUG')

    if not args.command:
        parser.print_help()
        sys.exit(0)

    print()
    print("  ╔═══════════════════════════════════════╗")
    print("  ║    🛡️  SENTINEL GUARD v1.0.0          ║")
    print("  ║    Real Antivirus Engine              ║")
    print("  ╚═══════════════════════════════════════╝")
    print()

    args.func(args)


if __name__ == "__main__":
    main()
