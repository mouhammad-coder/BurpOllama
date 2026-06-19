#!/usr/bin/env python3
"""
resume_poll.py — Standalone OOB Re-Poller
Re-polls a saved interactsh session days or weeks after the main pipeline
has shut down, catching delayed cron-job, batch-processor, or webhook callbacks.

Usage:
    python3 resume_poll.py --list
    python3 resume_poll.py --scan-id <scan_id>
    python3 resume_poll.py --scan-id <scan_id> --wait 30

The interactsh output file must still exist on disk. If the session was
closed and the file deleted, this script cannot recover interactions.
For long-lived campaigns, copy the output file to a safe location before
stopping the pipeline.
"""

import argparse
import asyncio
import json
import os
import sqlite3
import sys

# Add analyzer directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "analyzer"))

DB_PATH = os.path.expanduser("~/.burpollama/oob_sessions.db")


def list_sessions():
    if not os.path.exists(DB_PATH):
        print("No sessions DB found at {}".format(DB_PATH))
        return
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT scan_id, domain, saved_at, status FROM oob_sessions ORDER BY saved_at DESC"
        ).fetchall()
    if not rows:
        print("No saved OOB sessions found.")
        return
    print("\nSaved OOB Sessions:")
    print("{:<20} {:<35} {:<25} {}".format("SCAN_ID", "DOMAIN", "SAVED_AT", "STATUS"))
    print("-" * 95)
    for scan_id, domain, saved_at, status in rows:
        print("{:<20} {:<35} {:<25} {}".format(scan_id, domain, saved_at, status))


async def resume_poll(scan_id: str, wait_secs: int = 0):
    from oob_engine import OOBEngine

    print("[Resume] Loading session: {}".format(scan_id))
    engine = OOBEngine.load_session_from_db(scan_id)
    if not engine:
        print("[Resume] Failed to load session. Exiting.")
        return

    if not os.path.exists(engine._output_file):
        print("[Resume] Output file not found: {}".format(engine._output_file))
        print("[Resume] The interactsh process must have been stopped and the file deleted.")
        print("[Resume] Copy the output file before stopping the pipeline for future re-polls.")
        return

    if wait_secs > 0:
        print("[Resume] Waiting {}s before polling...".format(wait_secs))
        await asyncio.sleep(wait_secs)

    def log(msg, level="info"):
        print("[{}] {}".format(level.upper(), msg))

    print("[Resume] Polling output file: {}".format(engine._output_file))
    new_interactions = engine._read_new_interactions()
    print("[Resume] Found {} new interaction(s) since last poll".format(
        len(new_interactions)))

    if not new_interactions:
        print("[Resume] No new OOB callbacks recorded.")
        _mark_polled(scan_id)
        return

    findings = engine._process_interactions(new_interactions, log)
    print()
    print("=" * 70)
    print("OOB FINDINGS ({})".format(len(findings)))
    print("=" * 70)
    for i, f in enumerate(findings, 1):
        print()
        print("Finding #{}: {}".format(i, f.get("vuln_type", "Unknown")))
        print("  Severity:    {}".format(f.get("severity", "")))
        print("  URL:         {}".format(f.get("url", "")))
        print("  Evidence:    {}".format(f.get("evidence", "")[:200]))
        print("  Remediation: {}".format(f.get("remediation", "")[:120]))

    # Save updated line count back to DB
    try:
        with sqlite3.connect(DB_PATH) as conn:
            state_row = conn.execute(
                "SELECT state_json FROM oob_sessions WHERE scan_id=?",
                (scan_id,)
            ).fetchone()
            if state_row:
                state = json.loads(state_row[0])
                state["reported_line_count"] = engine._reported_line_count
                conn.execute(
                    "UPDATE oob_sessions SET state_json=?, status='polled' WHERE scan_id=?",
                    (json.dumps(state), scan_id)
                )
        print()
        print("[Resume] Line cursor updated ({} lines processed).".format(
            engine._reported_line_count))
    except Exception as e:
        print("[Resume] DB update error: {}".format(e))


def _mark_polled(scan_id: str):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "UPDATE oob_sessions SET status='polled' WHERE scan_id=?",
                (scan_id,)
            )
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="BurpOllama OOB Resume Poller — re-poll saved interactsh sessions"
    )
    parser.add_argument("--list",    action="store_true",
                        help="List all saved OOB sessions")
    parser.add_argument("--scan-id", type=str,
                        help="Scan ID to re-poll")
    parser.add_argument("--wait",    type=int, default=0,
                        help="Wait N seconds before polling (simulate delayed callback)")
    args = parser.parse_args()

    if args.list:
        list_sessions()
    elif args.scan_id:
        asyncio.run(resume_poll(args.scan_id, args.wait))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
