#!/usr/bin/env python3
"""
AWS Cloud Detection Lab
-----------------------
Pulls CloudTrail and VPC Flow Log events from S3, runs detection rules,
and writes a markdown findings report.

Usage:
    python main.py              # process last 2 hours
    python main.py --hours 24   # process last 24 hours
    python main.py --dry-run    # print findings to console only, no report file
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from ingestors.cloudtrail_ingestor import ingest as ingest_cloudtrail
from ingestors.flowlog_ingestor import ingest as ingest_flowlogs
from detections.rules import run_all
from output.reporter import write_markdown


def main():
    parser = argparse.ArgumentParser(description="AWS Cloud Detection Lab")
    parser.add_argument("--hours", type=int, default=2, help="Hours of logs to look back (default: 2)")
    parser.add_argument("--dry-run", action="store_true", help="Print findings to console only")
    args = parser.parse_args()

    print(f"\n{'='*50}")
    print(f"  AWS Cloud Detection Lab")
    print(f"  Look-back window: {args.hours}h")
    print(f"{'='*50}\n")

    # Ingest
    ct_events = ingest_cloudtrail(hours=args.hours)
    fl_events = ingest_flowlogs(hours=args.hours)
    all_events = ct_events + fl_events

    print(f"\n[Main] Total events loaded: {len(all_events)} "
          f"(CloudTrail: {len(ct_events)}, FlowLogs: {len(fl_events)})\n")

    if not all_events:
        print("[Main] No events to process. Check that logs are landing in S3 "
              "and that your AWS credentials are configured (aws configure).")
        return

    # Detect
    findings = run_all(all_events)
    print(f"\n[Main] Total findings: {len(findings)}")

    if not findings:
        print("[Main] No findings — clean run or no events matched the rules.")

    # Output
    if args.dry_run:
        print("\n--- DRY RUN: Findings ---")
        for f in findings:
            raw = f.pop("raw_event", None)
            print(json.dumps(f, indent=2, default=str))
    else:
        write_markdown(findings, len(ct_events), len(fl_events))

    print("\nDone.\n")


if __name__ == "__main__":
    main()