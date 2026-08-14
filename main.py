#!/usr/bin/env python3
"""
main.py
CLI for the Phishing Detection & Awareness System.

Usage:
    python main.py check <url> [--offline] [--json]
    python main.py history [--limit N] [--level Low|Medium|High|Critical]
    python main.py export <output.csv>
    python main.py clear-history
"""

import argparse
import json
import sys
from dataclasses import asdict

from analyzer import analyze_url
from report import render_text_report
from history import HistoryStore


def cmd_check(args):
    result = analyze_url(args.url, use_network=not args.offline)

    store = HistoryStore()
    record_id = store.save(result)

    if args.json:
        payload = asdict(result)
        payload["history_id"] = record_id
        print(json.dumps(payload, indent=2))
    else:
        print(render_text_report(result))
        print(f"\n(Saved to history as record #{record_id})")


def cmd_history(args):
    store = HistoryStore()
    rows = store.list(limit=args.limit, risk_level=args.level)
    if not rows:
        print("No history records found.")
        return

    print(f"{'ID':<5}{'Score':<7}{'Level':<10}{'Domain':<30}{'Analyzed At'}")
    print("-" * 90)
    for r in rows:
        print(
            f"{r['id']:<5}{r['risk_score']:<7}{r['risk_level']:<10}"
            f"{(r['registrable_domain'] or '')[:28]:<30}{r['analyzed_at']}"
        )


def cmd_export(args):
    store = HistoryStore()
    path = store.export_csv(args.output)
    print(f"History exported to {path}")


def cmd_clear_history(args):
    store = HistoryStore()
    store.clear()
    print("History cleared.")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Phishing Detection & Awareness System"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Analyze a single URL")
    p_check.add_argument("url", help="URL to analyze")
    p_check.add_argument(
        "--offline", action="store_true",
        help="Skip network-based checks (SSL cert, redirects)"
    )
    p_check.add_argument(
        "--json", action="store_true", help="Output raw JSON instead of a report"
    )
    p_check.set_defaults(func=cmd_check)

    p_history = sub.add_parser("history", help="View analysis history")
    p_history.add_argument("--limit", type=int, default=20)
    p_history.add_argument("--level", choices=["Low", "Medium", "High", "Critical"])
    p_history.set_defaults(func=cmd_history)

    p_export = sub.add_parser("export", help="Export history to CSV")
    p_export.add_argument("output", help="Output CSV path")
    p_export.set_defaults(func=cmd_export)

    p_clear = sub.add_parser("clear-history", help="Delete all history records")
    p_clear.set_defaults(func=cmd_clear_history)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
