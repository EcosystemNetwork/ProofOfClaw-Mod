#!/usr/bin/env python3
"""
Proof of Claw — Activity Seed Script
──────────────────────────────────────
Populates the agent API with realistic activity events for testing.

Usage:
  python scripts/seed_activity.py                         # single burst to localhost:4443
  python scripts/seed_activity.py --url http://localhost:4443 --count 20
  python scripts/seed_activity.py --loop --interval 5    # drip-feed every 5s
  python scripts/seed_activity.py --dry-run              # print events, don't POST

Agent selector:
  python scripts/seed_activity.py --agent alpha-sentinel
"""

import argparse
import json
import os
import random
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ─── Realistic event templates ───────────────────────────────────────────────

PROOF_EVENTS = [
    ("Proof Generated", "Swap {amount} USDC → ETH • DeFi • {agent}"),
    ("Proof Verified On-Chain", "Token balance query • Autonomous • Sepolia"),
    ("ZK Proof Submitted", "Cross-chain bridge transfer • {amount} USDC • {agent}"),
    ("Boundless Proof Complete", "Governance vote participation • {agent}"),
    ("Proof Batch Settled", "{count} proofs verified • Gas: {gas} gwei"),
    ("RISC Zero Receipt", "Smart contract audit pass • {agent}"),
]

MESSAGE_EVENTS = [
    ("DM3 Message Received", "From {peer} • Encrypted"),
    ("DM3 Message Sent", "To {peer} • Strategy update"),
    ("ENS Resolution", "{agent}.proofofclaw.eth → wallet"),
    ("Swarm Message Relayed", "Cross-agent coordination • {peer}"),
    ("Inbox Sync", "{count} new messages from {peer}"),
]

APPROVAL_EVENTS = [
    ("Ledger Approval Granted", "Transfer {amount} USDC • Signed via Ledger"),
    ("Approval Request Sent", "Transfer {amount} USDC exceeds limit • Awaiting Ledger"),
    ("Action Rejected", "Transfer {amount} USDC • Rejected by owner"),
    ("Policy Check Passed", "Autonomous limit: {amount} USDC • Within bounds"),
    ("High-Value Action Approved", "Bridge {amount} ETH → L2 • Ledger confirmed"),
]

BRIDGE_EVENTS = [
    ("Bridge Transaction Initiated", "{amount} ETH → Arbitrum • {agent}"),
    ("Bridge Completed", "Cross-chain transfer confirmed • {amount} USDC"),
    ("Swarm Bridge Heartbeat", "Node health OK • Latency: {ms}ms"),
]

ALL_EVENTS = [
    ("proof",    PROOF_EVENTS),
    ("message",  MESSAGE_EVENTS),
    ("approval", APPROVAL_EVENTS),
    ("bridge",   BRIDGE_EVENTS),
]

AGENTS = [
    "alpha-sentinel", "defi-scout", "sec-auditor",
    "gov-delegate", "yield-hunter", "data-oracle",
]

PEERS = [
    "bob.proofofclaw.eth", "alice.proofofclaw.eth",
    "alpha.proofofclaw.eth", "gov.proofofclaw.eth",
]


def make_event(agent_id=None):
    """Generate one realistic activity event dict."""
    etype, templates = random.choice(ALL_EVENTS)
    title_tmpl, desc_tmpl = random.choice(templates)

    ctx = {
        "agent": agent_id or random.choice(AGENTS),
        "peer":  random.choice(PEERS),
        "amount": random.choice([50, 100, 200, 500, 1000]),
        "count": random.randint(2, 15),
        "gas":   random.randint(10, 80),
        "ms":    random.randint(40, 200),
    }

    return {
        "activity_type": etype,
        "title":         title_tmpl,
        "description":   desc_tmpl.format(**ctx),
        "timestamp":     int(datetime.now(timezone.utc).timestamp()),
        "agent_id":      ctx["agent"],
        "metadata": {
            "source": "seed_script",
            "version": "1.0",
        },
    }


def post_event(url: str, event: dict, dry_run: bool = False, api_key: str = '') -> bool:
    """POST a single event to the agent API. Returns True on success."""
    endpoint = url.rstrip("/") + "/api/activity"
    payload = json.dumps(event).encode("utf-8")

    if dry_run:
        ts = datetime.fromtimestamp(event["timestamp"]).strftime("%H:%M:%S")
        print(f"[DRY] [{ts}] [{event['activity_type'].upper():8}] {event['title']}")
        print(f"        └─ {event['description']}")
        return True

    try:
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-Api-Key"] = api_key
        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            ts = datetime.fromtimestamp(event["timestamp"]).strftime("%H:%M:%S")
            print(f"[{resp.status}] [{ts}] [{event['activity_type'].upper():8}] {event['title']}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[ERR] HTTP {e.code} — {endpoint}: {e.reason}")
        return False
    except (urllib.error.URLError, OSError) as e:
        print(f"[ERR] Cannot reach {endpoint}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Seed the Proof of Claw agent API with realistic activity events."
    )
    parser.add_argument("--url", default="http://localhost:4443",
                        help="Base URL of agent API (default: http://localhost:4443)")
    parser.add_argument("--agent", default=None,
                        help="Specific agent ID (default: random from list)")
    parser.add_argument("--count", type=int, default=10,
                        help="Number of events to send in a single burst (default: 10)")
    parser.add_argument("--interval", type=float, default=3.0,
                        help="Seconds between events in --loop mode (default: 3)")
    parser.add_argument("--loop", action="store_true",
                        help="Keep drip-feeding events indefinitely")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print events without POSTing to the API")
    parser.add_argument("--api-key", default=os.environ.get('API_KEY', ''),
                        help="API key for authentication (default: $API_KEY env var)")
    args = parser.parse_args()

    mode = "loop" if args.loop else f"burst of {args.count}"
    target = f"{args.url}/api/activity" if not args.dry_run else "stdout (dry run)"
    print(f"Proof of Claw — Activity Seed Script")
    print(f"  Mode   : {mode}")
    print(f"  Target : {target}")
    print(f"  Agent  : {args.agent or 'random'}")
    print()

    if args.loop:
        sent = 0
        try:
            while True:
                event = make_event(args.agent)
                post_event(args.url, event, args.dry_run, args.api_key)
                sent += 1
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\nStopped after {sent} events.")
    else:
        ok = 0
        for i in range(args.count):
            event = make_event(args.agent)
            if post_event(args.url, event, args.dry_run, args.api_key):
                ok += 1
            if i < args.count - 1:
                time.sleep(0.3)  # gentle rate limiting
        print(f"\nDone — {ok}/{args.count} events {'printed' if args.dry_run else 'sent'}.")


if __name__ == "__main__":
    main()
