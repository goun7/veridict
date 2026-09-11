#!/usr/bin/env python
"""Generate an offline-verifiable audit badge (SVG) from a certificate.

The badge is a CLAIM about a certificate, not a decoration: this script
refuses to emit a passing badge unless the certificate verifies offline
AND every claim verdict is VERIFIED. Anything else gets an honest badge
(INCONCLUSIVE / REFUTED) or no badge at all (invalid certificate → exit 1).

Usage:
    python scripts/make_badge.py --cert cert.json --ledger led.jsonl \\
        --out badge.svg [--label "my-repo"]

Embed in any README (zero hosting — the SVG lives in the audited repo):
    [![Veridict audit](badge.svg)](https://github.com/goun7/veridict)

Verify the claim behind any badge:
    veridict verify --ledger <ledger.jsonl> --cert <cert.json>
"""
from __future__ import annotations

import argparse
import html
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.certificate import verify_certificate

COLORS = {
    "VERIFIED": "#2da44e",      # green — all claims VERIFIED, cert valid
    "INCONCLUSIVE": "#bf8700",  # amber — audited, but something unresolved
    "REFUTED": "#cf222e",       # red — audited, and something failed
    "ESCALATED": "#8250df",     # purple — a human decision is on record
}

SVG_TEMPLATE = """<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="{label}: {status}">
<!-- Veridict audit badge. Claim: certificate {cert_id} verified offline.
     Audit it yourself: veridict verify --ledger <ledger.jsonl> --cert <cert.json>
     Standard: https://goun7.github.io/veridict/standard.html -->
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<rect rx="3" width="{width}" height="20" fill="#555"/>
<rect rx="3" x="{left_w}" width="{right_w}" height="20" fill="{color}"/>
<rect rx="3" width="{width}" height="20" fill="url(#s)"/>
<g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
<text x="{left_cx}" y="15">{label}</text>
<text x="{right_cx}" y="15">{status}</text>
</g>
</svg>
"""


def badge_status(cert: dict) -> str:
    """Worst-verdict-wins: one REFUTED claim taints the whole badge."""
    verdicts = [c["verdict_value"] for c in cert.get("claims", [])]
    if not verdicts:
        return "INCONCLUSIVE"
    for bad in ("REFUTED", "ESCALATED", "INCONCLUSIVE"):
        if bad in verdicts:
            return bad
    return "VERIFIED"


def main() -> int:
    ap = argparse.ArgumentParser(description="Veridict audit badge generator")
    ap.add_argument("--cert", required=True)
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="veridict audit")
    args = ap.parse_args()

    report = verify_certificate(args.ledger, args.cert)
    if not report["valid"]:
        print(f"refusing badge: certificate INVALID — {report['errors']}",
              file=sys.stderr)
        return 1
    with open(args.cert, encoding="utf-8") as f:
        cert = json.load(f)
    status = badge_status(cert)
    cert_id = cert.get("cert_id", "?")[:12]

    label, color = html.escape(args.label), COLORS[status]
    left_w = 10 * len(args.label) + 12
    right_w = 10 * len(status) + 22
    width = left_w + right_w
    svg = SVG_TEMPLATE.format(
        width=width, left_w=left_w, right_w=right_w,
        left_cx=left_w // 2, right_cx=left_w + right_w // 2,
        label=label, status=status, color=color, cert_id=cert_id)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"badge: {status} (cert {cert_id}) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
