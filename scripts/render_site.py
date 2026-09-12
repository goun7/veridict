#!/usr/bin/env python
"""Render the public docs (standard, README, design) to a minimal static
site for GitHub Pages. Zero dependencies beyond the stdlib + `markdown`.

Deliberately plain: no JS, no tracking, one stylesheet. The standard is the
product — the site is just a readable window onto the repository.
"""
from __future__ import annotations

import os
import re
import sys

import markdown

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "_site")

STYLE = """
:root { color-scheme: light dark; }
body { max-width: 52rem; margin: 2rem auto; padding: 0 1.2rem;
       font: 16px/1.65 -apple-system, "Segoe UI", Roboto, sans-serif; }
h1, h2, h3 { line-height: 1.25; }
code, pre { background: #f4f4f4; border-radius: 4px; }
pre { padding: 0.8rem; overflow-x: auto; }
table { border-collapse: collapse; } td, th { border: 1px solid #bbb;
       padding: 0.3rem 0.6rem; }
nav a { margin-right: 1rem; }
@media (prefers-color-scheme: dark) {
  body { background: #14171c; color: #dbe1e8; }
  code, pre { background: #22262e; } td, th { border-color: #3a3f47; } }
"""

NAV = ('<nav><a href="index.html">Home</a>'
       '<a href="standard.html">The Standard</a>'
       '<a href="design.html">Design</a>'
       '<a href="marketplace.html">Watchers</a>'
       '<a href="https://github.com/goun7/veridict">Repository</a></nav><hr>')


def _marketplace_md() -> str:
    """Generate the watcher showcase page from the SHIPPED manifests —
    never hand-maintained (a hand list would be a second truth). Renders
    every examples/manifests/*.json with tier, domains, and producer."""
    import json
    mdir = os.path.join(REPO, "examples", "manifests")
    rows = []
    for name in sorted(os.listdir(mdir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(mdir, name), encoding="utf-8") as f:
            m = json.load(f)
        cap = m["capabilities"]
        subs = ", ".join(f"`{s}`" if s != "*" else "`*` (all)"
                         for s in cap["subscribes_to"])
        rows.append(
            f"| [{m['watcher_id']}](https://github.com/goun7/veridict/blob/"
            f"main/examples/manifests/{name}) | {m['name'].replace('Example ', '')}"
            f" | `{cap['max_tier']}` | {subs} "
            f"| {m['producer']['maintainer']} | v{m['version']} |")
    return f"""# The watcher marketplace

Third-party producers participate through **signed manifests + blind
sessions** — the core has no special case for any of them. A watcher can
never produce W1a (machine truth is reserved to built-in verifiers), and
each must pass the **conformance kit** (C1–C10: blindness, tier ceiling,
abstain semantics, deadline, evidence shape) before it can be listed.

These are the example watchers we ship. Real third-party watchers join
the same way — see [`CONTRIBUTING.md`](https://github.com/goun7/veridict/blob/main/CONTRIBUTING.md).

| Watcher | Doctrine | Tier | Domains | Maintainer | Version |
|---|---|---|---|---|---|
{chr(10).join(rows)}

## Verify the index yourself

An index is a VIEW of registered manifests exported from a ledger —
never a separate truth. Offline consumers verify:

```
veridict registry index --registry r.jsonl --out index.json
```

…then validate `index.json` against the ledger they trust. Revoked
watchers never appear in an index (§6.6 — an index that lists revoked
watchers is a CRL nobody reads).
"""


def render(md_path: str, title: str) -> str:
    with open(md_path, encoding="utf-8") as f:
        text = f.read()
    # resolve repo-relative links to GitHub so they work from Pages
    text = re.sub(r"\]\((docs/[^)]+|corpus/[^)]+)\)",
                  r"](https://github.com/goun7/veridict/blob/main/\1)", text)
    body = markdown.markdown(text, extensions=["tables", "fenced_code", "toc"])
    return (f"<!doctype html><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{title} — Veridict</title><style>{STYLE}</style>"
            f"{NAV}{body}</html>")


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    pages = {
        "index.html": (None, "An audit standard for AI-generated work"),
        "standard.html": (os.path.join(REPO, "docs", "specs",
                                       "2026-09-10-veridict-standard-v1.0.md"),
                          "Standard v1.0.0-draft"),
        "design.html": (os.path.join(REPO, "docs", "specs",
                                     "2026-09-09-veridict-design.md"),
                        "Design document"),
    }
    index_md = f"""# Veridict

*The verdict that survived verification.*

An append-only, hash-chained audit standard for AI-generated work: signed
evidence, blind juries, watcher manifests with revocation, and signed
certificates anyone can verify offline — from the standard alone.

- **[The Standard v1.0.0-draft](standard.html)** — normative, with a public
  errata ledger (§14.2)
- **[Design document](design.html)** — the founding paper
- **[The watcher marketplace](marketplace.html)** — ten shipped example
  watchers, all certified by the conformance kit
- **[Repository](https://github.com/goun7/veridict)** — core, offline
  verifier, conformance test vectors, spec-only verifier, CI receipts
- **[Independent verifier challenge](https://github.com/goun7/veridict/issues/1)**
  — implement the standard without reading our code; findings earn errata
  credit
- **JSON Schemas** for the watcher manifest, the certificate, and the
  ledger entry live in [`docs/schemas/`](https://github.com/goun7/veridict/tree/main/docs/schemas) —
  validated against every real artifact the system produces on each push

*Humans own the verdict of responsibility; machines own the verdict of
intelligence.*
"""
    with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
        pass  # README is intentionally NOT mirrored here; index is curated
    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "vd-index.md")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(index_md)
    pages["index.html"] = (tmp, pages["index.html"][1])
    market_tmp = os.path.join(tempfile.gettempdir(), "vd-marketplace.md")
    with open(market_tmp, "w", encoding="utf-8") as f:
        f.write(_marketplace_md())
    pages["marketplace.html"] = (market_tmp, "The watcher marketplace")
    for name, (src, title) in pages.items():
        html = render(src, title) if name not in ("index.html",
                                                  "marketplace.html") \
            else render(market_tmp if name == "marketplace.html" else tmp,
                        title)
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
            f.write(html)
        print("rendered", name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
