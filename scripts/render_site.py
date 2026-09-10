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
       '<a href="https://github.com/goun7/veridict">Repository</a></nav><hr>')


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
- **[Repository](https://github.com/goun7/veridict)** — core, offline
  verifier, conformance test vectors, spec-only verifier, CI receipts
- **[Independent verifier challenge](https://github.com/goun7/veridict/issues/1)**
  — implement the standard without reading our code; findings earn errata
  credit

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
    for name, (src, title) in pages.items():
        html = render(src, title) if name != "index.html" else render(tmp, title)
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
            f.write(html)
        print("rendered", name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
