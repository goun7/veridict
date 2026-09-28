# veridict-receipt — MCP server

Signed **proof-of-done** for AI agents. An agent does work; it hands its
principal a receipt the principal can verify **without trusting the agent or
the platform**.

This is the receipt layer of [Veridict](https://github.com/goun7/veridict),
exposed over the Model Context Protocol. The audit server
(`adapters/mcp/veridict_mcp`) runs full evidence-ladder audits; this one does
the single thing a paying party actually asks for — *did it happen, and can I
check it myself?*

## What a receipt proves

Every receipt is one self-contained JSON file:

| Field | Why it matters |
|---|---|
| `content_digest` | sha256 over the canonical achievement payload. **Recomputable from the receipt's own fields** — anyone can confirm the receipt binds to what it certifies. |
| `signatures` | ed25519 over the canonical body, verified against the public key **embedded in the receipt**. The issuer cannot deny having signed this exact document. |
| `issued_at` | ISO-8601 UTC timestamp **inside the signed body**, so the signature binds issuance order, not just content. |
| `cert_id` | Derived from the subject fields exactly like an audit certificate — one standalone verifier serves both. |

`verify` needs **nothing but the receipt**: no ledger, no network, no
account. That is the whole point — "the agent said it paid" is a claim;
a receipt that recomputes under your own hand is proof.

## Tools

| Tool | Purpose |
|---|---|
| `issue` | Issue a signed receipt for one achievement |
| `verify` | Verify a receipt — standalone, or fully with the issuer's ledger |
| `revoke` | Append a revocation to the issuer's append-only ledger |
| `list` | Enumerate issued receipts with revocation status |

## Install

The server speaks stdio. Requires Python 3.12+ and `pip install mcp`.

### Claude Desktop / Claude Code

Add to `claude_desktop_config.json` (macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "veridict-receipt": {
      "command": "python",
      "args": ["-m", "veridict_receipt_mcp.server"],
      "cwd": "/path/to/veridict/mcp",
      "env": {
        "VERIDICT_HOME": "/path/to/your/veridict-workspace"
      }
    }
  }
}
```

### Cursor / Cline / any stdio client

```json
{
  "mcpServers": {
    "veridict-receipt": {
      "command": "python",
      "args": ["-m", "veridict_receipt_mcp.server"],
      "cwd": "/path/to/veridict/mcp"
    }
  }
}
```

### From a checkout (no install)

```bash
python mcp/veridict_receipt_mcp/server.py     # server.py puts the repo root on sys.path
```

## Workspace

The server keeps state in one directory (`VERIDICT_HOME`, default
`./.veridict`):

```
workspace/
  ledger.jsonl      append-only, hash-chained ledger (issuance + revocation)
  keys/issuer.json  the issuer's LOCAL signing key, mode 0600
  receipts/         issued receipt files
```

**Custody:** `keys/issuer.json` is the custody boundary — whoever can read
it can issue and revoke receipts for the workspace. It is created `0600`, is
never returned by a tool, never logged, never transmitted. Only its **public**
half appears in the ledger and in receipts. It is a local document-signing
key: not a blockchain key, no mainnet, no payment rail.

## End-to-end example

```bash
# an agent issues a receipt for completed work
python -c "from veridict.cli import main; main(['receipt','issue', \
  '--achievement','deployed api v2 to staging','--actor','agent-7', \
  '--evidence','gh run 8812 passed','--evidence','canary 5xx 0.0%'])"

# the principal verifies it — standalone, from the file alone
veridict verify .veridict/receipts/<cert_id>.json

# with the issuer's ledger: chain, issuance and revocation too
veridict receipt verify --cert .veridict/receipts/<cert_id>.json \
  --ledger .veridict/ledger.jsonl
```

## Registry publishing

`mcp.json` is the server definition (name, description, command, args, env,
tool catalog). Publish it to an MCP registry by submitting that object; the
`install` block is a complete stdio launcher requiring no build step.

## Relation to the audit server

`adapters/mcp/veridict_mcp` runs **full audits** (evidence ladder, jury,
watchers, offline-replayable certificates). This server runs **receipts** —
no jury, no policy, no claims: just a signed, revocable record that an
achievement happened. Use receipts for day-to-day agent work; use audits
when you need the verdict of a machine-verifiable evidence ladder.
