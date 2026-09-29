#!/usr/bin/env python3
"""Standalone runner for the veridict-receipt MCP server.

Smithery/Arcade ve herhangi bir stdio MCP client için tek giriş noktası.
`python -m veridict_receipt_mcp.server` yalnızca bu `mcp/` dizini cwd veya
sys.path'teyse çalışır; bu script her cwd'den çalışır ve aynı çakışmadan
kaçınır: bu dosya `mcp/` içinde olduğu için `import mcp` (yüklü MCP SDK)
hâlâ modül-çeşmesindeki `mcp` paketini bulur — `mcp/`'nin kendisini DEĞİL.

Ayrıca: `import mcp` SDK'sını yüklerken repo-kökü sys.path'te olmamalıdır,
çünkü repo-kökündeki `mcp/` dizini yüklü SDK'yı gölgediği için
`from mcp.server.fastmcp import FastMCP` kırılırdı. Bu yüzden yalnızca bu
dosyanın kendi dizinini (`mcp/`) koyuyoruz, ki `veridict_receipt_mcp` orada.
"""
import runpy
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent  # <root>/mcp
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

runpy.run_module("veridict_receipt_mcp.server", run_name="__main__")
