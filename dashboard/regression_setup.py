"""Reuse unchanged MySQL setup, recording new outcomes only under the Phase 5 Gate."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "labs/VULN-002-IDOR"))
import runtime
import manage


def start(recorded_command):
    previous = runtime.command
    runtime.command = lambda args, label, env=None, timeout=300: recorded_command(
        args, label, env or runtime.environment(), timeout=timeout)
    try:
        manage.manage("up")
    finally:
        runtime.command = previous
