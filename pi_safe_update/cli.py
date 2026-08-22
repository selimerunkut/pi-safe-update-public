#!/usr/bin/env python3
"""Executable CLI for pi-safe-update."""
from __future__ import annotations

if __package__:
    from .workflow import main
else:
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from pi_safe_update.workflow import main

if __name__ == "__main__":
    raise SystemExit(main())
