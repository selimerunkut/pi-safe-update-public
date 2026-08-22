#!/usr/bin/env bash
# Public compatibility entrypoint. The implementation lives in Python.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${PYTHON3:-python3}" "$SCRIPT_DIR/pi_safe_update/cli.py" "$@"
