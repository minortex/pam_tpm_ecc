#!/usr/bin/env bash
# Compatibility wrapper. Prefer test/integration/hardware.sh.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/integration/hardware.sh" "$@"
