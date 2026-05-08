#!/usr/bin/env bash
# Integration tests against a real TPM device or an already configured TCTI.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

PIN="${1:-${PIN:-}}"
KEY_HANDLE="${KEY_HANDLE:-0x81020001}"
PUBKEY="${PUBKEY:-/home/texsd/Workdir/tpm/pub.pem}"
TCTI="${TCTI:-device:/dev/tpmrm0}"
WORKDIR="$(mktemp -d /tmp/pam_tpm_ecc_hw.XXXXXX)"

cleanup() {
  cleanup_pam_test
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "=== pam_tpm_ecc hardware integration ==="
echo "TCTI: $TCTI"
echo "KEY_HANDLE: $KEY_HANDLE"
echo "PUBKEY: $PUBKEY"

echo ""
echo "[env] dependencies"
require_cmd cargo || true
require_cmd nm || true
require_cmd readelf || true
require_cmd ldd || true
require_cmd openssl || true
require_cmd tpm2_getrandom || true
require_cmd tpm2_sign || true
if [ "$FAIL" -gt 0 ]; then
  print_report_and_exit
fi

if [ ! -f "$PUBKEY" ]; then
  fail "pubkey PEM exists" "$PUBKEY not found"
else
  pass "pubkey PEM exists"
fi

build_release
check_pam_symbols
run_tpm_sign_verify_suite "$PIN" "$KEY_HANDLE" "$PUBKEY" "$TCTI" "$WORKDIR"
run_diagnostic_tool "$PIN" "$KEY_HANDLE" "$TCTI"
run_pamtester_suite "$PIN" "$KEY_HANDLE" "pubkey=$PUBKEY" "$TCTI"
check_shared_library_health
print_report_and_exit
