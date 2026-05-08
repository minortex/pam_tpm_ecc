#!/usr/bin/env bash
# Integration tests against IBM's TPM 2.0 simulator.
#
# By default this starts tpm_server, starts tpm2-abrmd on a session D-Bus,
# creates an ECC signing key in the simulator, and runs the same signing/PAM
# checks through the tabrmd TCTI.
#
# Useful overrides:
#   PIN=123456
#   KEY_HANDLE=0x81020010
#   SIM_USE_ABRMD=1
#   SIM_TCTI=mssim:host=127.0.0.1,port=2321
#   TEST_TCTI=tabrmd:bus_type=session
#   TPM_SERVER_ARGS="-rm"
#   ABRMD_ARGS='--session --allow-root --tcti=mssim:host=127.0.0.1,port=2321'

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

PIN="${1:-${PIN:-123456}}"
KEY_HANDLE="${KEY_HANDLE:-0x81020010}"
SIM_USE_ABRMD="${SIM_USE_ABRMD:-1}"
SIM_TCTI="${SIM_TCTI:-mssim:host=127.0.0.1,port=2321}"
TEST_TCTI="${TEST_TCTI:-tabrmd:bus_type=session}"

if [ "$SIM_USE_ABRMD" = "1" ] && [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
  if ! command -v dbus-run-session >/dev/null 2>&1; then
    echo "dbus-run-session is required for SIM_USE_ABRMD=1" >&2
    exit 1
  fi
  exec dbus-run-session -- "$0" "$@"
fi

WORKDIR="$(mktemp -d /tmp/pam_tpm_ecc_sim.XXXXXX)"
STATE_DIR="${WORKDIR}/tpm-state"
PRIMARY_CTX="${WORKDIR}/primary.ctx"
KEY_PUB="${WORKDIR}/ecc.pub"
KEY_PRIV="${WORKDIR}/ecc.priv"
KEY_CTX="${WORKDIR}/ecc.ctx"
PUBKEY="${WORKDIR}/pubkey.pem"
PUBKEY_DIR="${WORKDIR}/keys"
TPM_SERVER_PID=""
ABRMD_PID=""

cleanup() {
  cleanup_pam_test
  if [ -n "$ABRMD_PID" ]; then
    kill "$ABRMD_PID" >/dev/null 2>&1 || true
  fi
  if [ -n "$TPM_SERVER_PID" ]; then
    kill "$TPM_SERVER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

start_tpm_server() {
  mkdir -p "$STATE_DIR"
  local server_args
  read -r -a server_args <<<"${TPM_SERVER_ARGS:--rm}"
  (
    cd "$STATE_DIR"
    tpm_server "${server_args[@]}"
  ) >"${WORKDIR}/tpm_server.log" 2>&1 &
  TPM_SERVER_PID="$!"
  pass "tpm_server started"
}

start_abrmd() {
  if [ "$SIM_USE_ABRMD" != "1" ]; then
    TEST_TCTI="$SIM_TCTI"
    return
  fi

  local abrmd_args
  read -r -a abrmd_args <<<"${ABRMD_ARGS:---session --allow-root --tcti=${SIM_TCTI}}"
  tpm2-abrmd "${abrmd_args[@]}" >"${WORKDIR}/tpm2-abrmd.log" 2>&1 &
  ABRMD_PID="$!"
  pass "tpm2-abrmd started on session D-Bus"
}

wait_for_tpm() {
  local tcti="$1"
  local attempt
  for attempt in $(seq 1 50); do
    if tpm2_startup -c -T "$tcti" >/dev/null 2>&1 || tpm2_getrandom 1 -T "$tcti" >/dev/null 2>&1; then
      pass "TPM ready: $tcti"
      return 0
    fi
    sleep 0.2
  done

  fail "TPM ready: $tcti" "startup/getrandom did not succeed"
  echo "---- tpm_server.log ----"
  cat "${WORKDIR}/tpm_server.log" || true
  if [ -f "${WORKDIR}/tpm2-abrmd.log" ]; then
    echo "---- tpm2-abrmd.log ----"
    cat "${WORKDIR}/tpm2-abrmd.log" || true
  fi
  return 1
}

create_sim_key() {
  echo ""
  echo "[setup] create simulator key"

  tpm2_createprimary -C o -G ecc -c "$PRIMARY_CTX" -T "$TEST_TCTI" >/dev/null
  pass "primary key created"

  tpm2_create -C "$PRIMARY_CTX" -G ecc256:ecdsa -u "$KEY_PUB" -r "$KEY_PRIV" \
    -p "$PIN" -T "$TEST_TCTI" >/dev/null
  pass "ECDSA key created"

  tpm2_load -C "$PRIMARY_CTX" -u "$KEY_PUB" -r "$KEY_PRIV" -c "$KEY_CTX" \
    -T "$TEST_TCTI" >/dev/null
  pass "ECDSA key loaded"

  tpm2_evictcontrol -C o -c "$KEY_HANDLE" -T "$TEST_TCTI" >/dev/null 2>&1 || true
  tpm2_evictcontrol -C o -c "$KEY_CTX" "$KEY_HANDLE" -T "$TEST_TCTI" >/dev/null
  pass "persistent key created: $KEY_HANDLE"

  tpm2_readpublic -c "$KEY_HANDLE" -f pem -o "$PUBKEY" -T "$TEST_TCTI" >/dev/null
  pass "public key exported"

  mkdir -p "$PUBKEY_DIR"
  cp "$PUBKEY" "${PUBKEY_DIR}/$(id -un).pem"
}

echo "=== pam_tpm_ecc IBM simulator integration ==="
echo "SIM_TCTI: $SIM_TCTI"
echo "TEST_TCTI: $TEST_TCTI"
echo "KEY_HANDLE: $KEY_HANDLE"

echo ""
echo "[env] dependencies"
require_cmd cargo || true
require_cmd nm || true
require_cmd readelf || true
require_cmd ldd || true
require_cmd openssl || true
require_cmd tpm_server || true
require_cmd tpm2_startup || true
require_cmd tpm2_getrandom || true
require_cmd tpm2_createprimary || true
require_cmd tpm2_create || true
require_cmd tpm2_load || true
require_cmd tpm2_evictcontrol || true
require_cmd tpm2_readpublic || true
require_cmd tpm2_sign || true
if [ "$SIM_USE_ABRMD" = "1" ]; then
  require_cmd tpm2-abrmd || true
fi
if [ "$FAIL" -gt 0 ]; then
  print_report_and_exit
fi

build_release
check_pam_symbols
start_tpm_server
start_abrmd
wait_for_tpm "$TEST_TCTI"
create_sim_key
run_tpm_sign_verify_suite "$PIN" "$KEY_HANDLE" "$PUBKEY" "$TEST_TCTI" "$WORKDIR"
run_diagnostic_tool "$PIN" "$KEY_HANDLE" "$TEST_TCTI"
run_pamtester_suite "$PIN" "$KEY_HANDLE" "pubkey_dir=$PUBKEY_DIR" "$TEST_TCTI"
check_shared_library_health
print_report_and_exit
