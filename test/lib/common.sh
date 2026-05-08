#!/usr/bin/env bash

set -euo pipefail

TEST_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(cd -- "${TEST_LIB_DIR}/.." && pwd)"
PROJECT_ROOT="$(cd -- "${TEST_DIR}/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

SO="${PROJECT_ROOT}/target/release/libpam_tpm_ecc.so"
PAM_MODULE="pam_tpm_ecc.so"
PAM_INSTALL="/usr/lib/security/${PAM_MODULE}"
PAM_SERVICE="${PAM_SERVICE:-pam_tpm_test}"
PAM_CONF="/etc/pam.d/${PAM_SERVICE}"
PAM_INSTALLED_BY_TEST=0

pass() {
  echo -e "  ${GREEN}PASS${NC}  $1"
  PASS=$((PASS + 1))
}

fail() {
  echo -e "  ${RED}FAIL${NC}  $1 - $2"
  FAIL=$((FAIL + 1))
}

skip() {
  echo -e "  ${YELLOW}SKIP${NC} $1 - $2"
  SKIP=$((SKIP + 1))
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    fail "command: $cmd" "not found"
    return 1
  fi
  pass "command present: $cmd"
}

build_release() {
  echo ""
  echo "[build] release artifacts"
  cargo build --release --locked --manifest-path "${PROJECT_ROOT}/Cargo.toml"
  pass "cargo build --release --locked"
}

check_pam_symbols() {
  echo ""
  echo "[symbols] PAM module exports"

  if [ ! -f "$SO" ]; then
    fail ".so exists" "$SO not built"
    return
  fi
  pass ".so exists"

  local sym
  for sym in pam_sm_authenticate pam_sm_setcred pam_sm_acct_mgmt \
    pam_sm_open_session pam_sm_close_session pam_sm_chauthtok; do
    if nm -D "$SO" 2>/dev/null | grep -qw "$sym"; then
      pass "exported: $sym"
    else
      fail "exported: $sym" "symbol missing"
    fi
  done
}

check_shared_library_health() {
  echo ""
  echo "[elf] shared library health"

  if ldd "$SO" 2>&1 | grep -q "not found"; then
    fail "ldd: all deps resolved" "$(ldd "$SO" 2>&1 | grep 'not found')"
  else
    pass "all shared library dependencies resolved"
  fi

  if readelf -l "$SO" 2>/dev/null | grep -A1 GNU_STACK | grep -q 'E'; then
    fail "GNU_STACK: NX" "stack is executable"
  else
    pass "GNU_STACK: no-execute (NX)"
  fi

  if readelf -d "$SO" 2>/dev/null | grep -q 'BIND_NOW'; then
    pass "Full RELRO (BIND_NOW)"
  else
    fail "Full RELRO" "BIND_NOW not set"
  fi
}

tpm2_sign_plain() {
  local pin="$1"
  local handle="$2"
  local tcti="$3"
  local challenge="$4"
  local signature="$5"

  if [ -z "$pin" ]; then
    tpm2_sign -c "$handle" -g sha256 -s ecdsa -f plain \
      -o "$signature" "$challenge" -T "$tcti" >/dev/null
  else
    tpm2_sign -c "$handle" -p "$pin" -g sha256 -s ecdsa -f plain \
      -o "$signature" "$challenge" -T "$tcti" >/dev/null
  fi
}

run_tpm_sign_verify_suite() {
  local pin="$1"
  local handle="$2"
  local pubkey="$3"
  local tcti="$4"
  local workdir="$5"

  echo ""
  echo "[tpm] sign and verify"

  if tpm2_getrandom 4 -T "$tcti" >/dev/null 2>&1; then
    pass "TPM responds: $tcti"
  else
    fail "TPM responds: $tcti" "tpm2_getrandom failed"
    return
  fi

  local challenge="${workdir}/challenge.bin"
  local wrong_challenge="${workdir}/wrong-challenge.bin"
  local sig="${workdir}/sig.bin"
  local sig_corrupt="${workdir}/sig-corrupt.bin"

  openssl rand 32 >"$challenge"

  if tpm2_sign_plain "$pin" "$handle" "$tcti" "$challenge" "$sig" 2>"${workdir}/tpm2_sign.err"; then
    pass "TPM sign"
  else
    fail "TPM sign" "$(cat "${workdir}/tpm2_sign.err")"
    return
  fi

  if openssl dgst -sha256 -verify "$pubkey" -signature "$sig" "$challenge" >/dev/null 2>&1; then
    pass "OpenSSL verify"
  else
    fail "OpenSSL verify" "signature does not match public key"
  fi

  openssl rand 32 >"$wrong_challenge"
  if openssl dgst -sha256 -verify "$pubkey" -signature "$sig" "$wrong_challenge" >/dev/null 2>&1; then
    fail "wrong challenge rejected" "signature unexpectedly verified"
  else
    pass "wrong challenge rejected"
  fi

  cp "$sig" "$sig_corrupt"
  printf '\xFF' | dd of="$sig_corrupt" bs=1 seek=30 count=1 conv=notrunc 2>/dev/null
  if openssl dgst -sha256 -verify "$pubkey" -signature "$sig_corrupt" "$challenge" >/dev/null 2>&1; then
    fail "corrupted signature rejected" "signature unexpectedly verified"
  else
    pass "corrupted signature rejected"
  fi
}

run_diagnostic_tool() {
  local pin="$1"
  local handle="$2"
  local tcti="$3"

  echo ""
  echo "[tool] tpm_sign_test"

  if "${PROJECT_ROOT}/target/release/tpm_sign_test" "$pin" "$handle" "$tcti" >/dev/null 2>&1; then
    pass "tpm_sign_test signs with TPM"
  else
    fail "tpm_sign_test signs with TPM" "diagnostic tool failed"
  fi
}

install_pam_module_for_test() {
  if [ ! -w /usr/lib/security ]; then
    skip "install PAM module" "no write access to /usr/lib/security"
    return 1
  fi

  if [ -f "$PAM_INSTALL" ]; then
    if [ "${PAM_TPM_ECC_REPLACE_SYSTEM_MODULE:-0}" != "1" ]; then
      skip "install PAM module" "$PAM_INSTALL already exists; set PAM_TPM_ECC_REPLACE_SYSTEM_MODULE=1 to overwrite for testing"
      return 1
    fi
  else
    PAM_INSTALLED_BY_TEST=1
  fi

  install -Dm755 "$SO" "$PAM_INSTALL"
  pass "PAM module installed for test"
}

cleanup_pam_test() {
  rm -f "$PAM_CONF"
  if [ "$PAM_INSTALLED_BY_TEST" -eq 1 ]; then
    rm -f "$PAM_INSTALL"
  fi
}

run_pamtester_suite() {
  local pin="$1"
  local key_handle="$2"
  local pubkey_arg="$3"
  local tcti="$4"
  local user="${PAM_TEST_USER:-$(id -un)}"

  echo ""
  echo "[pam] end-to-end with pamtester"

  if ! command -v pamtester >/dev/null 2>&1; then
    skip "pamtester" "not installed"
    return
  fi
  if [ ! -w /etc/pam.d ]; then
    skip "PAM service config" "no write access to /etc/pam.d"
    return
  fi
  if ! install_pam_module_for_test; then
    return
  fi

  cat >"$PAM_CONF" <<PAMEOF
auth required $PAM_MODULE key_handle=$key_handle $pubkey_arg tcti=$tcti
PAMEOF
  pass "PAM service config created"

  local pamtester_out
  if pamtester_out=$(printf '%s' "$pin" | pamtester "$PAM_SERVICE" "$user" authenticate 2>&1); then
    pass "pamtester authenticate"
  else
    fail "pamtester authenticate" "$pamtester_out"
  fi

  if printf '%s' "wrong-pin-12345" | pamtester "$PAM_SERVICE" "$user" authenticate >/dev/null 2>&1; then
    fail "wrong PIN rejected" "authentication unexpectedly succeeded"
  else
    pass "wrong PIN rejected"
  fi
}

print_report_and_exit() {
  echo ""
  echo "--------------------------------"
  printf "Results: ${GREEN}%d passed${NC}" "$PASS"
  if [ "$SKIP" -gt 0 ]; then
    printf ", ${YELLOW}%d skipped${NC}" "$SKIP"
  fi
  if [ "$FAIL" -gt 0 ]; then
    printf ", ${RED}%d failed${NC}" "$FAIL"
  fi
  echo ""
  echo "--------------------------------"
  exit "$FAIL"
}
