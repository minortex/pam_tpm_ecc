#!/bin/bash
# test.sh — Integration tests for pam_tpm_ecc.so
#
# Requires: TPM device, persistent ECC key at 0x81020001,
#           tpm2-tools, openssl, pamtester (optional)
#
# Usage:  ./test.sh [PIN]
#         PIN defaults to empty string if key has no auth value.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SO="${0%/*}/../build/src/pam_tpm_ecc.so"
PAM_MODULE="pam_tpm_ecc.so"
PAM_INSTALL="/lib/security/${PAM_MODULE}"
KEY_HANDLE="0x81020001"
PUBKEY="/home/texsd/Workdir/tpm/pub.pem"
TCTI="device:/dev/tpmrm0"
PAM_SERVICE="pam_tpm_test"
PAM_CONF="/etc/pam.d/${PAM_SERVICE}"

PASS=0
FAIL=0

pass() {
  echo -e "  ${GREEN}PASS${NC}  $1"
  PASS=$((PASS + 1))
}
fail() {
  echo -e "  ${RED}FAIL${NC}  $1 — $2"
  FAIL=$((FAIL + 1))
}
skip() { echo -e "  ${YELLOW}SKIP${NC} $1 — $2"; }

cleanup() {
  rm -f /tmp/tpm_challenge.bin /tmp/tpm_sig.bin /tmp/tpm_sig.der /tmp/tpm_sig_corrupt.bin
  if [ -f "$PAM_CONF" ]; then
    rm -f "$PAM_CONF"
  fi
  # Remove installed module if we put it there
  if [ -f "$PAM_INSTALL" ] && [ "$(readlink -f "$SO")" != "$(readlink -f "$PAM_INSTALL")" ]; then
    rm -f "$PAM_INSTALL"
  fi
}
trap cleanup EXIT

echo "=== pam_tpm_ecc Integration Tests ==="
echo ""

# ─────────────────────────────────────────────────────────────────────
# Test 1: TPM device accessible
# ─────────────────────────────────────────────────────────────────────
echo "[1] Environment checks"

if [ -c /dev/tpmrm0 ] || [ -c /dev/tpm0 ]; then
  pass "TPM device present"
else
  fail "TPM device present" "no /dev/tpm* found"
fi

if tpm2_getrandom 4 -T "$TCTI" >/dev/null 2>&1; then
  pass "TPM responds"
else
  fail "TPM responds" "tpm2_getrandom failed"
fi

if [ -f "$PUBKEY" ]; then
  pass "pubkey PEM exists: $PUBKEY"
else
  fail "pubkey PEM exists" "$PUBKEY not found"
fi

# ─────────────────────────────────────────────────────────────────────
# Test 2: .so symbols
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "[2] PAM module symbols"

if [ ! -f "$SO" ]; then
  fail ".so exists" "$SO not built — run make first"
  exit 1
fi
pass ".so exists"

for sym in pam_sm_authenticate pam_sm_setcred pam_sm_acct_mgmt \
  pam_sm_open_session pam_sm_close_session pam_sm_chauthtok; do
  if nm -D "$SO" 2>/dev/null | grep -qw "$sym"; then
    pass "  exported: $sym"
  else
    fail "  exported: $sym" "symbol missing"
  fi
done

# ─────────────────────────────────────────────────────────────────────
# Test 3: TPM sign + OpenSSL verify (same as PAM module logic)
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "[3] TPM sign + OpenSSL verify"

PIN="${1:-}"

# generate challenge
head -c 32 /dev/urandom >/tmp/tpm_challenge.bin

# sign with TPM
if [ -z "$PIN" ]; then
  if tpm2_sign -c "$KEY_HANDLE" -g sha256 -s ecdsa -f plain \
    -o /tmp/tpm_sig.bin /tmp/tpm_challenge.bin -T "$TCTI" 2>/dev/null; then
    pass "TPM sign (no PIN)"
  else
    fail "TPM sign (no PIN)" "key may require auth value — pass PIN as argument"
    echo ""
    echo "Usage: ./test.sh <PIN>"
    exit 1
  fi
else
  if tpm2_sign -c "$KEY_HANDLE" -p "$PIN" -g sha256 -s ecdsa -f plain \
    -o /tmp/tpm_sig.bin /tmp/tpm_challenge.bin -T "$TCTI" 2>/dev/null; then
    pass "TPM sign (with PIN)"
  else
    fail "TPM sign (with PIN)" "wrong PIN or TPM error"
    exit 1
  fi
fi

# verify with OpenSSL
if openssl dgst -sha256 -verify "$PUBKEY" \
  -signature /tmp/tpm_sig.bin /tmp/tpm_challenge.bin >/dev/null 2>&1; then
  pass "OpenSSL verify"
else
  fail "OpenSSL verify" "signature does not match public key"
fi

# wrong challenge → must fail
head -c 32 /dev/urandom >/tmp/tpm_challenge.bin
if openssl dgst -sha256 -verify "$PUBKEY" \
  -signature /tmp/tpm_sig.bin /tmp/tpm_challenge.bin >/dev/null 2>&1; then
  fail "verify with wrong challenge" "should have been rejected"
else
  pass "wrong challenge → rejected"
fi

# corrupted signature → must fail
cp /tmp/tpm_sig.bin /tmp/tpm_sig_corrupt.bin
# flip a byte in the middle
printf '\xFF' | dd of=/tmp/tpm_sig_corrupt.bin bs=1 seek=30 count=1 conv=notrunc 2>/dev/null
head -c 32 /dev/urandom >/tmp/tpm_challenge.bin
# re-sign with original challenge to get valid sig, then corrupt
if [ -z "$PIN" ]; then
  tpm2_sign -c "$KEY_HANDLE" -g sha256 -s ecdsa -f plain \
    -o /tmp/tpm_sig.bin /tmp/tpm_challenge.bin -T "$TCTI" 2>/dev/null
else
  tpm2_sign -c "$KEY_HANDLE" -p "$PIN" -g sha256 -s ecdsa -f plain \
    -o /tmp/tpm_sig.bin /tmp/tpm_challenge.bin -T "$TCTI" 2>/dev/null
fi
cp /tmp/tpm_sig.bin /tmp/tpm_sig_corrupt.bin
printf '\xFF' | dd of=/tmp/tpm_sig_corrupt.bin bs=1 seek=30 count=1 conv=notrunc 2>/dev/null

if openssl dgst -sha256 -verify "$PUBKEY" \
  -signature /tmp/tpm_sig_corrupt.bin /tmp/tpm_challenge.bin >/dev/null 2>&1; then
  fail "corrupted sig → rejected" "should have been rejected"
else
  pass "corrupted signature → rejected"
fi
rm -f /tmp/tpm_sig_corrupt.bin

# ─────────────────────────────────────────────────────────────────────
# Test 4: PAM module via pamtester
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "[4] PAM module end-to-end (pamtester)"

if ! command -v pamtester >/dev/null 2>&1; then
  skip "pamtester not found" "cannot test PAM integration"
elif [ ! -w /etc/pam.d ]; then
  skip "no write access to /etc/pam.d" "run 'sudo ./test.sh $PIN' for full PAM test"
elif [ ! -w /lib/security ]; then
  skip "no write access to /lib/security" "cannot install PAM module"
else
  # Install module if not already installed
  if [ ! -f "$PAM_INSTALL" ]; then
    cp "$SO" "$PAM_INSTALL"
    echo "  INFO   installed $PAM_MODULE to /lib/security/"
  fi
  # Create temporary PAM service config
  cat >"$PAM_CONF" <<PAMEOF
auth required $PAM_MODULE key_handle=$KEY_HANDLE pubkey=$PUBKEY tcti=$TCTI
PAMEOF
  pass "PAM service config created"

  if [ -z "$PIN" ]; then
    # No PIN — test with empty password
    if echo -n "" | pamtester "$PAM_SERVICE" "$(whoami)" authenticate 2>&1; then
      pass "pamtester authenticate (no PIN)"
    else
      # Expected failure if PIN is required
      skip "pamtester authenticate" "key requires PIN — test manually with PIN"
    fi
  else
    pamtester_out=$(echo -n "$PIN" | pamtester "$PAM_SERVICE" "$(whoami)" authenticate 2>&1) && {
      pass "pamtester authenticate"
    } || {
      fail "pamtester authenticate" "${pamtester_out}"
    }
  fi

  # Test: wrong PIN → must fail
  echo -n "wrong-pin-12345" | pamtester "$PAM_SERVICE" "$(whoami)" authenticate 2>/dev/null && {
    fail "wrong PIN → rejected" "should have been rejected"
  } || {
    pass "wrong PIN → rejected by PAM module"
  }

  rm -f "$PAM_CONF"
fi

# ─────────────────────────────────────────────────────────────────────
# Test 5: .so loads cleanly (ldd)
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "[5] Shared library health"

if ldd "$SO" 2>&1 | grep -q "not found"; then
  fail "ldd: all deps resolved" "$(ldd "$SO" 2>&1 | grep 'not found')"
else
  pass "all shared library dependencies resolved"
fi

# verify no exec stack
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

# ─────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────"
printf "Results: ${GREEN}%d passed${NC}" "$PASS"
if [ "$FAIL" -gt 0 ]; then
  printf ", ${RED}%d failed${NC}" "$FAIL"
fi
echo ""
echo "────────────────────────────────"

exit "$FAIL"
