#!/bin/bash
set -euo pipefail

LOG=/tmp/pam_tpm.log
exec >>"$LOG" 2>&1

echo "=== $(date) ==="

KEY=0x81020001
PUB=/home/texsd/Workdir/tpm/pub.pem

CHAL=$(mktemp)
SIG=$(mktemp)

cleanup() {
  rm -f "$CHAL" "$SIG"
}
trap cleanup EXIT

# 读取 PIN - 忽略 read 的返回值
PIN=""

IFS= read -r PIN || true

# 清理 PIN
if [ -n "${PIN:-}" ]; then
  PIN=$(echo -n "$PIN" | tr -d '\n\r')
fi

if [ -z "${PIN:-}" ]; then
  echo "[!] No PIN provided"
  exit 1
fi

# 生成 challenge
head -c 32 /dev/urandom >"$CHAL"

# TPM 签名
if ! tpm2_sign -c "$KEY" -p "$PIN" -g sha256 -s ecdsa -f plain -o "$SIG" "$CHAL"; then
  echo "[!] TPM sign FAILED"
  exit 1
fi

# OpenSSL 验证
if ! openssl dgst -sha256 -verify "$PUB" -signature "$SIG" "$CHAL"; then
  echo "[!] OpenSSL verify FAILED"
  exit 1
fi

echo "[+] Authentication successful"
exit 0
