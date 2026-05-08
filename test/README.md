# Tests

## Layout

```text
test/
├── README.md
├── test.sh                         # Compatibility wrapper for hardware.sh
├── lib/
│   └── common.sh                   # Shared build, ELF, TPM, and PAM checks
└── integration/
    ├── hardware.sh                 # Real TPM or preconfigured TCTI
    └── ibmswtpm2.sh                # IBM TPM simulator + optional tpm2-abrmd
```

## Unit Tests

Unit tests do not require a TPM:

```sh
cargo test --locked
```

## Hardware Integration

Use a real TPM device, or any already configured TCTI:

```sh
KEY_HANDLE=0x81020000 \
PUBKEY=/etc/tpm-ecc.pub.pem \
TCTI=device:/dev/tpmrm0 \
test/integration/hardware.sh 123456
```

If the key has no auth value, pass an empty PIN:

```sh
test/integration/hardware.sh ""
```

The PAM end-to-end portion requires `pamtester` and write access to
`/etc/pam.d` and `/usr/lib/security`; otherwise it is skipped.

## IBM Simulator Integration

The simulator path is intended for CI/CD. It starts IBM's `tpm_server`, starts
`tpm2-abrmd` on a session D-Bus by default, creates a temporary persistent
ECDSA key, exports the public key, and runs the same checks through the `tabrmd`
TCTI.

Typical dependencies:

- `tpm_server` from IBM's TPM 2.0 simulator package
- `tpm2-tools`
- `tpm2-abrmd`
- `dbus-run-session`
- `openssl`
- `pamtester` for the optional PAM end-to-end portion

Run:

```sh
test/integration/ibmswtpm2.sh 123456
```

Default simulator settings:

```sh
SIM_TCTI=mssim:host=127.0.0.1,port=2321
TEST_TCTI=tabrmd:bus_type=session
TPM_SERVER_ARGS="-rm"
ABRMD_ARGS="--session --allow-root --tcti=mssim:host=127.0.0.1,port=2321"
```

To bypass `tpm2-abrmd` and test directly against the simulator TCTI:

```sh
SIM_USE_ABRMD=0 TEST_TCTI=mssim:host=127.0.0.1,port=2321 test/integration/ibmswtpm2.sh 123456
```

For full PAM testing in CI, run the job as root or in a container where writing
`/etc/pam.d` and `/usr/lib/security` is acceptable. If an existing system
`pam_tpm_ecc.so` is present, the PAM test will not overwrite it unless this is
set:

```sh
PAM_TPM_ECC_REPLACE_SYSTEM_MODULE=1
```
