/*
 * tpm_sign_test.c — minimal ESYS sign test (no PAM, mirrors pam_tpm_ecc.c)
 *
 * Compile:
 *   gcc -std=c11 -Wall -Wextra -O2 -o tpm_sign_test tpm_sign_test.c \
 *       $(pkg-config --cflags --libs tss2-esys tss2-rc tss2-mu tss2-tctildr)
 *
 * Usage: ./tpm_sign_test [PIN] [key_handle] [tcti]
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#define DEFAULT_KEY_HANDLE 0x81020001U
#define DEFAULT_TCTI "device:/dev/tpmrm0"

static const char *rc_str(TSS2_RC rc) {
  static char buf[64];
  snprintf(buf, sizeof(buf), "0x%08X", rc);
  return buf;
}

int main(int argc, char **argv) {
  const char *pin_str = (argc > 1) ? argv[1] : "";
  uint32_t key_handle =
      (argc > 2) ? (uint32_t)strtoul(argv[2], NULL, 0) : DEFAULT_KEY_HANDLE;
  const char *tcti_conf = (argc > 3) ? argv[3] : DEFAULT_TCTI;

  TSS2_RC rc;
  TSS2_TCTI_CONTEXT *tcti = NULL;
  ESYS_CONTEXT *ctx = NULL;
  ESYS_TR key_tr = ESYS_TR_NONE;
  TPMT_SIGNATURE *tpm_sig = NULL;
  int ret = 1;

  unsigned char challenge[32];
  FILE *urand = NULL;

  printf("TCTI:      %s\n", tcti_conf);
  printf("Key handle: 0x%08X\n", key_handle);
  printf("PIN len:   %zu\n", strlen(pin_str));

  /* ---- generate challenge -------------------------------------- */
  urand = fopen("/dev/urandom", "r");
  if (!urand || fread(challenge, 1, 32, urand) != 32) {
    fprintf(stderr, "FAIL: /dev/urandom\n");
    goto out;
  }
  fclose(urand);
  urand = NULL;
  printf("Challenge:  generated 32 bytes\n");

  /* ---- init TCTI ----------------------------------------------- */
  rc = Tss2_TctiLdr_Initialize(tcti_conf, &tcti);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "FAIL: Tss2_TctiLdr_Initialize → %s\n", rc_str(rc));
    goto out;
  }
  printf("TCTI init: OK\n");

  /* ---- init ESYS ----------------------------------------------- */
  rc = Esys_Initialize(&ctx, tcti, NULL);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "FAIL: Esys_Initialize → %s\n", rc_str(rc));
    goto out;
  }
  tcti = NULL;
  printf("ESYS init: OK\n");

  /* ---- startup ------------------------------------------------- */
  rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
  if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
    fprintf(stderr, "FAIL: Esys_Startup → %s\n", rc_str(rc));
    goto out;
  }
  printf("Startup:   %s\n",
         (rc == TPM2_RC_INITIALIZE) ? "already started" : "OK");

  /* ---- get ESYS_TR for persistent handle ----------------------- */
  rc = Esys_TR_FromTPMPublic(ctx, (TPM2_HANDLE)key_handle, ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &key_tr);
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "FAIL: Esys_TR_FromTPMPublic → %s\n", rc_str(rc));
    goto out;
  }
  printf("TR handle: OK (ESYS_TR=0x%X)\n", key_tr);

  /* ---- set auth ------------------------------------------------ */
  {
    size_t pin_len = strlen(pin_str);
    TPM2B_AUTH auth = {.size = (uint16_t)pin_len};
    memcpy(auth.buffer, pin_str, pin_len);
    rc = Esys_TR_SetAuth(ctx, key_tr, &auth);
    if (rc != TSS2_RC_SUCCESS) {
      fprintf(stderr, "FAIL: Esys_TR_SetAuth → %s\n", rc_str(rc));
      goto out;
    }
  }
  printf("Set auth:  OK\n");

  /* ---- sign ---------------------------------------------------- */
  {
    TPM2B_DIGEST digest = {.size = 32};
    memcpy(digest.buffer, challenge, 32);

    TPMT_SIG_SCHEME scheme = {.scheme = TPM2_ALG_ECDSA,
                              .details.ecdsa.hashAlg = TPM2_ALG_SHA256};
    TPMT_TK_HASHCHECK null_ticket = {.tag = TPM2_ST_HASHCHECK,
                                     .hierarchy = TPM2_RH_NULL};

    rc = Esys_Sign(ctx, key_tr, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   &digest, &scheme, &null_ticket, &tpm_sig);
  }
  if (rc != TSS2_RC_SUCCESS) {
    fprintf(stderr, "FAIL: Esys_Sign → %s\n", rc_str(rc));
    goto out;
  }
  printf("Sign:      OK\n");

  /* ---- extract signature --------------------------------------- */
  if (tpm_sig->sigAlg == TPM2_ALG_ECDSA) {
    printf("Signature: ECDSA  r=%u bytes  s=%u bytes\n",
           tpm_sig->signature.ecdsa.signatureR.size,
           tpm_sig->signature.ecdsa.signatureS.size);
    ret = 0;
  } else {
    fprintf(stderr, "FAIL: unexpected sigAlg=0x%X\n", tpm_sig->sigAlg);
    goto out;
  }

out:
  if (tpm_sig)
    free(tpm_sig);
  if (ctx)
    Esys_Finalize(&ctx);
  if (tcti)
    Tss2_TctiLdr_Finalize(&tcti);
  if (urand)
    fclose(urand);
  return ret;
}
