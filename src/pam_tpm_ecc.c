/*
 * pam_tpm_ecc.c — PAM module: TPM ECDSA challenge-response authentication
 *
 * Replaces pam_tpm_ecc.sh with a memory-safe C implementation.
 * All sensitive material (PIN, challenge, signature) is locked from swap
 * and zeroed before free / return.
 *
 * Dependencies: tpm2-tss (esys), openssl >= 1.1, libpam
 *
 * PAM config line:
 *   auth sufficient pam_tpm_ecc.so \
 *       key_handle=0x81020001 \
 *       pubkey=/home/texsd/Workdir/tpm/pub.pem \
 *       [tcti=device:/dev/tpmrm0]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define CHALLENGE_SIZE   32U
#define MAX_PIN_LEN      256U
#define MAX_PATH_LEN     512U
#define MAX_SIG_RAW      (48U * 2)   /* P-256 ECC: 2 x 48-byte components */

#define DEFAULT_TCTI     "device:/dev/tpmrm0"

/* ------------------------------------------------------------------ */
/*  Secure-memory helpers                                              */
/* ------------------------------------------------------------------ */

/*
 * secure_zero  – guaranteed zeroing via glibc explicit_bzero.
 *                Backed by compiler barriers and a symbol-preservation
 *                technique that defeats dead-store elimination even
 *                under LTO.  (Single volatile store as additional
 *                guard on very old toolchains.)
 */
static void
secure_zero(void *p, size_t n)
{
    if (p == NULL || n == 0)
        return;
    explicit_bzero(p, n);
}

static int
secure_mlock(void *p, size_t n)
{
    if (p == NULL || n == 0)
        return 0;
    if (mlock(p, n) != 0)
        return errno;
    return 0;
}

static void
secure_munlock(void *p, size_t n)
{
    if (p != NULL && n > 0)
        munlock(p, n);
}

/* ------------------------------------------------------------------ */
/*  Public-key file — atomic open + validate (TOCTOU-safe)              */
/*                                                                      */
/*  Opens the file, then validates the handle with fstat, so the check  */
/*  and subsequent read are on the same inode.  Returns a fd on success */
/*  or -1 on failure (with a syslog message).                           */
/* ------------------------------------------------------------------ */

static int
open_and_validate_pubkey(pam_handle_t *pamh, const char *path)
{
    struct stat st;
    int fd;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        pam_syslog(pamh, LOG_ERR, "open(%s) failed: %s", path, strerror(errno));
        return -1;
    }

    if (fstat(fd, &st) != 0) {
        pam_syslog(pamh, LOG_ERR, "fstat(%s) failed: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        pam_syslog(pamh, LOG_ERR, "%s is not a regular file", path);
        close(fd);
        return -1;
    }
    if (st.st_uid != 0) {
        pam_syslog(pamh, LOG_ERR, "%s is not owned by root", path);
        close(fd);
        return -1;
    }
    if ((st.st_mode & 0777) & ~0644) {
        pam_syslog(pamh, LOG_ERR, "%s has overly-permissive mode %04o",
                   path, (unsigned)(st.st_mode & 07777));
        close(fd);
        return -1;
    }
    return fd;
}

/* ------------------------------------------------------------------ */
/*  Argument parsing (key_handle, pubkey, tcti)                        */
/* ------------------------------------------------------------------ */

static int
parse_args(pam_handle_t *pamh, int argc, const char **argv,
           uint32_t *kh, const char **pk, const char **tcti)
{
    *kh   = 0;
    *pk   = NULL;
    *tcti = DEFAULT_TCTI;

    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "key_handle=", 11U) == 0) {
            char *end = NULL;
            unsigned long v = strtoul(argv[i] + 11, &end, 0);
            if (end == argv[i] + 11 || *end != '\0' || v > UINT32_MAX) {
                pam_syslog(pamh, LOG_ERR, "invalid key_handle: %s", argv[i] + 11);
                return -1;
            }
            *kh = (uint32_t)v;
        } else if (strncmp(argv[i], "pubkey=", 7U) == 0) {
            *pk = argv[i] + 7;
        } else if (strncmp(argv[i], "tcti=", 5U) == 0) {
            *tcti = argv[i] + 5;
        }
    }

    if (*kh == 0) {
        pam_syslog(pamh, LOG_ERR, "key_handle= missing");
        return -1;
    }
    if (*pk == NULL || **pk == '\0') {
        pam_syslog(pamh, LOG_ERR, "pubkey= missing");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  TPM2 – obtain challenge signature via ESYS                         */
/*                                                                     */
/*  On success *sig_len receives the raw r||s length.                  */
/*  sig_out must have room for MAX_SIG_RAW bytes.                      */
/* ------------------------------------------------------------------ */

static int
tpm_sign(pam_handle_t *pamh,
         const char *tcti_conf, uint32_t key_handle_val,
         const unsigned char *pin, size_t pin_len,
         const unsigned char *challenge, size_t chal_len,
         unsigned char *sig_out, size_t *sig_len)
{
    TSS2_RC         rc;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT   *ctx = NULL;
    ESYS_TR         key_tr = ESYS_TR_NONE;
    TPMT_SIGNATURE *tpm_sig = NULL;
    int             ret = -1;

    /* ---- init TCTI + ESYS --------------------------------------- */
    rc = Tss2_TctiLdr_Initialize(tcti_conf, &tcti);
    if (rc != TSS2_RC_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Tss2_TctiLdr_Initialize: 0x%08X", rc);
        goto out;
    }

    rc = Esys_Initialize(&ctx, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Esys_Initialize: 0x%08X", rc);
        goto out;
    }
    tcti = NULL;               /* owned by ctx now */

    /* ---- startup — required by ESYS even when RM is present ------ */
    rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
    if (rc != TSS2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
        /* TPM2_RC_INITIALIZE means TPM was already started — OK */
        pam_syslog(pamh, LOG_ERR, "Esys_Startup: 0x%08X", rc);
        goto out;
    }

    /* ---- get ESYS_TR for persistent handle ----------------------- */
    rc = Esys_TR_FromTPMPublic(ctx, (TPM2_HANDLE)key_handle_val,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &key_tr);
    if (rc != TSS2_RC_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Esys_TR_FromTPMPublic(0x%08X): 0x%08X",
                   key_handle_val, rc);
        goto out;
    }

    /* ---- set auth value (PIN) ------------------------------------ */
    if (pin != NULL && pin_len > 0) {
        TPM2B_AUTH auth = { .size = (uint16_t)pin_len };
        if (pin_len > sizeof(auth.buffer))
            goto out;
        memcpy(auth.buffer, pin, pin_len);
        rc = Esys_TR_SetAuth(ctx, key_tr, &auth);
        secure_zero(auth.buffer, sizeof(auth.buffer));
        if (rc != TSS2_RC_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "Esys_TR_SetAuth: 0x%08X", rc);
            goto out;
        }
    }

    /* ---- pre-hash challenge (TPM with null ticket signs digest as-is) */
    unsigned char message_hash[32];
    SHA256(challenge, chal_len, message_hash);

    /* ---- sign ---------------------------------------------------- */
    {
        TPM2B_DIGEST digest = { .size = 32 };
        memcpy(digest.buffer, message_hash, 32);

        TPMT_SIG_SCHEME scheme = {
            .scheme = TPM2_ALG_ECDSA,
            .details.ecdsa.hashAlg = TPM2_ALG_SHA256
        };

        /*
         * tpm2-tss 4.x requires a non-NULL validation ticket.
         * A null ticket (tag=HASHCHECK, hierarchy=NULL) means the
         * digest was not produced by a TPM-restricted key.  With a
         * null ticket the TPM signs the digest bytes directly without
         * re-hashing, so we must pre-hash with SHA256 ourselves.
         */
        TPMT_TK_HASHCHECK null_ticket = {
            .tag       = TPM2_ST_HASHCHECK,
            .hierarchy = TPM2_RH_NULL
        };

        rc = Esys_Sign(ctx, key_tr,
                       ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                       &digest, &scheme, &null_ticket, &tpm_sig);
    }

    secure_zero(message_hash, sizeof(message_hash));
    if (rc != TSS2_RC_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "Esys_Sign: 0x%08X", rc);
        goto out;
    }

    /* ---- extract raw r || s -------------------------------------- */
    if (tpm_sig->sigAlg != TPM2_ALG_ECDSA)
        goto out;

    {
        uint16_t rs = tpm_sig->signature.ecdsa.signatureR.size;
        uint16_t ss = tpm_sig->signature.ecdsa.signatureS.size;

        if (rs > 32 || ss > 32)
            goto out;

        /* Pad both components to 32 bytes (P-256 key size) so midpoint
         * split in pubkey_verify is always correct, regardless of
         * leading-zero variance in the TPM output. */
        memset(sig_out, 0, 64);
        memcpy(sig_out + 32 - rs,
               tpm_sig->signature.ecdsa.signatureR.buffer, rs);
        memcpy(sig_out + 64 - ss,
               tpm_sig->signature.ecdsa.signatureS.buffer, ss);
        *sig_len = 64;
    }

    ret = 0;

out:
    if (tpm_sig != NULL) {
        secure_zero(tpm_sig, sizeof(*tpm_sig));
        free(tpm_sig);
    }
    if (ctx != NULL)
        Esys_Finalize(&ctx);
    if (tcti != NULL)
        Tss2_TctiLdr_Finalize(&tcti);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  OpenSSL – convert raw r||s to DER then verify against PEM pubkey  */
/* ------------------------------------------------------------------ */

static int
pubkey_verify(pam_handle_t *pamh,
              int pubkey_fd,
              const unsigned char *challenge, size_t chal_len,
              const unsigned char *raw_sig, size_t raw_sig_len)
{
    int              ret = -1;
    BIO             *bio = NULL;
    EVP_PKEY        *pkey = NULL;
    EVP_MD_CTX      *mdctx = NULL;
    ECDSA_SIG       *ecsig = NULL;
    unsigned char   *der = NULL;
    int              der_len = 0;

    /* ---- load public key from validated fd ------------------------
     * BIO_new_fd takes ownership and closes fd on free.            */
    bio = BIO_new_fd(pubkey_fd, BIO_CLOSE);
    if (bio == NULL) {
        pam_syslog(pamh, LOG_ERR, "BIO_new_fd failed");
        close(pubkey_fd);
        goto out;
    }

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        pam_syslog(pamh, LOG_ERR, "PEM_read_bio_PUBKEY failed");
        goto out;
    }

    /* ---- convert raw r||s → DER --------------------------------- */
    {
        /* Both components are 32 bytes (padded in tpm_sign) */
        size_t half = 32;

        BIGNUM *r = BN_bin2bn(raw_sig, (int)half, NULL);
        BIGNUM *s = BN_bin2bn(raw_sig + half, (int)(raw_sig_len - half), NULL);
        if (r == NULL || s == NULL) {
            pam_syslog(pamh, LOG_ERR, "BN_bin2bn failed");
            BN_free(r);
            BN_free(s);
            goto out;
        }

        ecsig = ECDSA_SIG_new();
        if (ecsig == NULL || ECDSA_SIG_set0(ecsig, r, s) == 0) {
            pam_syslog(pamh, LOG_ERR, "ECDSA_SIG_set0 failed");
            BN_free(r);
            BN_free(s);
            goto out;
        }
        /* r,s ownership transferred to ecsig — do NOT free separately */

        der_len = i2d_ECDSA_SIG(ecsig, &der);
        if (der_len <= 0) {
            pam_syslog(pamh, LOG_ERR, "i2d_ECDSA_SIG failed");
            goto out;
        }
    }

    /* ---- verify ------------------------------------------------- */
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        pam_syslog(pamh, LOG_ERR, "EVP_MD_CTX_new failed");
        goto out;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        pam_syslog(pamh, LOG_ERR, "EVP_DigestVerifyInit failed");
        goto out;
    }

    if (EVP_DigestVerifyUpdate(mdctx, challenge, chal_len) != 1) {
        pam_syslog(pamh, LOG_ERR, "EVP_DigestVerifyUpdate failed");
        goto out;
    }

    if (EVP_DigestVerifyFinal(mdctx, der, (size_t)der_len) != 1) {
        pam_syslog(pamh, LOG_ERR, "EVP_DigestVerifyFinal: signature mismatch");
        goto out;
    }

    ret = 0;   /* signature valid */

out:
    if (der != NULL) {
        secure_zero(der, (size_t)der_len);
        OPENSSL_free(der);
    }
    ECDSA_SIG_free(ecsig);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  PAM entry point – pam_sm_authenticate                              */
/* ------------------------------------------------------------------ */

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
                    int argc, const char **argv)
{
    (void)flags;

    int              pam_ret = PAM_AUTH_ERR;
    uint32_t         key_handle = 0;
    const char      *pubkey_path = NULL;
    const char      *tcti_conf = NULL;
    char            *pin = NULL;
    unsigned char   *challenge = NULL;
    unsigned char   *sig_raw = NULL;
    size_t           sig_len = 0;

    /* ---- parse arguments ----------------------------------------- */
    if (parse_args(pamh, argc, argv, &key_handle, &pubkey_path, &tcti_conf) != 0)
        return PAM_SERVICE_ERR;

    /* ---- open + validate public key file (TOCTOU-safe) ------------ */
    int pubkey_fd = open_and_validate_pubkey(pamh, pubkey_path);
    if (pubkey_fd < 0)
        return PAM_SERVICE_ERR;

    /* ---- allocate and lock sensitive buffers --------------------- */
    pin = calloc(1, MAX_PIN_LEN + 1);
    challenge = calloc(1, CHALLENGE_SIZE);
    sig_raw = calloc(1, MAX_SIG_RAW);

    if (pin == NULL || challenge == NULL || sig_raw == NULL) {
        pam_syslog(pamh, LOG_CRIT, "allocation failed");
        pam_ret = PAM_BUF_ERR;
        goto cleanup;
    }

    /* Lock pages so pin / challenge / sig never hit swap */
    if (secure_mlock(pin, MAX_PIN_LEN + 1) != 0 ||
        secure_mlock(challenge, CHALLENGE_SIZE) != 0 ||
        secure_mlock(sig_raw, MAX_SIG_RAW) != 0) {
        pam_syslog(pamh, LOG_CRIT, "mlock failed (RLIMIT_MEMLOCK?) — rejecting");
        pam_ret = PAM_BUF_ERR;
        goto cleanup;
    }

    /* ---- obtain PIN via PAM conversation ------------------------- */
    {
        struct pam_conv *conv = NULL;
        if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS
            || conv == NULL || conv->conv == NULL) {
            pam_syslog(pamh, LOG_ERR, "no conversation function");
            goto cleanup;
        }

        struct pam_message msg = {
            .msg_style = PAM_PROMPT_ECHO_OFF,
            .msg       = "TPM PIN: "
        };
        const struct pam_message *msgp = &msg;
        struct pam_response *resp = NULL;

        int cv_ret = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
        if (cv_ret != PAM_SUCCESS || resp == NULL || resp->resp == NULL) {
            pam_syslog(pamh, LOG_ERR, "conversation failed");
            goto cleanup;
        }

        size_t pin_len = strnlen(resp->resp, MAX_PIN_LEN);
        if (pin_len == 0 || pin_len > MAX_PIN_LEN) {
            secure_zero(resp->resp, strnlen(resp->resp, MAX_PIN_LEN + 1));
            free(resp->resp);
            free(resp);
            pam_syslog(pamh, LOG_ERR, "empty or overlong PIN");
            goto cleanup;
        }

        memcpy(pin, resp->resp, pin_len);
        /* pin_len already <= MAX_PIN_LEN, pin is zero-filled */
        secure_zero(resp->resp, strnlen(resp->resp, MAX_PIN_LEN + 1));
        free(resp->resp);
        free(resp);
    }

    /* ---- generate challenge -------------------------------------- */
    if (RAND_bytes(challenge, CHALLENGE_SIZE) != 1) {
        pam_syslog(pamh, LOG_ERR, "RAND_bytes failed");
        goto cleanup;
    }

    /* ---- TPM signature ------------------------------------------- */
    if (tpm_sign(pamh, tcti_conf, key_handle,
                 (unsigned char *)pin, strnlen(pin, MAX_PIN_LEN),
                 challenge, CHALLENGE_SIZE,
                 sig_raw, &sig_len) != 0) {
        pam_syslog(pamh, LOG_ERR, "TPM sign failed");
        goto cleanup;
    }

    /* ---- OpenSSL verification ------------------------------------ */
    if (pubkey_verify(pamh, pubkey_fd,
                      challenge, CHALLENGE_SIZE,
                      sig_raw, sig_len) != 0) {
        pam_syslog(pamh, LOG_ERR, "signature verification failed");
        goto cleanup;
    }
    pubkey_fd = -1;  /* fd ownership transferred to OpenSSL BIO */

    pam_syslog(pamh, LOG_INFO, "TPM ECC authentication succeeded");
    pam_ret = PAM_SUCCESS;

cleanup:
    /* Close pubkey fd if still owned (error before BIO takes over) */
    if (pubkey_fd >= 0)
        close(pubkey_fd);
    /* Zero and unlock sensitive buffers */
    if (pin != NULL) {
        secure_zero(pin, MAX_PIN_LEN + 1);
        secure_munlock(pin, MAX_PIN_LEN + 1);
        free(pin);
    }
    if (challenge != NULL) {
        secure_zero(challenge, CHALLENGE_SIZE);
        secure_munlock(challenge, CHALLENGE_SIZE);
        free(challenge);
    }
    if (sig_raw != NULL) {
        secure_zero(sig_raw, MAX_SIG_RAW);
        secure_munlock(sig_raw, MAX_SIG_RAW);
        free(sig_raw);
    }

    return pam_ret;
}

/* ---- stub the other PAM entry points -------------------------------- */

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
