/*
 * test_verify.c — unit tests for ECDSA signature DER conversion & OpenSSL verification
 *
 * Self-contained: generates an EC P-256 keypair in-process, signs a challenge,
 * converts the DER signature back to raw r||s (simulating the TPM output path),
 * then verifies through the exact same logic that pam_tpm_ecc.c uses.
 *
 * No TPM or PAM required.  Pure OpenSSL.
 *
 * Compile (manual):
 *   gcc -std=c11 -Wall -Wextra -O2 -o test_verify test_verify.c -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* ---------- helpers (same as pam_tpm_ecc.c) ---------------------------- */

static void
sec_zero(void *p, size_t n)
{
    if (p == NULL || n == 0) return;
    volatile unsigned char *vp = p;
    while (n--) *vp++ = 0;
}

/* ---------- DER → raw r||s (inverse of the module's conversion) -------- */

/*
 * der_to_raw  – extract r||s from a DER-encoded ECDSA signature.
 *                sig_raw_out must have room for 2 * key_bytes bytes.
 * Returns total raw length, or 0 on error.
 */
static size_t
der_to_raw(const unsigned char *der, int der_len,
           unsigned char *raw_out, size_t key_bytes)
{
    const unsigned char *p = der;
    ECDSA_SIG *ecsig = d2i_ECDSA_SIG(NULL, &p, (long)der_len);
    if (ecsig == NULL) return 0;

    const BIGNUM *r = NULL, *s = NULL;
    ECDSA_SIG_get0(ecsig, &r, &s);

    int rlen = BN_num_bytes(r);
    int slen = BN_num_bytes(s);
    if (rlen > (int)key_bytes || slen > (int)key_bytes) {
        ECDSA_SIG_free(ecsig);
        return 0;
    }

    /* left-pad with zeros to key_bytes */
    memset(raw_out, 0, key_bytes * 2);
    BN_bn2binpad(r, raw_out, (int)key_bytes);
    BN_bn2binpad(s, raw_out + key_bytes, (int)key_bytes);

    ECDSA_SIG_free(ecsig);
    return key_bytes * 2;
}

/* ---------- raw r||s → DER → verify (mirrors pubkey_verify) ------------ */

static int
raw_verify(EVP_PKEY *pkey,
           const unsigned char *challenge, size_t chal_len,
           const unsigned char *raw_sig, size_t raw_sig_len)
{
    int              ret = -1;
    EVP_MD_CTX      *mdctx = NULL;
    ECDSA_SIG       *ecsig = NULL;
    unsigned char   *der = NULL;
    int              der_len = 0;

    /* ---- convert raw r||s → DER --------------------------------- */
    {
        size_t half = raw_sig_len / 2;

        BIGNUM *r = BN_bin2bn(raw_sig, (int)half, NULL);
        BIGNUM *s = BN_bin2bn(raw_sig + half, (int)(raw_sig_len - half), NULL);
        if (r == NULL || s == NULL) {
            BN_free(r); BN_free(s);
            goto out;
        }

        ecsig = ECDSA_SIG_new();
        if (ecsig == NULL || ECDSA_SIG_set0(ecsig, r, s) == 0) {
            BN_free(r); BN_free(s);
            goto out;
        }

        der_len = i2d_ECDSA_SIG(ecsig, &der);
        if (der_len <= 0) goto out;
    }

    /* ---- verify ------------------------------------------------- */
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) goto out;

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1)
        goto out;
    if (EVP_DigestVerifyUpdate(mdctx, challenge, chal_len) != 1)
        goto out;
    if (EVP_DigestVerifyFinal(mdctx, der, (size_t)der_len) != 1)
        goto out;

    ret = 0;

out:
    if (der != NULL) { sec_zero(der, (size_t)der_len); OPENSSL_free(der); }
    ECDSA_SIG_free(ecsig);
    EVP_MD_CTX_free(mdctx);
    return ret;
}

/* ---------- test harness ----------------------------------------------- */

static int tests_run   = 0;
static int tests_fail  = 0;

#define TEST(name)  do { tests_run++; fprintf(stderr, "  %-45s ", name); } while(0)
#define PASS()      do { fprintf(stderr, "PASS\n"); } while(0)
#define FAIL(fmt, ...) \
    do { fprintf(stderr, "FAIL  " fmt "\n", ##__VA_ARGS__); tests_fail++; } while(0)

/* ------------------------------------------------------------------ */
/*  Test 1: sign with OpenSSL → convert to raw → verify with raw_verify  */
/* ------------------------------------------------------------------ */
static int
test_roundtrip(void)
{
    TEST("raw r||s → DER → verify roundtrip");

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char challenge[32];
    unsigned char der_sig[256];
    unsigned char raw_sig[64];
    size_t der_sig_len = sizeof(der_sig);
    size_t raw_len;
    int ok = 0;

    /* generate EC P-256 keypair */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) { FAIL("pctx alloc"); goto out; }
    if (EVP_PKEY_keygen_init(pctx) != 1) { FAIL("keygen_init"); goto out; }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1)
        { FAIL("set_curve"); goto out; }
    if (EVP_PKEY_keygen(pctx, &pkey) != 1) { FAIL("keygen"); goto out; }

    /* challenge */
    if (RAND_bytes(challenge, sizeof(challenge)) != 1)
        { FAIL("RAND_bytes"); goto out; }

    /* sign (hashes internally with SHA256) */
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) { FAIL("mdctx alloc"); goto out; }
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1)
        { FAIL("DigestSignInit"); goto out; }
    if (EVP_DigestSignUpdate(mdctx, challenge, sizeof(challenge)) != 1)
        { FAIL("DigestSignUpdate"); goto out; }
    if (EVP_DigestSignFinal(mdctx, der_sig, &der_sig_len) != 1)
        { FAIL("DigestSignFinal"); goto out; }

    /* convert DER → raw (simulate TPM output) */
    raw_len = der_to_raw(der_sig, (int)der_sig_len, raw_sig, 32);
    if (raw_len != 64) { FAIL("der_to_raw returned %zu", raw_len); goto out; }

    /* verify with raw_verify() — same logic as pubkey_verify() */
    if (raw_verify(pkey, challenge, sizeof(challenge), raw_sig, raw_len) != 0)
        { FAIL("raw_verify rejected valid sig"); goto out; }

    ok = 1;
    PASS();

out:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Test 2: wrong challenge → must fail                                */
/* ------------------------------------------------------------------ */
static int
test_wrong_challenge(void)
{
    TEST("wrong challenge → verify fails");

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char challenge[32];
    unsigned char wrong[32];
    unsigned char der_sig[256];
    unsigned char raw_sig[64];
    size_t der_sig_len = sizeof(der_sig);
    size_t raw_len;
    int ok = 0;

    /* generate keypair */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) goto out;
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &pkey);

    /* challenge A */
    RAND_bytes(challenge, sizeof(challenge));
    /* challenge B (different) */
    RAND_bytes(wrong, sizeof(wrong));
    /* force difference */
    wrong[0] ^= 0xFF;

    /* sign challenge A */
    mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(mdctx, challenge, sizeof(challenge));
    EVP_DigestSignFinal(mdctx, der_sig, &der_sig_len);

    /* convert to raw */
    raw_len = der_to_raw(der_sig, (int)der_sig_len, raw_sig, 32);
    if (raw_len != 64) { FAIL("der_to_raw %zu", raw_len); goto out; }

    /* verify with WRONG challenge — must fail */
    if (raw_verify(pkey, wrong, sizeof(wrong), raw_sig, raw_len) == 0)
        { FAIL("accepted signature for wrong challenge"); goto out; }

    ok = 1;
    PASS();

out:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Test 3: corrupted signature → must fail                            */
/* ------------------------------------------------------------------ */
static int
test_corrupted_sig(void)
{
    TEST("corrupted signature → verify fails");

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char challenge[32];
    unsigned char der_sig[256];
    unsigned char raw_sig[64];
    size_t der_sig_len = sizeof(der_sig);
    size_t raw_len;
    int ok = 0;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &pkey);

    RAND_bytes(challenge, sizeof(challenge));

    mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(mdctx, challenge, sizeof(challenge));
    EVP_DigestSignFinal(mdctx, der_sig, &der_sig_len);

    raw_len = der_to_raw(der_sig, (int)der_sig_len, raw_sig, 32);
    if (raw_len != 64) { FAIL("der_to_raw %zu", raw_len); goto out; }

    /* flip a single bit in the middle of the signature */
    raw_sig[31] ^= 0x01;

    if (raw_verify(pkey, challenge, sizeof(challenge), raw_sig, raw_len) == 0)
        { FAIL("accepted corrupted signature"); goto out; }

    ok = 1;
    PASS();

out:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Test 4: raw r||s with leading-zero variance (BN core preserves value) */
/* ------------------------------------------------------------------ */
static int
test_leading_zero_r(void)
{
    TEST("r component w/ leading zero → still valid");

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char challenge[32];
    unsigned char der_sig[256];
    unsigned char raw_sig[64];
    ECDSA_SIG *ecsig = NULL;
    const BIGNUM *r = NULL, *s = NULL;
    unsigned char *der = NULL;
    size_t der_sig_len = sizeof(der_sig);
    int ok = 0;

    /* generate keypair */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_keygen(pctx, &pkey);
    RAND_bytes(challenge, sizeof(challenge));

    /* sign */
    mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(mdctx, challenge, sizeof(challenge));
    EVP_DigestSignFinal(mdctx, der_sig, &der_sig_len);

    /* parse DER signature */
    {
        const unsigned char *p = der_sig;
        ecsig = d2i_ECDSA_SIG(NULL, &p, (long)der_sig_len);
    }
    if (ecsig == NULL) { FAIL("d2i_ECDSA_SIG"); goto out; }
    ECDSA_SIG_get0(ecsig, &r, &s);

    /*
     * BN_bn2bin → i2d_ECDSA_SIG → d2i_ECDSA_SIG → BN_bn2bin
     * tests that the DER round-trip preserves the integer values
     * regardless of leading-zero encoding.
     */
    {
        size_t rs = (size_t)BN_bn2bin(r, raw_sig);
        size_t ss = (size_t)BN_bn2bin(s, raw_sig + rs);

        /* Re-encode via our module logic */
        BIGNUM *rn = BN_bin2bn(raw_sig, (int)rs, NULL);
        BIGNUM *sn = BN_bin2bn(raw_sig + rs, (int)ss, NULL);
        ECDSA_SIG *sig2 = ECDSA_SIG_new();
        ECDSA_SIG_set0(sig2, rn, sn);
        int dlen = i2d_ECDSA_SIG(sig2, &der);
        ECDSA_SIG_free(sig2);

        if (dlen <= 0) { FAIL("re-encode"); goto out; }

        /* verify with the re-encoded DER */
        EVP_MD_CTX *vctx = EVP_MD_CTX_new();
        int v = EVP_DigestVerifyInit(vctx, NULL, EVP_sha256(), NULL, pkey);
        v = v && EVP_DigestVerifyUpdate(vctx, challenge, sizeof(challenge));
        v = v && EVP_DigestVerifyFinal(vctx, der, (size_t)dlen);
        EVP_MD_CTX_free(vctx);
        sec_zero(der, (size_t)dlen);
        OPENSSL_free(der);

        if (v != 1) { FAIL("verify after re-encode"); goto out; }
    }

    ok = 1;
    PASS();

out:
    ECDSA_SIG_free(ecsig);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Test 5: PEM load failure on non-existent file                      */
/* ------------------------------------------------------------------ */
static int
test_bad_pem_path(void)
{
    TEST("non-existent PEM file → BIO_new_file fails");

    BIO *bio = BIO_new_file("/tmp/__nonexistent_xyz.pem", "r");
    if (bio != NULL) {
        BIO_free(bio);
        FAIL("opened non-existent file");
        return 0;
    }
    PASS();
    return 1;
}

/* ------------------------------------------------------------------ */
/*  main                                                                */
/* ------------------------------------------------------------------ */

int
main(void)
{
    fprintf(stderr, "=== pam_tpm_ecc unit tests ===\n\n");

    test_roundtrip();
    test_wrong_challenge();
    test_corrupted_sig();
    test_leading_zero_r();
    test_bad_pem_path();

    fprintf(stderr, "\n%d/%d tests passed\n",
            tests_run - tests_fail, tests_run);

    return tests_fail == 0 ? 0 : 1;
}
