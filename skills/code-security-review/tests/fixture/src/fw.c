/* C, firmware-shaped: the physical-attacker rules (HW-*), and the name-matched
 * rules whose hit is the function itself rather than a line in it. */
#include <stdint.h>
#include <string.h>

static const uint8_t sbox[256] = {0};

int verify_pin(const uint8_t *pin, uint32_t stored_pin, unsigned n)  /* EXPECT-FUNC: verify_pin */ /* EXPECT: HW-007, LOG-004 */
{
    uint32_t given = 0;
    int auth_ok = 0;                                 /* EXPECT: HW-005 */
    for (unsigned i = 0; i < n; i++)                 /* EXPECT: HW-004 */
        given = (given << 8) | pin[i];
    if (given == stored_pin)                         /* EXPECT: HW-009, LOG-008 */
        auth_ok = 1;
    return auth_ok;
}

int dispatch(int state)                              /* EXPECT-FUNC: dispatch */
{
    switch (state) {                                 /* EXPECT: HW-001 */
    case 1: return unlock_debug();                   /* EXPECT: HW-003 */
    default: return 0;
    }
}

void load_key(uint8_t *out)                          /* EXPECT-FUNC: load_key */
{
    uint8_t aes_key[16];                             /* EXPECT: HW-010 */
    otp_read(0x40, aes_key, sizeof(aes_key));        /* EXPECT: HW-006 */
    AES_encrypt(aes_key, out, NULL);                 /* EXPECT: HW-002 */
    send(0, out, 16, 0);                             /* EXPECT: HW-008 */
    memset(aes_key, 0, sizeof(aes_key));             /* EXPECT: HW-012 */
}

uint8_t sub_byte(uint8_t x)                          /* EXPECT-FUNC: sub_byte */
{
    return sbox[x];                                  /* EXPECT: HW-011 */
}

int bn_mod_exp(uint32_t *r, const uint32_t *b, unsigned n)   /* EXPECT-FUNC: bn_mod_exp */ /* EXPECT: LOG-007 */
{
    return r[0] = b[n - 1];
}

/* Appended below so that nothing citing the lines above moves. A logic-flaw
 * rule with a line_pattern has each half asserted on its own: a sink inside a
 * function its name half does not select, and a name on a definition line no
 * sink shares. The rules asserted only in Python until now get a C spelling. */

int load_peer(EVP_MD_CTX *ctx, const unsigned char *sig, size_t n)   /* EXPECT-FUNC: load_peer */
{
    return EVP_DigestVerifyFinal(ctx, sig, n);                       /* EXPECT: LOG-004 */
}

unsigned wire_len(const unsigned char *buf)                         /* EXPECT-FUNC: wire_len */
{
    return (*(struct wire_hdr *)buf).len;                           /* EXPECT: LOG-006 */
}

int sshpam_auth_passwd(const char *user, const char *pw)            /* EXPECT-FUNC: sshpam_auth_passwd */ /* EXPECT: LOG-001 */
{
    return user != pw;
}

int user_key_allowed(int uid)                                       /* EXPECT-FUNC: user_key_allowed */ /* EXPECT: LOG-002 */
{
    return uid == 0;
}

int hmac_finish(unsigned char *out, unsigned n)                     /* EXPECT-FUNC: hmac_finish */ /* EXPECT: LOG-003 */
{
    return out[n - 1];
}

/* Appended below so that nothing citing the lines above moves. The spellings
 * the logic-flaw patterns did not know. CVE-2008-5077: EVP_VerifyFinal returns
 * -1 on error, and a caller testing `if (i)` takes that for a good signature. */

int accept_update(EVP_MD_CTX *md_ctx, const unsigned char *p, unsigned n, EVP_PKEY *pkey)   /* EXPECT-FUNC: accept_update */
{
    int i = EVP_VerifyFinal(md_ctx, p, n, pkey);                     /* EXPECT: LOG-004 */
    return i != 0;
}

int parse_ske(mbedtls_pk_context *pk, const unsigned char *h, const unsigned char *s, size_t sl)   /* EXPECT-FUNC: parse_ske */
{
    mbedtls_pk_verify(pk, MBEDTLS_MD_SHA256, h, 32, s, sl);          /* EXPECT: LOG-004 */
    return 0;
}

int userauth_none(const char *user)                                 /* EXPECT-FUNC: userauth_none */ /* EXPECT: LOG-001 */
{
    return user == NULL;
}

int mbedtls_ecp_gen_privkey(void *grp, void *d)                     /* EXPECT-FUNC: mbedtls_ecp_gen_privkey */ /* EXPECT: LOG-003, LOG-005 */
{
    return grp == d;
}

int ecp_mul_comb_after_precomp(const unsigned char *k, unsigned n)  /* EXPECT-FUNC: ecp_mul_comb_after_precomp */ /* EXPECT: LOG-007 */
{
    return k[n - 1];
}

int mbedtls_ssl_session_load(void *session, const unsigned char *buf, size_t len)   /* EXPECT-FUNC: mbedtls_ssl_session_load */ /* EXPECT: LOG-006, LOG-009 */
{
    return session == buf;
}

int mbedtls_ssl_ticket_parse(unsigned age, unsigned lifetime)       /* EXPECT-FUNC: mbedtls_ssl_ticket_parse */ /* EXPECT: LOG-009 */
{
    return age > lifetime;
}

/* A discarded result is the LOG-004 defect itself, and a cast in front of the
 * call is a context the sink half once read as no call at all. */
int open_message(unsigned char *m, unsigned long *mlen, const unsigned char *sm, unsigned long smlen, const unsigned char *pk)   /* EXPECT-FUNC: open_message */
{
    (void) crypto_sign_open(m, mlen, sm, smlen, pk);                 /* EXPECT: LOG-004 */
    return 0;
}

/* A byte of the MAC against a byte of the one computed: the loop leaves at the
 * first difference. */
int macs_equal(const unsigned char *hmac, const unsigned char *hmac_calc, int n)   /* EXPECT-FUNC: macs_equal */
{
    for (int i = 0; i < n; i++) {
        if (hmac[i] != hmac_calc[i])                                 /* EXPECT: LOG-008 */
            return 0;
    }
    return 1;
}
