/* C: memory safety, the family the ruleset was originally written for. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

struct rec { char payload[256]; };

int parse_tlv(struct rec *r, const char *cur, unsigned n)   /* EXPECT-FUNC: parse_tlv */
{
    unsigned len = (unsigned)((cur[2] << 8) | cur[3]);
    if (len == 0) return -1;
    memcpy(r->payload, cur, len);                    /* EXPECT: MEM-002 */
    return 0;
}

int copy_name(struct rec *r, const char *name)       /* EXPECT-FUNC: copy_name */
{
    char local[32];
    strcpy(local, name);                             /* EXPECT: MEM-001 */
    sprintf(local, "%s", name);                      /* EXPECT: MEM-001 */
    memcpy(r->payload, local, sizeof(r->payload));   /* EXPECT-SKIP: MEM-002 */
    return 0;
}

void log_it(const char *user)                        /* EXPECT-FUNC: log_it */
{
    printf(user);                                    /* EXPECT: INJ-001 */
}

char *sized(unsigned a, unsigned b)                  /* EXPECT-FUNC: sized */
{
    return malloc(a * b);                            /* EXPECT: MEM-010 */
}

int read_in(int fd, struct rec *r, unsigned n)       /* EXPECT-FUNC: read_in */
{
    char buf[64];
    return (int)read(fd, buf, n);                    /* EXPECT: MEM-005 */
}

void shell(const char *u)                            /* EXPECT-FUNC: shell */
{
    system(u);                                       /* EXPECT: INJ-002 */
}

int check_mac(const char *given, const char *expected, unsigned n)  /* EXPECT-FUNC: check_mac */ /* EXPECT: LOG-010 */
{
    return memcmp(given, expected, n) == 0;          /* EXPECT: LOG-008, CRY-005, HW-009 */
}

/* Appended below the lines above so that nothing citing them moves. One
 * function per rule the lines above do not reach. */

static void on_term(int sig)                         /* EXPECT-FUNC: on_term */
{
    printf("bye %d\n", sig);
    exit(1);
}

/* OTH-004's skip is about the HANDLER argument. The error check on the
 * registration mentions SIG_ERR and registers a real handler all the same. */
int install_handlers(void)                           /* EXPECT-FUNC: install_handlers */
{
    struct sigaction sa;
    if (signal(SIGTERM, on_term) == SIG_ERR)         /* EXPECT: OTH-004 */
        return -1;
    sa.sa_handler = on_term;                         /* EXPECT: OTH-004 */
    return sigaction(SIGHUP, &sa, NULL);
}

int copy_bounded(char *dst, const char *src, size_t n)   /* EXPECT-FUNC: copy_bounded */
{
    char line[80];
    strncpy(dst, src, n);                            /* EXPECT: MEM-003 */
    snprintf(line, n, "%s", src);                    /* EXPECT: MEM-004, INJ-001 */
    return sscanf(src, "%79s", line);                /* EXPECT: MEM-006, INJ-006 */
}

/* realpath(p, NULL) is the safe call; a caller buffer smaller than PATH_MAX is
 * the overflow. MEM-007 used to match only the first. */
char *resolve(const char *user_path)                 /* EXPECT-FUNC: resolve */
{
    char out[64];                                    /* EXPECT: MEM-009 */
    if (!realpath(user_path, out))                   /* EXPECT: MEM-007 */
        return NULL;
    return strdup(out);
}

int *counter(void)                                   /* EXPECT-FUNC: counter */
{
    int local = 0;
    return &local;                                   /* EXPECT: MEM-009 */
}

/* The sizeof(<dest>) skip assumes dest comes first and the length is bytes.
 * bcopy takes the source first; wmemcpy counts wchar_t. Both are overflows. */
void copy_wide(struct rec *r, const wchar_t *wsrc, const char *big)   /* EXPECT-FUNC: copy_wide */
{
    wchar_t wdst[16];
    bcopy(big, r->payload, sizeof(big));             /* EXPECT: MEM-002 */
    wmemcpy(wdst, wsrc, sizeof(wdst));               /* EXPECT: MEM-002 */
}

void release_rec(struct rec *r)                      /* EXPECT-FUNC: release_rec */
{
    free(r);                                         /* EXPECT: MEM-008 */
    r->payload[0] = 0;
}

int port_of(const char *s)                           /* EXPECT-FUNC: port_of */
{
    return atoi(s);                                  /* EXPECT: INJ-006 */
}

int seal(EVP_CIPHER_CTX *c, const unsigned char *k)  /* EXPECT-FUNC: seal */
{
    unsigned char iv[16] = {0};                      /* EXPECT: CRY-001 */
    return EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, k, iv);   /* EXPECT: CRY-002, HW-002 */
}

SSL_CTX *weak_ctx(RSA **r)                           /* EXPECT-FUNC: weak_ctx */
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    *r = RSA_generate_key(1024, 65537, NULL, NULL);  /* EXPECT: CRY-003 */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);  /* EXPECT: CRY-004 */
    return ctx;
}

int drop_root(void)                                  /* EXPECT-FUNC: drop_root */
{
    FILE *f = fopen("/tmp/app.lock", "w");           /* EXPECT: OTH-001, INJ-004 */
    if (f) fclose(f);
    return setuid(0);                                /* EXPECT: OTH-003 */
}

void ignore_pipe(void)                               /* EXPECT-FUNC: ignore_pipe */
{
    signal(SIGPIPE, SIG_IGN);                        /* EXPECT-SKIP: OTH-004 */
}

/* Appended below so that nothing citing the lines above moves. A project's own
 * realpath helper, named more often than realpath itself. MEM-007 has no
 * wrapper_class, so there is no wrapper to name; the candidate gate once asked
 * it anyway and refused this file with nothing the operator could change. */
static char *safe_realpath(const char *p, char *out)   /* EXPECT-FUNC: safe_realpath */
{
    return realpath(p, out);                           /* EXPECT: MEM-007 */
}

int resolve_all(const char *a, const char *b, const char *c, const char *d)   /* EXPECT-FUNC: resolve_all */
{
    char w[PATH_MAX];
    if (safe_realpath(a, w) == NULL) return -1;
    if (safe_realpath(b, w) == NULL) return -1;
    if (safe_realpath(c, w) == NULL) return -1;
    if (safe_realpath(d, w) == NULL) return -1;
    return 0;
}
