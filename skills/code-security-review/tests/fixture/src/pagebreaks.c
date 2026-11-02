/* GNU style: page breaks between functions. */
#include <string.h>

void a(char *d, const char *s)   /* EXPECT-FUNC: a */
{
    strcpy(d, s);                 /* EXPECT: MEM-001 */
}

void b(const char *u)            /* EXPECT-FUNC: b */
{
    system(u);                    /* EXPECT: INJ-002 */
}
