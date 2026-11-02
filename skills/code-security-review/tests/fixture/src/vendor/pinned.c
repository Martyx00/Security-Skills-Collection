/* First-party code kept under vendor/. Excluded by default, and
 * recovered by the path-scoped `--include src/vendor` that
 * smoke_test.py passes; every later stage has to walk it too. */
#include <string.h>

void pinned_copy(char *d, const char *s)             /* EXPECT-FUNC: pinned_copy */
{
    strcpy(d, s);                                    /* EXPECT: MEM-001 */
}
