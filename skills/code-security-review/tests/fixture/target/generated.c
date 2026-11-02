/* Build output: excluded by default at stage 1, so this carries no
 * EXPECT, and the candidate gate's recount must skip it as well. */
#include <stdlib.h>

int generated(const char *cmd)
{
    return system(cmd);
}
