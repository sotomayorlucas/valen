#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-78: OS command injection via getenv -> system */
int main(int argc, char **argv) {
    char *cmd = getenv("CMD");
    if (cmd) {
        system(cmd);
    }

    char buf[64];
    fgets(buf, sizeof(buf), stdin);
    system(buf);

    char dst[8];
    strcpy(dst, getenv("PATH"));
    return 0;
}
