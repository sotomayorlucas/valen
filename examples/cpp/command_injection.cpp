#include <cstdio>
#include <cstdlib>
#include <cstring>

/* CWE-78 / CWE-120: command injection + buffer overflow */
void run(const char *input) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "echo %s", input);
    system(cmd);
}

int main(int argc, char **argv) {
    char *env_cmd = getenv("CMD");
    if (env_cmd) {
        system(env_cmd);
    }

    char small[8];
    char *big = getenv("PAYLOAD");
    if (big) {
        strcpy(small, big);  /* buffer overflow */
    }

    char line[32];
    fgets(line, sizeof(line), stdin);
    system(line);
    return 0;
}
