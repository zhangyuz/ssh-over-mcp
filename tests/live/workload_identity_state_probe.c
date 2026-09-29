#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int wanted_status_line(const char *line) {
    static const char *prefixes[] = {
        "Uid:", "Gid:", "Groups:", "CapInh:", "CapPrm:",
        "CapEff:", "CapAmb:", "NoNewPrivs:",
    };
    size_t count = sizeof(prefixes) / sizeof(prefixes[0]);

    for (size_t i = 0; i < count; ++i) {
        size_t length = strlen(prefixes[i]);
        if (strncmp(line, prefixes[i], length) == 0) {
            return 1;
        }
    }
    return 0;
}

int main(void) {
    const char *raw_fd = getenv("SSH_OVER_MCP_LIVE_REPORT_FD");
    if (raw_fd == NULL || *raw_fd == '\0') {
        return 2;
    }

    char *end = NULL;
    long parsed_fd = strtol(raw_fd, &end, 10);
    if (end == raw_fd || *end != '\0' || parsed_fd < 0) {
        return 3;
    }

    FILE *status = fopen("/proc/self/status", "r");
    if (status == NULL) {
        return 4;
    }

    int fd = (int)parsed_fd;
    if (dprintf(fd, "POST_BEGIN\n") < 0) {
        fclose(status);
        return 5;
    }

    char line[512];
    while (fgets(line, sizeof(line), status) != NULL) {
        if (wanted_status_line(line) && dprintf(fd, "%s", line) < 0) {
            fclose(status);
            return 6;
        }
    }

    if (fclose(status) != 0 || dprintf(fd, "POST_END\n") < 0) {
        return 7;
    }
    return 0;
}
