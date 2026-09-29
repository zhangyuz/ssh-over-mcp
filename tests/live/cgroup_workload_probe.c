#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_GROUPS 256
#define MAX_SOCKET_INODES 256
#define MAX_DESCENDANTS 16
#define MAX_FORK_ATTEMPTS 64
#define MAX_HOLD_MS 30000ULL
#define MAX_CPU_MS 10000ULL
#define MAX_MEMORY_BYTES (128ULL * 1024ULL * 1024ULL)

static int usage(const char *program) {
    fprintf(stderr,
            "usage: %s state | escape-check | descendants COUNT HOLD_MS | "
            "cpu DURATION_MS | memory BYTES HOLD_MS | fork ATTEMPTS HOLD_MS\n",
            program);
    return 64;
}

static bool parse_u64(const char *raw, uint64_t minimum, uint64_t maximum,
                      uint64_t *out) {
    char *end = NULL;
    unsigned long long value;

    if (raw == NULL || raw[0] == '\0') {
        return false;
    }
    for (const char *cursor = raw; *cursor != '\0'; cursor++) {
        if (*cursor < '0' || *cursor > '9') {
            return false;
        }
    }
    errno = 0;
    value = strtoull(raw, &end, 10);
    if (errno != 0 || end == raw || *end != '\0') {
        return false;
    }
    if ((uint64_t)value < minimum || (uint64_t)value > maximum) {
        return false;
    }
    *out = (uint64_t)value;
    return true;
}

static int sleep_ms(uint64_t milliseconds) {
    struct timespec requested = {
        .tv_sec = (time_t)(milliseconds / 1000ULL),
        .tv_nsec = (long)((milliseconds % 1000ULL) * 1000000ULL),
    };

    while (nanosleep(&requested, &requested) != 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    return 0;
}

static void print_json_string(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    putchar('"');
    while (*cursor != '\0') {
        unsigned char ch = *cursor++;
        switch (ch) {
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '\b':
            fputs("\\b", stdout);
            break;
        case '\f':
            fputs("\\f", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        default:
            if (ch < 0x20U) {
                printf("\\u%04x", (unsigned int)ch);
            } else {
                putchar((int)ch);
            }
        }
    }
    putchar('"');
}

static bool read_status_value(const char *key, char *output, size_t output_size) {
    FILE *stream = fopen("/proc/self/status", "r");
    char line[512];
    size_t key_length = strlen(key);

    if (stream == NULL) {
        return false;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        char *value;
        size_t length;
        if (strncmp(line, key, key_length) != 0 || line[key_length] != ':') {
            continue;
        }
        value = line + key_length + 1;
        while (*value == ' ' || *value == '\t') {
            value++;
        }
        length = strcspn(value, "\r\n");
        if (length + 1 > output_size) {
            fclose(stream);
            return false;
        }
        memcpy(output, value, length);
        output[length] = '\0';
        fclose(stream);
        return true;
    }
    fclose(stream);
    return false;
}

static bool read_unified_cgroup(char *output, size_t output_size) {
    FILE *stream = fopen("/proc/self/cgroup", "r");
    char line[PATH_MAX + 32];

    if (stream == NULL) {
        return false;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        char *value;
        size_t length;
        if (strncmp(line, "0::", 3) != 0) {
            continue;
        }
        value = line + 3;
        length = strcspn(value, "\r\n");
        if (length + 1 > output_size) {
            fclose(stream);
            return false;
        }
        memcpy(output, value, length);
        output[length] = '\0';
        fclose(stream);
        return true;
    }
    fclose(stream);
    return false;
}

extern char **environ;
static int process_argc = 0;

static size_t environment_count(void) {
    size_t count = 0;
    while (environ[count] != NULL) {
        count++;
    }
    return count;
}

static int compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

static bool read_socket_inodes(uint64_t *output, size_t *count) {
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    size_t used = 0;

    if (directory == NULL) {
        return false;
    }
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long raw_fd;
        struct stat info;

        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') {
            continue;
        }
        errno = 0;
        raw_fd = strtol(entry->d_name, &end, 10);
        if (errno != 0 || end == entry->d_name || *end != '\0' ||
            raw_fd < 0 || raw_fd > INT_MAX) {
            closedir(directory);
            return false;
        }
        if ((int)raw_fd == dirfd(directory)) {
            continue;
        }
        if (fstat((int)raw_fd, &info) != 0) {
            if (errno == EBADF || errno == ENOENT) {
                continue;
            }
            closedir(directory);
            return false;
        }
        if (!S_ISSOCK(info.st_mode)) {
            continue;
        }
        if (used >= MAX_SOCKET_INODES) {
            closedir(directory);
            return false;
        }
        output[used++] = (uint64_t)info.st_ino;
    }
    closedir(directory);
    qsort(output, used, sizeof(output[0]), compare_u64);
    *count = used;
    return true;
}

static int compare_gid(const void *left, const void *right) {
    gid_t a = *(const gid_t *)left;
    gid_t b = *(const gid_t *)right;
    return (a > b) - (a < b);
}

static int emit_state(void) {
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    gid_t groups[MAX_GROUPS];
    int group_count;
    char cgroup[PATH_MAX];
    char cap_inh[64], cap_prm[64], cap_eff[64], cap_amb[64], no_new_privs[64];
    uint64_t socket_inodes[MAX_SOCKET_INODES];
    size_t socket_inode_count = 0;

    if (getresuid(&ruid, &euid, &suid) != 0 || getresgid(&rgid, &egid, &sgid) != 0) {
        perror("getresuid/getresgid");
        return 70;
    }
    group_count = getgroups(MAX_GROUPS, groups);
    if (group_count < 0) {
        perror("getgroups");
        return 70;
    }
    qsort(groups, (size_t)group_count, sizeof(groups[0]), compare_gid);
    if (!read_unified_cgroup(cgroup, sizeof(cgroup)) ||
        !read_status_value("CapInh", cap_inh, sizeof(cap_inh)) ||
        !read_status_value("CapPrm", cap_prm, sizeof(cap_prm)) ||
        !read_status_value("CapEff", cap_eff, sizeof(cap_eff)) ||
        !read_status_value("CapAmb", cap_amb, sizeof(cap_amb)) ||
        !read_status_value("NoNewPrivs", no_new_privs, sizeof(no_new_privs))) {
        fprintf(stderr, "cannot read process state\n");
        return 70;
    }
    if (!read_socket_inodes(socket_inodes, &socket_inode_count)) {
        fprintf(stderr, "cannot inspect process file descriptors\n");
        return 70;
    }

    printf("{\"event\":\"state\",\"pid\":%ld,\"argc\":%d,\"env_count\":%zu,\"ruid\":%u,\"euid\":%u,\"suid\":%u,"
           "\"rgid\":%u,\"egid\":%u,\"sgid\":%u,\"groups\":[",
           (long)getpid(), process_argc, environment_count(),
           (unsigned int)ruid, (unsigned int)euid, (unsigned int)suid,
           (unsigned int)rgid, (unsigned int)egid, (unsigned int)sgid);
    for (int index = 0; index < group_count; index++) {
        if (index != 0) {
            putchar(',');
        }
        printf("%u", (unsigned int)groups[index]);
    }
    fputs("],\"socket_inodes\":[", stdout);
    for (size_t index = 0; index < socket_inode_count; index++) {
        if (index != 0) {
            putchar(',');
        }
        printf("%" PRIu64, socket_inodes[index]);
    }
    fputs("],\"cap_inh\":", stdout);
    print_json_string(cap_inh);
    fputs(",\"cap_prm\":", stdout);
    print_json_string(cap_prm);
    fputs(",\"cap_eff\":", stdout);
    print_json_string(cap_eff);
    fputs(",\"cap_amb\":", stdout);
    print_json_string(cap_amb);
    fputs(",\"no_new_privs\":", stdout);
    print_json_string(no_new_privs);
    fputs(",\"cgroup\":", stdout);
    print_json_string(cgroup);
    fputs("}\n", stdout);
    return 0;
}

static bool path_is_within(const char *root, const char *path) {
    size_t root_length = strlen(root);
    if (strcmp(root, path) == 0) {
        return true;
    }
    if (strncmp(root, path, root_length) != 0) {
        return false;
    }
    return root_length > 0 && root[root_length - 1] == '/'
               ? true
               : path[root_length] == '/';
}

static bool validate_membership_target(const char *raw_path, const char *root,
                                       bool allow_root, char *output,
                                       size_t output_size) {
    char resolved[PATH_MAX];
    const char *base;

    if (raw_path == NULL || raw_path[0] != '/') {
        return false;
    }
    if (realpath(raw_path, resolved) == NULL) {
        return false;
    }
    if (!path_is_within(root, resolved)) {
        return false;
    }
    base = strrchr(resolved, '/');
    if (base == NULL || strcmp(base + 1, "cgroup.procs") != 0) {
        return false;
    }
    if (!allow_root) {
        char root_procs[PATH_MAX];
        int written = snprintf(root_procs, sizeof(root_procs), "%s/cgroup.procs", root);
        if (written < 0 || (size_t)written >= sizeof(root_procs)) {
            return false;
        }
        if (strcmp(root_procs, resolved) == 0) {
            return false;
        }
    }
    if (strlen(resolved) + 1 > output_size) {
        return false;
    }
    strcpy(output, resolved);
    return true;
}

static int attempt_migration(const char *label, const char *path) {
    char data[64];
    int fd;
    int length = snprintf(data, sizeof(data), "%ld\n", (long)getpid());
    if (length <= 0 || (size_t)length >= sizeof(data)) {
        return 70;
    }

    fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        int error_number = errno;
        printf("{\"event\":\"migration\",\"target\":");
        print_json_string(label);
        printf(",\"outcome\":\"%s\",\"errno\":%d}\n",
               (error_number == EACCES || error_number == EPERM) ? "denied" : "error",
               error_number);
        return (error_number == EACCES || error_number == EPERM) ? 0 : 70;
    }

    ssize_t written = write(fd, data, (size_t)length);
    if (written == (ssize_t)length) {
        close(fd);
        printf("{\"event\":\"migration\",\"target\":");
        print_json_string(label);
        fputs(",\"outcome\":\"succeeded\",\"errno\":0}\n", stdout);
        return 77;
    }

    int error_number = (written < 0) ? errno : EIO;
    close(fd);
    printf("{\"event\":\"migration\",\"target\":");
    print_json_string(label);
    printf(",\"outcome\":\"%s\",\"errno\":%d}\n",
           (error_number == EACCES || error_number == EPERM) ? "denied" : "error",
           error_number);
    return (error_number == EACCES || error_number == EPERM) ? 0 : 70;
}

static int action_escape_check(void) {
    const char *raw_root = getenv("SSH_OVER_MCP_LIVE_CGROUP_ROOT");
    const char *raw_sibling = getenv("SSH_OVER_MCP_LIVE_CGROUP_SIBLING_PROCS");
    char root[PATH_MAX], root_procs[PATH_MAX], sibling_procs[PATH_MAX];
    char raw_root_procs[PATH_MAX];
    int result;

    if (raw_root == NULL || raw_root[0] != '/' || realpath(raw_root, root) == NULL) {
        fprintf(stderr, "invalid SSH_OVER_MCP_LIVE_CGROUP_ROOT\n");
        return 64;
    }
    int written = snprintf(raw_root_procs, sizeof(raw_root_procs), "%s/cgroup.procs", root);
    if (written < 0 || (size_t)written >= sizeof(raw_root_procs) ||
        !validate_membership_target(raw_root_procs, root, true, root_procs,
                                    sizeof(root_procs)) ||
        !validate_membership_target(raw_sibling, root, false, sibling_procs,
                                    sizeof(sibling_procs))) {
        fprintf(stderr, "invalid live cgroup migration target\n");
        return 64;
    }

    result = emit_state();
    if (result != 0) {
        return result;
    }
    result = attempt_migration("root", root_procs);
    if (result != 0) {
        return result;
    }
    return attempt_migration("sibling", sibling_procs);
}

static void close_child_stdio(void) {
    (void)close(STDIN_FILENO);
    (void)close(STDOUT_FILENO);
    (void)close(STDERR_FILENO);
}

static int action_descendants(uint64_t count, uint64_t hold_ms) {
    pid_t children[MAX_DESCENDANTS];
    size_t created = 0;
    int state_result = emit_state();
    if (state_result != 0) {
        return state_result;
    }

    for (uint64_t index = 0; index < count; index++) {
        pid_t pid = fork();
        if (pid < 0) {
            int error_number = errno;
            for (size_t child_index = 0; child_index < created; child_index++) {
                (void)kill(children[child_index], SIGKILL);
                (void)waitpid(children[child_index], NULL, 0);
            }
            fprintf(stderr, "descendant fork failed: %s\n", strerror(error_number));
            return 70;
        }
        if (pid == 0) {
            close_child_stdio();
            (void)sleep_ms(hold_ms);
            _exit(0);
        }
        children[created++] = pid;
        printf("{\"event\":\"descendant\",\"pid\":%ld}\n", (long)pid);
    }
    printf("{\"event\":\"descendants_ready\",\"count\":%zu}\n", created);
    return 0;
}

static int action_cpu(uint64_t duration_ms) {
    struct timespec start, now;
    volatile uint64_t accumulator = 0;
    uint64_t iterations = 0;
    int state_result = emit_state();
    if (state_result != 0) {
        return state_result;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("clock_gettime");
        return 70;
    }
    for (;;) {
        for (uint64_t index = 0; index < 100000ULL; index++) {
            accumulator = (accumulator * 1664525ULL) + index + 1013904223ULL;
        }
        iterations += 100000ULL;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            perror("clock_gettime");
            return 70;
        }
        uint64_t elapsed_ms = (uint64_t)(now.tv_sec - start.tv_sec) * 1000ULL;
        long nanoseconds = now.tv_nsec - start.tv_nsec;
        if (nanoseconds < 0) {
            elapsed_ms -= 1000ULL;
            nanoseconds += 1000000000L;
        }
        elapsed_ms += (uint64_t)nanoseconds / 1000000ULL;
        if (elapsed_ms >= duration_ms) {
            break;
        }
    }
    printf("{\"event\":\"cpu_done\",\"iterations\":%" PRIu64
           ",\"checksum\":%" PRIu64 "}\n",
           iterations, (uint64_t)accumulator);
    return 0;
}

static int action_memory(uint64_t bytes, uint64_t hold_ms) {
    volatile unsigned char *memory;
    long page_size = sysconf(_SC_PAGESIZE);
    int state_result = emit_state();
    if (state_result != 0) {
        return state_result;
    }
    if (page_size <= 0) {
        fprintf(stderr, "invalid page size\n");
        return 70;
    }
    memory = malloc((size_t)bytes);
    if (memory == NULL) {
        printf("{\"event\":\"memory_alloc\",\"outcome\":\"failed\",\"bytes\":%" PRIu64
               "}\n",
               bytes);
        return 71;
    }
    for (uint64_t offset = 0; offset < bytes; offset += (uint64_t)page_size) {
        memory[offset] = (unsigned char)(offset & 0xffU);
    }
    memory[bytes - 1] = 0x5aU;
    printf("{\"event\":\"memory_ready\",\"bytes\":%" PRIu64 "}\n", bytes);
    if (sleep_ms(hold_ms) != 0) {
        perror("nanosleep");
        free((void *)memory);
        return 70;
    }
    free((void *)memory);
    fputs("{\"event\":\"memory_done\"}\n", stdout);
    return 0;
}

static int action_fork_limit(uint64_t attempts, uint64_t hold_ms) {
    pid_t children[MAX_FORK_ATTEMPTS];
    size_t created = 0;
    int failure_errno = 0;
    int state_result = emit_state();
    if (state_result != 0) {
        return state_result;
    }

    for (uint64_t index = 0; index < attempts; index++) {
        pid_t pid = fork();
        if (pid < 0) {
            failure_errno = errno;
            break;
        }
        if (pid == 0) {
            close_child_stdio();
            (void)sleep_ms(hold_ms);
            _exit(0);
        }
        children[created++] = pid;
    }

    printf("{\"event\":\"fork_summary\",\"attempts\":%" PRIu64
           ",\"created\":%zu,\"errno\":%d}\n",
           attempts, created, failure_errno);
    for (size_t index = 0; index < created; index++) {
        while (waitpid(children[index], NULL, 0) < 0 && errno == EINTR) {
        }
    }
    fputs("{\"event\":\"fork_done\"}\n", stdout);
    return 0;
}

int main(int argc, char **argv) {
    uint64_t first, second;
    process_argc = argc;
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        return usage(argv[0]);
    }
    if (strcmp(argv[1], "state") == 0) {
        if (argc != 2) {
            return usage(argv[0]);
        }
        return emit_state();
    }
    if (strcmp(argv[1], "escape-check") == 0) {
        if (argc != 2) {
            return usage(argv[0]);
        }
        return action_escape_check();
    }
    if (strcmp(argv[1], "descendants") == 0) {
        if (argc != 4 ||
            !parse_u64(argv[2], 1, MAX_DESCENDANTS, &first) ||
            !parse_u64(argv[3], 100, MAX_HOLD_MS, &second)) {
            return usage(argv[0]);
        }
        return action_descendants(first, second);
    }
    if (strcmp(argv[1], "cpu") == 0) {
        if (argc != 3 || !parse_u64(argv[2], 10, MAX_CPU_MS, &first)) {
            return usage(argv[0]);
        }
        return action_cpu(first);
    }
    if (strcmp(argv[1], "memory") == 0) {
        if (argc != 4 ||
            !parse_u64(argv[2], 4096, MAX_MEMORY_BYTES, &first) ||
            !parse_u64(argv[3], 0, MAX_HOLD_MS, &second)) {
            return usage(argv[0]);
        }
        return action_memory(first, second);
    }
    if (strcmp(argv[1], "fork") == 0) {
        if (argc != 4 ||
            !parse_u64(argv[2], 1, MAX_FORK_ATTEMPTS, &first) ||
            !parse_u64(argv[3], 100, MAX_HOLD_MS, &second)) {
            return usage(argv[0]);
        }
        return action_fork_limit(first, second);
    }
    return usage(argv[0]);
}
