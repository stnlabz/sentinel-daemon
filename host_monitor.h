/* Host-wide, metadata-only polling. No file contents or command-line secrets. */
#include <stdint.h>

#define HOST_BUCKETS 65536
typedef struct host_entry {
    char *path;
    struct stat stamp;
    char *identity;
    unsigned long generation;
    struct host_entry *next;
} host_entry;

static host_entry *host_files[HOST_BUCKETS], *host_processes[HOST_BUCKETS];
static unsigned long host_generation;
static int host_baseline;
static unsigned long host_count, host_errors, host_process_count;

static unsigned host_hash(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h % HOST_BUCKETS;
}

/* Keep untrusted filenames from injecting extra log records. */
static void host_event(const char *event, const char *path)
{
    char escaped[PATH_MAX * 4 + 1];
    size_t n = 0;
    const unsigned char *p = (const unsigned char *)path;
    while (*p && n + 4 < sizeof(escaped)) {
        if (*p < 32 || *p == 127 || *p == '\\') {
            snprintf(escaped + n, sizeof(escaped) - n, "\\x%02x", *p);
            n += 4;
        } else escaped[n++] = (char)*p;
        p++;
    }
    escaped[n] = '\0';
    slog("INFO", event, escaped);
}

static void host_error(const char *path)
{
    if (host_errors++ < 10) host_event("HOST_COVERAGE_ERROR", path);
}

static int host_stamp_changed(const struct stat *a, const struct stat *b)
{
    return a->st_dev != b->st_dev || a->st_ino != b->st_ino ||
        a->st_mode != b->st_mode || a->st_uid != b->st_uid ||
        a->st_gid != b->st_gid || a->st_size != b->st_size ||
        a->st_mtim.tv_sec != b->st_mtim.tv_sec ||
        a->st_mtim.tv_nsec != b->st_mtim.tv_nsec ||
        a->st_ctim.tv_sec != b->st_ctim.tv_sec ||
        a->st_ctim.tv_nsec != b->st_ctim.tv_nsec;
}

static void host_record(host_entry **table, const char *path,
                        const struct stat *stamp, const char *identity)
{
    unsigned h = host_hash(path);
    host_entry *e;
    int process = identity != NULL;
    for (e = table[h]; e; e = e->next)
        if (!strcmp(e->path, path)) break;
    if (!e) {
        e = calloc(1, sizeof(*e));
        if (!e) { host_error(path); return; }
        e->path = strdup(path);
        e->identity = identity ? strdup(identity) : NULL;
        if (!e->path || (identity && !e->identity)) {
            free(e->path); free(e->identity); free(e); host_error(path); return;
        }
        e->next = table[h]; table[h] = e;
        if (host_baseline) {
            host_event(process ? "HOST_PROCESS_START" : "HOST_FILE_CREATED", path);
            if (process) host_event("HOST_PROCESS_IDENTITY", identity);
        }
    } else if (process && strcmp(e->identity, identity)) {
        char *copy = strdup(identity);
        if (!copy) { host_error(path); return; }
        if (host_baseline) {
            host_event("HOST_PROCESS_CHANGED", path);
            host_event("HOST_PROCESS_IDENTITY", identity);
        }
        free(e->identity); e->identity = copy;
    } else if (!process && host_stamp_changed(&e->stamp, stamp) && host_baseline) {
        host_event("HOST_FILE_CHANGED", path);
    }
    if (stamp) e->stamp = *stamp;
    e->generation = host_generation;
}

static void host_finish(host_entry **table, int complete)
{
    unsigned h;
    if (!complete) return; /* Inaccessible paths are not evidence of deletion. */
    for (h = 0; h < HOST_BUCKETS; h++) {
        host_entry **link = &table[h];
        while (*link) {
            host_entry *e = *link;
            if (e->generation != host_generation) {
                if (host_baseline)
                    host_event(table == host_files ? "HOST_FILE_REMOVED" : "HOST_PROCESS_EXIT", e->path);
                *link = e->next;
                free(e->path); free(e->identity); free(e);
            } else link = &e->next;
        }
    }
}

static int host_under(const char *path, const char *root)
{
    size_t n = strlen(root);
    return n && !strncmp(path, root, n) && (!path[n] || path[n] == '/');
}

static int host_excluded(const char *path)
{
    char parent[MAX_PATH_LEN];
    /* Kernel pseudo-files are monitored via process snapshots, not walked.
       /dev/shm is scanned separately; other device nodes are not regular files. */
    if (host_under(path, "/proc") || host_under(path, "/sys") ||
        (host_under(path, "/dev") && !host_under(path, "/dev/shm"))) return 1;
    if (host_under(path, Q_DIR)) return 1;
    if (parent_dir_from_file(LOG_FILE, parent, sizeof(parent)) == 0 &&
        host_under(path, parent)) return 1;
    if (parent_dir_from_file(STATE_FILE, parent, sizeof(parent)) == 0 &&
        host_under(path, parent)) return 1;
    if (parent_dir_from_file(HEARTBEAT_FILE, parent, sizeof(parent)) == 0 &&
        host_under(path, parent)) return 1;
    return 0;
}

static void host_walk(const char *path, unsigned depth)
{
    struct stat st;
    DIR *dir;
    struct dirent *ent;
    if (!running || host_excluded(path)) return;
    if (lstat(path, &st)) {
        if (errno != ENOENT) host_error(path);
        return;
    }
    host_count++;
    host_record(host_files, path, &st, NULL);
    if (!S_ISDIR(st.st_mode)) return; /* Never follow symlinks or open devices. */
    if (depth >= 256) { host_error(path); return; }
    dir = opendir(path);
    if (!dir) { host_error(path); return; }
    while (running) {
        char child[PATH_MAX];
        errno = 0;
        ent = readdir(dir);
        if (!ent) { if (errno) host_error(path); break; }
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;
        if (snprintf(child, sizeof(child), "%s%s%s", path,
                     !strcmp(path, "/") ? "" : "/", ent->d_name) >= (int)sizeof(child)) {
            host_error(path); continue;
        }
        host_walk(child, depth + 1);
    }
    closedir(dir);
}

static void host_scan_processes(void)
{
    DIR *dir = opendir("/proc");
    struct dirent *ent;
    unsigned long before = host_errors;
    if (!dir) { host_error("/proc"); return; }
    while (running) {
        char path[PATH_MAX], buf[8192], exe[PATH_MAX], identity[PATH_MAX + 512];
        char *tail, *token, *save;
        unsigned long long start = 0;
        FILE *fp;
        ssize_t n;
        int field;
        errno = 0;
        ent = readdir(dir);
        if (!ent) { if (errno) host_error("/proc"); break; }
        if (!ent->d_name[0] || strspn(ent->d_name, "0123456789") != strlen(ent->d_name)) continue;
        snprintf(path, sizeof(path), "/proc/%s/stat", ent->d_name);
        fp = fopen(path, "r");
        if (!fp) { if (errno != ENOENT && errno != ESRCH) host_error(path); continue; }
        if (!fgets(buf, sizeof(buf), fp)) { fclose(fp); continue; }
        fclose(fp);
        tail = strrchr(buf, ')'); /* comm may contain spaces and parentheses. */
        if (!tail) { host_error(path); continue; }
        token = strtok_r(tail + 1, " ", &save);
        for (field = 3; token && field < 22; field++) token = strtok_r(NULL, " ", &save);
        if (!token || sscanf(token, "%llu", &start) != 1) { host_error(path); continue; }
        snprintf(path, sizeof(path), "/proc/%s/exe", ent->d_name);
        n = readlink(path, exe, sizeof(exe) - 1);
        if (n < 0) {
            if (errno != ENOENT && errno != ESRCH) host_error(path);
            safe_copy(exe, "[kernel-thread-or-exiting]", sizeof(exe));
        } else if (n >= (ssize_t)sizeof(exe) - 1) { host_error(path); continue; }
        else exe[n] = '\0';
        snprintf(identity, sizeof(identity), "pid=%s start=%llu exe=%s", ent->d_name, start, exe);
        host_record(host_processes, ent->d_name, NULL, identity);
        host_process_count++;
    }
    closedir(dir);
    host_finish(host_processes, running && before == host_errors);
}

static void host_scan(void)
{
    char summary[256];
    time_t started = time(NULL);
    host_generation++;
    host_count = host_errors = host_process_count = 0;
    host_walk("/", 0);
    host_walk("/dev/shm", 0);
    host_finish(host_files, running && !host_errors);
    host_scan_processes();
    snprintf(summary, sizeof(summary),
             "entries=%lu processes=%lu coverage_errors=%lu duration_seconds=%ld",
             host_count, host_process_count, host_errors, (long)(time(NULL) - started));
    slog("INFO", host_baseline ? "HOST_SCAN_COMPLETE" : "HOST_BASELINE_COMPLETE", summary);
    host_baseline = 1;
}

