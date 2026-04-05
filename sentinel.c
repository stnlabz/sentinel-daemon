/**
 * Sentinel Daemon
 *
 * v0.5.7 Execution Awareness + Heartbeat
 *
 * Build:
 *   gcc -Wall -Wextra -O2 -o sentinel sentinel.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>

#define CONFIG_FILE "/etc/sentinel.conf"

#define DEFAULT_LOG_FILE        "/var/log/sentinel/sentinel.log"
#define DEFAULT_Q_DIR           "/var/log/sentinel/quarantine"
#define DEFAULT_STATE_FILE      "/var/lib/sentinel/state.db"
#define DEFAULT_HEARTBEAT_FILE  "/var/lib/sentinel/heartbeat"

#define DEFAULT_LOOP         10
#define DEFAULT_MAX_ACTIONS  50
#define DEFAULT_KILL_DETECT  0

#define MAX_PATH_LEN      1024
#define MAX_WATCH_DIRS    16
#define MAX_TRACKED_FILES 2048
#define MAX_NAME_LEN      255
#define MAX_PIDS_TRACKED  4096

static volatile sig_atomic_t running = 1;

/* =========================
   WATCH RULE
========================= */
typedef struct {
    char path[MAX_PATH_LEN];
    char allow[256];
    char block[256];
    char trust_ext[256];
} watch_rule;

static watch_rule WATCH[MAX_WATCH_DIRS];
static int WATCH_COUNT = 0;

/* =========================
   CONFIG
========================= */
static char Q_DIR[MAX_PATH_LEN]           = DEFAULT_Q_DIR;
static char LOG_FILE[MAX_PATH_LEN]        = DEFAULT_LOG_FILE;
static char STATE_FILE[MAX_PATH_LEN]      = DEFAULT_STATE_FILE;
static char HEARTBEAT_FILE[MAX_PATH_LEN]  = DEFAULT_HEARTBEAT_FILE;

static int LOOP_INTERVAL = DEFAULT_LOOP;
static int MAX_ACTIONS   = DEFAULT_MAX_ACTIONS;
static int KILL_ON_DETECT = DEFAULT_KILL_DETECT;

/* =========================
   RUNTIME
========================= */
static int actions_this_cycle = 0;
static int state_rebuilt = 0;

/* =========================
   FILE TRACKING
========================= */
typedef struct {
    char name[MAX_NAME_LEN + 1];
    time_t mtime;
} file_entry;

static file_entry tracked[MAX_TRACKED_FILES];
static int tracked_count = 0;

/* =========================
   EXEC TRACKING
========================= */
typedef struct {
    pid_t pid;
    time_t seen_at;
} pid_entry;

static pid_entry seen_pids[MAX_PIDS_TRACKED];
static int seen_pid_count = 0;

/* ========================= */
static void handle_signal(int sig)
{
    (void)sig;
    running = 0;
}

/* ========================= */
static void slog(const char *level, const char *event, const char *extra)
{
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) {
        return;
    }

    time_t now = time(NULL);
    struct tm tm_now;
    char ts[32];

    if (!gmtime_r(&now, &tm_now)) {
        fclose(fp);
        return;
    }

    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_now);

    fprintf(
        fp,
        "[%s] %s: %s %s\n",
        ts,
        level ? level : "INFO",
        event ? event : "EVENT",
        extra ? extra : ""
    );

    fclose(fp);
}

/* ========================= */
static void safe_copy(char *dest, const char *src, size_t size)
{
    size_t len;

    if (!dest || !src || size == 0)
        return;

    len = strlen(src);
    if (len >= size)
        len = size - 1;

    memcpy(dest, src, len);
    dest[len] = '\0';
}

/* ========================= */
static void trim(char *str)
{
    char *start;
    char *end;

    if (!str || *str == '\0')
        return;

    start = str;
    while (*start == ' ' || *start == '\t')
        start++;

    if (start != str)
        memmove(str, start, strlen(start) + 1);

    if (*str == '\0')
        return;

    end = str + strlen(str) - 1;
    while (end >= str && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
        *end = '\0';
        if (end == str)
            break;
        end--;
    }
}

/* ========================= */
static int build_path(char *out, size_t size, const char *a, const char *b)
{
    int n;

    if (!out || !a || !b || size == 0)
        return -1;

    n = snprintf(out, size, "%s/%s", a, b);
    if (n < 0 || (size_t)n >= size)
        return -1;

    return 0;
}

/* ========================= */
static const char *base_name(const char *path)
{
    const char *slash;

    if (!path)
        return "";

    slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* ========================= */
static int parent_dir_from_file(const char *file_path, char *out, size_t out_size)
{
    const char *slash;
    size_t len;

    if (!file_path || !out || out_size == 0)
        return -1;

    slash = strrchr(file_path, '/');
    if (!slash)
        return -1;

    len = (size_t)(slash - file_path);
    if (len == 0 || len >= out_size)
        return -1;

    memcpy(out, file_path, len);
    out[len] = '\0';

    return 0;
}

/* ========================= */
static int ensure_dir(const char *path, mode_t mode)
{
    struct stat st;

    if (!path || *path == '\0')
        return -1;

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode))
            return 0;
        return -1;
    }

    if (mkdir(path, mode) == 0)
        return 0;

    if (errno == EEXIST)
        return 0;

    return -1;
}

/* ========================= */
static int ensure_runtime_paths(void)
{
    char log_dir[MAX_PATH_LEN];
    char state_dir[MAX_PATH_LEN];
    char heartbeat_dir[MAX_PATH_LEN];

    if (parent_dir_from_file(LOG_FILE, log_dir, sizeof(log_dir)) != 0)
        return -1;

    if (parent_dir_from_file(STATE_FILE, state_dir, sizeof(state_dir)) != 0)
        return -1;

    if (parent_dir_from_file(HEARTBEAT_FILE, heartbeat_dir, sizeof(heartbeat_dir)) != 0)
        return -1;

    if (ensure_dir(log_dir, 0755) != 0)
        return -1;

    if (ensure_dir(Q_DIR, 0755) != 0)
        return -1;

    if (ensure_dir(state_dir, 0755) != 0)
        return -1;

    if (ensure_dir(heartbeat_dir, 0755) != 0)
        return -1;

    return 0;
}

/* ========================= */
static int write_heartbeat(void)
{
    char tmp[MAX_PATH_LEN];
    FILE *fp;
    time_t now = time(NULL);

    if (snprintf(tmp, sizeof(tmp), "%s.tmp", HEARTBEAT_FILE) >= (int)sizeof(tmp))
        return -1;

    fp = fopen(tmp, "w");
    if (!fp)
        return -1;

    fprintf(fp, "%ld\n", (long)now);

    if (fflush(fp) != 0) {
        fclose(fp);
        unlink(tmp);
        return -1;
    }

    if (fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(tmp);
        return -1;
    }

    fclose(fp);

    if (rename(tmp, HEARTBEAT_FILE) != 0) {
        unlink(tmp);
        return -1;
    }

    return 0;
}

/* ========================= */
static void add_watch_dir(const char *path)
{
    if (!path || *path == '\0')
        return;

    if (WATCH_COUNT >= MAX_WATCH_DIRS)
        return;

    safe_copy(WATCH[WATCH_COUNT].path, path, sizeof(WATCH[WATCH_COUNT].path));
    WATCH[WATCH_COUNT].allow[0] = '\0';
    WATCH[WATCH_COUNT].block[0] = '\0';
    WATCH[WATCH_COUNT].trust_ext[0] = '\0';

    WATCH_COUNT++;
}

/* ========================= */
static void load_config(void)
{
    FILE *fp = fopen(CONFIG_FILE, "r");
    char line[512];

    if (!fp) {
        add_watch_dir("/tmp");
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *eq;
        char *key;
        char *val;

        trim(line);

        if (line[0] == '#' || line[0] == '\0')
            continue;

        eq = strchr(line, '=');
        if (!eq)
            continue;

        *eq = '\0';
        key = line;
        val = eq + 1;

        trim(key);
        trim(val);

        if (strcmp(key, "watch_dir") == 0) {
            add_watch_dir(val);
        } else if (strcmp(key, "allow_ext") == 0 && WATCH_COUNT) {
            safe_copy(WATCH[WATCH_COUNT - 1].allow, val, sizeof(WATCH[WATCH_COUNT - 1].allow));
        } else if (strcmp(key, "block_ext") == 0 && WATCH_COUNT) {
            safe_copy(WATCH[WATCH_COUNT - 1].block, val, sizeof(WATCH[WATCH_COUNT - 1].block));
        } else if (strcmp(key, "trust_ext") == 0 && WATCH_COUNT) {
            safe_copy(WATCH[WATCH_COUNT - 1].trust_ext, val, sizeof(WATCH[WATCH_COUNT - 1].trust_ext));
        } else if (strcmp(key, "quarantine_dir") == 0) {
            safe_copy(Q_DIR, val, sizeof(Q_DIR));
        } else if (strcmp(key, "log_file") == 0) {
            safe_copy(LOG_FILE, val, sizeof(LOG_FILE));
        } else if (strcmp(key, "state_file") == 0) {
            safe_copy(STATE_FILE, val, sizeof(STATE_FILE));
        } else if (strcmp(key, "heartbeat_file") == 0) {
            safe_copy(HEARTBEAT_FILE, val, sizeof(HEARTBEAT_FILE));
        } else if (strcmp(key, "loop_interval") == 0) {
            LOOP_INTERVAL = atoi(val);
        } else if (strcmp(key, "max_actions_per_cycle") == 0) {
            MAX_ACTIONS = atoi(val);
        } else if (strcmp(key, "kill_on_detect") == 0) {
            KILL_ON_DETECT = atoi(val);
        }
    }

    fclose(fp);

    if (WATCH_COUNT == 0)
        add_watch_dir("/tmp");
}

/* =========================
   STRICT STATE LOAD
   RETURN 1 = GOOD
   RETURN 0 = BAD / MISSING
========================= */
static int load_state(void)
{
    FILE *fp = fopen(STATE_FILE, "r");
    char line[512];

    tracked_count = 0;

    if (!fp)
        return 0;

    while (fgets(line, sizeof(line), fp)) {
        char name[MAX_NAME_LEN + 1];
        long mt;

        if (tracked_count >= MAX_TRACKED_FILES) {
            fclose(fp);
            tracked_count = 0;
            return 0;
        }

        if (sscanf(line, "%255[^|]|%ld", name, &mt) != 2) {
            fclose(fp);
            tracked_count = 0;
            return 0;
        }

        if (name[0] == '\0') {
            fclose(fp);
            tracked_count = 0;
            return 0;
        }

        safe_copy(tracked[tracked_count].name, name, sizeof(tracked[tracked_count].name));
        tracked[tracked_count].mtime = (time_t)mt;
        tracked_count++;
    }

    fclose(fp);
    return 1;
}

/* =========================
   ATOMIC STATE REBUILD
========================= */
static int rebuild_state(void)
{
    char tmp[MAX_PATH_LEN];
    FILE *fp;

    if (snprintf(tmp, sizeof(tmp), "%s.tmp", STATE_FILE) >= (int)sizeof(tmp))
        return 0;

    fp = fopen(tmp, "w");
    if (!fp)
        return 0;

    if (fflush(fp) != 0) {
        fclose(fp);
        unlink(tmp);
        return 0;
    }

    if (fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(tmp);
        return 0;
    }

    fclose(fp);

    if (rename(tmp, STATE_FILE) != 0) {
        unlink(tmp);
        return 0;
    }

    tracked_count = 0;
    state_rebuilt = 1;

    return 1;
}

/* ========================= */
static void save_state(void)
{
    FILE *fp = fopen(STATE_FILE, "w");
    int i;

    if (!fp)
        return;

    for (i = 0; i < tracked_count; i++) {
        fprintf(fp, "%s|%ld\n", tracked[i].name, (long)tracked[i].mtime);
    }

    fclose(fp);
}

/* ========================= */
static int match_ext(const char *name, const char *list)
{
    const char *ext;
    char buf[256];
    char *tok;

    if (!name || !list || !*list)
        return 0;

    ext = strrchr(name, '.');
    if (!ext)
        return 0;

    safe_copy(buf, list, sizeof(buf));

    tok = strtok(buf, ",");
    while (tok) {
        trim(tok);
        if (strcmp(ext, tok) == 0)
            return 1;
        tok = strtok(NULL, ",");
    }

    return 0;
}

/* ========================= */
static int is_trusted(const char *name, const watch_rule *rule)
{
    if (!name || !rule)
        return 0;

    if (rule->trust_ext[0] && match_ext(name, rule->trust_ext))
        return 1;

    return 0;
}

/* ========================= */
static int is_allowed_file(const char *name, const watch_rule *rule)
{
    if (!name || !rule)
        return 0;

    if (rule->allow[0] && !match_ext(name, rule->allow))
        return 0;

    if (rule->block[0] && match_ext(name, rule->block))
        return 0;

    return 1;
}

/* ========================= */
static int should_process(const char *name, time_t mtime)
{
    int i;

    if (!name)
        return 0;

    for (i = 0; i < tracked_count; i++) {
        if (strcmp(tracked[i].name, name) == 0) {
            if (tracked[i].mtime == mtime)
                return 0;

            tracked[i].mtime = mtime;
            return 1;
        }
    }

    if (tracked_count < MAX_TRACKED_FILES) {
        safe_copy(tracked[tracked_count].name, name, sizeof(tracked[tracked_count].name));
        tracked[tracked_count].mtime = mtime;
        tracked_count++;
    }

    return 1;
}

/* ========================= */
static int was_pid_seen(pid_t pid)
{
    int i;

    for (i = 0; i < seen_pid_count; i++) {
        if (seen_pids[i].pid == pid)
            return 1;
    }

    if (seen_pid_count < MAX_PIDS_TRACKED) {
        seen_pids[seen_pid_count].pid = pid;
        seen_pids[seen_pid_count].seen_at = time(NULL);
        seen_pid_count++;
    }

    return 0;
}

/* ========================= */
static int path_belongs_to_rule(const char *path, const watch_rule *rule)
{
    size_t len;

    if (!path || !rule || !rule->path[0])
        return 0;

    len = strlen(rule->path);

    if (strncmp(path, rule->path, len) != 0)
        return 0;

    if (path[len] == '\0' || path[len] == '/')
        return 1;

    return 0;
}

/* ========================= */
static void quarantine_file(const char *full_path, const char *filename)
{
    char final[MAX_PATH_LEN];
    int counter = 0;

    if (!full_path || !filename)
        return;

    if (actions_this_cycle >= MAX_ACTIONS)
        return;

    while (counter < 100) {
        int n = snprintf(final, sizeof(final), "%s/%s.%d", Q_DIR, filename, counter);
        if (n < 0 || (size_t)n >= sizeof(final))
            return;

        if (access(final, F_OK) != 0)
            break;

        counter++;
    }

    if (rename(full_path, final) == 0) {
        actions_this_cycle++;
        slog("ACTION", "QUARANTINE_SUCCESS", final);
    } else {
        slog("ERROR", "QUARANTINE_FAILED", full_path);
    }
}

/* ========================= */
static void enforce_exec(pid_t pid, const char *exe_path, const char *event)
{
    char msg[MAX_PATH_LEN + 64];

    if (!exe_path || !event)
        return;

    snprintf(msg, sizeof(msg), "pid=%ld exe=%s", (long)pid, exe_path);
    slog("ALERT", event, msg);

    if (KILL_ON_DETECT) {
        if (kill(pid, SIGTERM) == 0) {
            slog("ACTION", "PROCESS_TERMINATED", msg);
        } else {
            slog("ERROR", "PROCESS_TERMINATE_FAILED", msg);
        }
    }
}

/* ========================= */
static void scan_directory(const watch_rule *rule)
{
    DIR *d;
    struct dirent *dir;

    if (!rule)
        return;

    d = opendir(rule->path);
    if (!d)
        return;

    while ((dir = readdir(d)) != NULL) {
        char full[MAX_PATH_LEN];
        struct stat st;

        if (actions_this_cycle >= MAX_ACTIONS)
            break;

        if (dir->d_name[0] == '.')
            continue;

        if (is_trusted(dir->d_name, rule))
            continue;

        if (build_path(full, sizeof(full), rule->path, dir->d_name) != 0)
            continue;

        if (stat(full, &st) != 0)
            continue;

        if (!S_ISREG(st.st_mode))
            continue;

        if (!should_process(dir->d_name, st.st_mtime))
            continue;

        if (!is_allowed_file(dir->d_name, rule)) {
            slog("ALERT", "RULE_VIOLATION", full);
            quarantine_file(full, dir->d_name);
            continue;
        }

        if (match_ext(dir->d_name, ".sh,.exe")) {
            slog("ALERT", "THREAT_DETECTED", full);
            quarantine_file(full, dir->d_name);
        }
    }

    closedir(d);
}

/* ========================= */
static void scan_processes(void)
{
    DIR *proc;
    struct dirent *ent;

    proc = opendir("/proc");
    if (!proc)
        return;

    while ((ent = readdir(proc)) != NULL) {
        pid_t pid;
        char proc_exe[MAX_PATH_LEN];
        char exe_path[MAX_PATH_LEN];
        ssize_t len;
        int i;

        if (!ent->d_name[0] || strspn(ent->d_name, "0123456789") != strlen(ent->d_name))
            continue;

        pid = (pid_t)atoi(ent->d_name);
        if (pid <= 0)
            continue;

        if (was_pid_seen(pid))
            continue;

        if (snprintf(proc_exe, sizeof(proc_exe), "/proc/%s/exe", ent->d_name) >= (int)sizeof(proc_exe))
            continue;

        len = readlink(proc_exe, exe_path, sizeof(exe_path) - 1);
        if (len <= 0)
            continue;

        exe_path[len] = '\0';

        for (i = 0; i < WATCH_COUNT; i++) {
            const char *exe_name;

            if (!path_belongs_to_rule(exe_path, &WATCH[i]))
                continue;

            exe_name = base_name(exe_path);

            if (is_trusted(exe_name, &WATCH[i]))
                continue;

            if (!is_allowed_file(exe_name, &WATCH[i])) {
                enforce_exec(pid, exe_path, "EXEC_VIOLATION");
                break;
            }

            if (match_ext(exe_name, ".sh,.exe")) {
                enforce_exec(pid, exe_path, "EXEC_THREAT");
                break;
            }
        }
    }

    closedir(proc);
}

/* ========================= */
int main(void)
{
    int i;

    load_config();

    if (ensure_runtime_paths() != 0) {
        return 1;
    }

    if (!load_state()) {
        if (!rebuild_state()) {
            return 1;
        }
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    slog("INFO", "DAEMON_START", "Sentinel v0.5.7");

    if (state_rebuilt) {
        slog("INFO", "STATE_REBUILT", STATE_FILE);
    }

    if (write_heartbeat() != 0) {
        slog("ERROR", "HEARTBEAT_WRITE_FAILED", HEARTBEAT_FILE);
    }

    while (running) {
        actions_this_cycle = 0;

        for (i = 0; i < WATCH_COUNT; i++) {
            scan_directory(&WATCH[i]);

            if (actions_this_cycle >= MAX_ACTIONS)
                break;
        }

        scan_processes();

        save_state();

        if (write_heartbeat() != 0) {
            slog("ERROR", "HEARTBEAT_WRITE_FAILED", HEARTBEAT_FILE);
        }

        sleep(LOOP_INTERVAL);
    }

    save_state();
    slog("INFO", "DAEMON_STOP", "Shutdown");

    return 0;
}
