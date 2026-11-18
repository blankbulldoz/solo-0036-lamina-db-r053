/*
 * laminad-fault -- deterministic persistence-boundary fault injector for
 * LaminaDB.
 *
 * Runs the database binary under ptrace(2), counts the syscalls that form
 * LaminaDB's durable boundaries, and at a chosen boundary either kills the
 * process exactly there or lets it die from SIGABRT:
 *
 *   kill-after:N:KIND   the N-th matching syscall has completed (its exit
 *                       stop is reached, no user-space instruction after it
 *                       has run), then the whole process is SIGKILLed.
 *   kill-in:N:KIND      the N-th matching syscall has been entered but has
 *                       not executed, then the process is SIGKILLed.
 *   abort-after:N:KIND  the N-th matching syscall has completed, then SIGABRT
 *                       is injected so the Go runtime's fatal path runs.
 *
 * KIND is one of: write fsync rename unlink mkdir open sync any.
 *
 * Only syscalls touching a path under one of the --watch prefixes are
 * counted. The counter is global across goroutines/threads, matching the
 * engine's single journal (durable mutations are serialized by the engine).
 *
 * Evidence:
 *   --evidence FILE     one JSON object per line for every counted syscall,
 *                       every watched file it touched, and the injected fault.
 *   --snapshot-dir DIR  immediately around the fault the tracer copies the raw
 *                       bytes of every watched regular file (pread in the
 *                       tracer, never through laminad) plus `ls -la` listings.
 *
 * The child inherits stdout/stderr, so laminad's slog output stays separate
 * from the JSONL evidence.
 *
 * Build: cc -O2 -o laminad-fault tracer.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

#define MAX_PATH 4096
#define MAX_WATCH 32
#define MAX_THREADS 1024
#define MAX_EVENTS 500000

enum kind {
    K_WRITE = 1, K_FSYNC, K_RENAME, K_UNLINK, K_MKDIR, K_OPEN, K_CLOSE, K_SYNC,
    K_TRUNCATE
};
enum action { A_NONE = 0, A_KILL_AFTER, A_KILL_IN, A_ABORT_AFTER, A_EIO_AFTER,
               A_TORN_AFTER };

struct watch { char path[MAX_PATH]; };

static struct {
    int n;
    int kind;
    int action;
    int watch_count;
    struct watch watch[MAX_WATCH];
    char evidence[MAX_PATH];
    char snapdir[MAX_PATH];
    int log_all_writes;
    int skip_first;
    int corrupt_flip;
    int corrupt_count;
    struct corrupt_rule {
        char path[MAX_PATH];
        long long offset;
        int length;
        unsigned char bytes[256];
    } corrupt[16];
    char arm_path[MAX_PATH];  /* counting starts only once this file exists */
} opt = {.n = 0, .kind = 0, .action = A_NONE, .watch_count = 0, .evidence = "", .snapdir = "", .log_all_writes = 0};

struct pending {
    int valid;
    int kind;
    uint64_t nr;
    int counted;
    int nth;
    int fd;
    long long len;
    long long off;
    int frame_valid;
    long long frame_seq;
    char frame_kind[32];
    int frame_crc_ok;
    unsigned long frame_len;
    char path[MAX_PATH];
    char path2[MAX_PATH];
};

static struct pending g_pending[MAX_THREADS];
static pid_t g_tids[MAX_THREADS];
static int g_thread_count;
static FILE *evf;
static pid_t g_pid;
static int g_counted;
static int g_seen_skips;
static int g_armed;

/* Override the return value of a syscall that already executed, simulating an
 * I/O error the kernel did not actually produce. Used only to exercise the
 * "durable append failed -> instance must stop serving" contract. */
static int override_return(pid_t tid, long value) {
#ifdef __aarch64__
    struct user_regs_struct regs;
    struct iovec io = {.iov_base = &regs, .iov_len = sizeof regs};
    if (ptrace(PTRACE_GETREGSET, tid, (void *)1, &io) != 0) return -1;
    regs.regs[0] = (unsigned long long)value; /* x0 */
    return ptrace(PTRACE_SETREGSET, tid, (void *)1, &io);
#else
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, tid, 0, &regs) != 0) return -1;
    regs.rax = (unsigned long long)value;
    return ptrace(PTRACE_SETREGS, tid, 0, &regs);
#endif
}
static char g_flip_path[MAX_PATH];
static long long g_flip_off = -1;
static long long g_last_write_off = -1;
static long long g_last_write_len = -1;
static int g_injected;
static long long g_events;
static struct timespec g_t0;

static const char *kind_name(int k) {
    switch (k) {
    case K_WRITE: return "write";
    case K_FSYNC: return "fsync";
    case K_RENAME: return "rename";
    case K_UNLINK: return "unlink";
    case K_MKDIR: return "mkdir";
    case K_OPEN: return "open";
    case K_CLOSE: return "close";
    case K_SYNC: return "sync";
    case K_TRUNCATE: return "truncate";
    default: return "other";
    }
}

static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static double now_ms(void) {
    return (now_ns() - ((long long)g_t0.tv_sec * 1000000000LL + g_t0.tv_nsec)) / 1e6;
}

static unsigned long crc32_ieee(const unsigned char *buf, size_t len) {
    static unsigned long table[256];
    static int ready;
    if (!ready) {
        for (unsigned long i = 0; i < 256; i++) {
            unsigned long c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320UL ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        ready = 1;
    }
    unsigned long c = 0xFFFFFFFFUL;
    for (size_t i = 0; i < len; i++)
        c = table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFUL;
}

/* Read the bytes handed to write(2) directly out of the target's address
 * space. This is what the kernel is about to persist; it is independent of
 * any later recovery by the database. */
static size_t vm_read(pid_t pid, uint64_t addr, void *dst, size_t len) {
    struct iovec local = {.iov_base = dst, .iov_len = len};
    struct iovec remote = {.iov_base = (void *)addr, .iov_len = len};
    long n = syscall(SYS_process_vm_readv, pid, &local, 1, &remote, 1, 0);
    if (n > 0) return (size_t)n;
    return 0;
}

struct frame_info {
    int valid;
    unsigned long frame_len;
    unsigned long stored_crc;
    unsigned long computed_crc;
    int crc_ok;
    long long seq;
    char kind[32];
};

static struct frame_info inspect_frame(pid_t pid, uint64_t addr, long long len) {
    struct frame_info fi;
    memset(&fi, 0, sizeof fi);
    fi.seq = -1;
    if (len < 8 || len > (long long)(1 << 20)) return fi;
    unsigned char buf[1 << 20];
    size_t got = vm_read(pid, addr, buf, (size_t)len);
    if (got < 8) return fi;
    fi.frame_len = ((unsigned long)buf[0] << 24) | ((unsigned long)buf[1] << 16) |
                   ((unsigned long)buf[2] << 8) | buf[3];
    fi.stored_crc = ((unsigned long)buf[4] << 24) | ((unsigned long)buf[5] << 16) |
                    ((unsigned long)buf[6] << 8) | buf[7];
    if (fi.frame_len == 0 || fi.frame_len > (16u << 20)) return fi;
    fi.valid = 1;
    size_t have = got - 8;
    if (have > fi.frame_len) have = fi.frame_len;
    if (have == fi.frame_len) {
        fi.computed_crc = crc32_ieee(buf + 8, have);
        fi.crc_ok = fi.computed_crc == fi.stored_crc;
    }
    /* Locate "kind" and "sequence" without parsing JSON. */
    char *payload = (char *)buf + 8;
    for (size_t i = 0; i + 7 < have; i++) {
        if (!memcmp(payload + i, "\"kind\":\"", 8)) {
            size_t k = 0;
            char *v = payload + i + 8;
            while (k + 1 < sizeof fi.kind && v[k] && v[k] != '"') { fi.kind[k] = v[k]; k++; }
            fi.kind[k] = 0;
            break;
        }
    }
    for (size_t i = 0; i + 11 < have; i++) {
        if (!memcmp(payload + i, "\"sequence\":", 11)) {
            fi.seq = atoll(payload + i + 11);
            break;
        }
    }
    return fi;
}

static void emit(const char *fmt, ...) {
    if (!evf || g_events >= MAX_EVENTS) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(evf, fmt, ap);
    va_end(ap);
    fputc('\n', evf);
    fflush(evf);
    g_events++;
}

static void jstr(const char *s) {
    fputc('"', evf);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', evf); fputc(*p, evf); }
        else if (*p < 0x20) fprintf(evf, "\\u%04x", *p);
        else fputc(*p, evf);
    }
    fputc('"', evf);
}

static int tid_slot(pid_t tid) {
    for (int i = 0; i < g_thread_count; i++) if (g_tids[i] == tid) return i;
    if (g_thread_count < MAX_THREADS) {
        g_tids[g_thread_count] = tid;
        memset(&g_pending[g_thread_count], 0, sizeof g_pending[0]);
        return g_thread_count++;
    }
    return MAX_THREADS - 1;
}

static int kind_of_nr(uint64_t nr) {
    switch (nr) {
    case __NR_write: return K_WRITE;
    case __NR_pwrite64: return K_WRITE;
    case __NR_fsync: return K_FSYNC;
    case __NR_fdatasync: return K_SYNC;
    case __NR_msync: return K_SYNC;
    case __NR_sync: return K_SYNC;
    case __NR_syncfs: return K_SYNC;
    case __NR_renameat2: return K_RENAME;
    case __NR_renameat: return K_RENAME;
#ifdef __NR_rename
    case __NR_rename: return K_RENAME;
#endif
    case __NR_unlinkat: return K_UNLINK;
#ifdef __NR_unlink
    case __NR_unlink: return K_UNLINK;
#endif
    case __NR_mkdirat: return K_MKDIR;
#ifdef __NR_mkdir
    case __NR_mkdir: return K_MKDIR;
#endif
    case __NR_openat: return K_OPEN;
    case __NR_openat2: return K_OPEN;
    case __NR_close: return K_CLOSE;
    case __NR_ftruncate: return K_TRUNCATE;
    default: return 0;
    }
}

static void read_cstr(pid_t pid, uint64_t addr, char *out, size_t cap) {
    out[0] = 0;
    if (!addr) return;
    size_t done = 0;
    while (done + 1 < cap) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + done), NULL);
        if (errno) break;
        memcpy(out + done, &word, sizeof word);
        for (size_t i = 0; i < sizeof word; i++)
            if (out[done + i] == 0) return;
        done += sizeof word;
    }
    out[cap - 1] = 0;
}

static void proc_fd_path(pid_t pid, int fd, char *out, size_t cap) {
    char link[64], target[MAX_PATH];
    out[0] = 0;
    if (fd < 0) return;
    snprintf(link, sizeof link, "/proc/%d/fd/%d", pid, fd);
    ssize_t n = readlink(link, target, sizeof target - 1);
    if (n <= 0) return;
    target[n] = 0;
    snprintf(out, cap, "%s", target);
}

static void proc_cwd(pid_t pid, char *out, size_t cap) {
    char link[64];
    snprintf(link, sizeof link, "/proc/%d/cwd", pid);
    ssize_t n = readlink(link, out, cap - 1);
    out[n > 0 ? n : 0] = 0;
}

static void resolve_at(pid_t pid, long dirfd, const char *rel, char *out, size_t cap) {
    if (rel[0] == '/') { snprintf(out, cap, "%s", rel); return; }
    char base[MAX_PATH] = "";
    if (dirfd == AT_FDCWD) proc_cwd(pid, base, sizeof base);
    else proc_fd_path(pid, (int)dirfd, base, sizeof base);
    if (base[0]) snprintf(out, cap, "%s/%s", base, rel);
    else snprintf(out, cap, "%s", rel);
}

/* Glob match: '*' matches any run of non-'/' characters, '?' one character. */
static int glob_match(const char *pat, const char *str) {
    while (*pat) {
        if (*pat == '*') {
            while (*pat == '*') pat++;
            if (!*pat) return strchr(str, '/') == NULL;
            for (const char *s = str; ; s++) {
                if (glob_match(pat, s)) return 1;
                if (!*s || *s == '/') return 0;
            }
        }
        if (!*str) return 0;
        if (*pat != '?' && *pat != *str) return 0;
        pat++;
        str++;
    }
    return *str == 0;
}

static int watched(const char *path) {
    if (opt.watch_count == 0) return 1;
    for (int i = 0; i < opt.watch_count; i++) {
        if (opt.watch[i].path[0] == 0) return 1;
        if (glob_match(opt.watch[i].path, path)) return 1;
    }
    return 0;
}

/* Current file offset of an open fd, read from the kernel (independent of
 * any userspace bookkeeping in the traced process). */
static long long fd_pos(pid_t pid, int fd) {
    if (fd < 0) return -1;
    char link[64], line[256];
    snprintf(link, sizeof link, "/proc/%d/fdinfo/%d", pid, fd);
    FILE *f = fopen(link, "re");
    if (!f) return -1;
    long long pos = -1;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "pos:", 4)) { pos = atoll(line + 4); break; }
    }
    fclose(f);
    return pos;
}

static long long file_size(const char *path) {
    struct stat st;
    if (!path || path[0] != '/' || stat(path, &st) != 0) return -1;
    return (long long)st.st_size;
}

static void snapshot_one(const char *path, const char *tag) {
    if (!opt.snapdir[0] || !path || path[0] != '/') return;
    struct stat st;
    if (lstat(path, &st) != 0) {
        emit("{\"event\":\"snapshot_absent\",\"tag\":\"%s\"}", tag);
        return;
    }
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    char dst[MAX_PATH];
    snprintf(dst, sizeof dst, "%.2048s/%.2048s.%.32s", opt.snapdir, base, tag);
    if (S_ISDIR(st.st_mode)) {
        fprintf(evf, "{\"event\":\"snapshot_dir\",\"tag\":\"%s\",\"path\":", tag);
        jstr(path);
        fputs("}\n", evf);
        fflush(evf);
        g_events++;
        return;
    }
    if (!S_ISREG(st.st_mode)) return;
    int in = open(path, O_RDONLY);
    if (in < 0) return;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0) { close(in); return; }
    char buf[65536];
    ssize_t n;
    unsigned long long total = 0;
    while ((n = read(in, buf, sizeof buf)) > 0) {
        ssize_t done = 0;
        while (done < n) {
            ssize_t w = write(out, buf + done, (size_t)(n - done));
            if (w <= 0) break;
            done += w;
        }
        total += (unsigned long long)n;
    }
    fsync(out);
    close(out);
    close(in);
    fprintf(evf, "{\"event\":\"snapshot_file\",\"tag\":\"%s\",\"path\":", tag);
    jstr(path);
    fputs(",\"copy\":", evf);
    jstr(dst);
    fprintf(evf, ",\"bytes\":%llu}\n", total);
    fflush(evf);
    g_events++;
}

static void snapshot_all(const char *extra, const char *tag) {
    char seen[2 * MAX_WATCH][MAX_PATH];
    int nseen = 0;
    for (int i = 0; i < opt.watch_count; i++) {
        if (strpbrk(opt.watch[i].path, "*?")) {
            glob_t g;
            memset(&g, 0, sizeof g);
            if (glob(opt.watch[i].path, 0, NULL, &g) == 0) {
                for (size_t k = 0; k < g.gl_pathc && nseen < 2 * MAX_WATCH; k++) {
                    snapshot_one(g.gl_pathv[k], tag);
                    snprintf(seen[nseen++], MAX_PATH, "%s", g.gl_pathv[k]);
                }
            }
            globfree(&g);
        } else {
            snapshot_one(opt.watch[i].path, tag);
            if (nseen < 2 * MAX_WATCH) snprintf(seen[nseen++], MAX_PATH, "%s", opt.watch[i].path);
        }
    }
    if (extra && extra[0] == '/') {
        int dup = 0;
        for (int i = 0; i < nseen; i++)
            if (!strcmp(seen[i], extra)) dup = 1;
        if (!dup) snapshot_one(extra, tag);
    }
    /* Directory listings are independent evidence of what names existed. */
    for (int i = 0; i < opt.watch_count; i++) {
        char dir[MAX_PATH];
        struct stat st;
        snprintf(dir, sizeof dir, "%s", opt.watch[i].path);
        if (lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            char *slash = strrchr(dir, '/');
            if (!slash) continue;
            *slash = 0;
        }
        char cmd[MAX_PATH * 3 + 64];
        snprintf(cmd, sizeof cmd, "ls -lnaR --time-style=full-iso '%s' > '%s/listing.%d.txt' 2>&1",
                 dir, opt.snapdir, i);
        if (system(cmd) != 0) { /* best effort */ }
    }
}

static void kill_group(void) {
    kill(-g_pid, SIGKILL);
    kill(g_pid, SIGKILL);
}

static void apply_corruption(void) {
    for (int i = 0; i < opt.corrupt_count; i++) {
        struct corrupt_rule *r = &opt.corrupt[i];
        int fd = open(r->path, O_RDWR);
        if (fd < 0) {
            fprintf(evf, "{\"event\":\"corrupt_failed\",\"path\":");
            jstr(r->path);
            fprintf(evf, ",\"errno\":%d}\n", errno);
            fflush(evf);
            continue;
        }
        ssize_t w = pwrite(fd, r->bytes, (size_t)r->length, (off_t)r->offset);
        fsync(fd);
        close(fd);
        fprintf(evf, "{\"event\":\"corrupt_applied\",\"path\":");
        jstr(r->path);
        fprintf(evf, ",\"offset\":%lld,\"length\":%d,\"written\":%zd}\n",
                r->offset, r->length, w);
        fflush(evf);
    }
}

/* Deterministically damage the bytes the target just persisted: flip one byte
 * in the middle of the last written frame (or the renamed-in file), after the
 * syscall has completed and before the process is killed. This is what a torn
 * or misdirected write leaves behind; the harness then checks that startup
 * refuses it instead of silently repairing. */
static void apply_flip(void) {
    if (!opt.corrupt_flip || g_flip_off < 0 || g_flip_path[0] != '/') return;
    int fd = open(g_flip_path, O_RDWR);
    if (fd < 0) {
        fprintf(evf, "{\"event\":\"flip_failed\",\"path\":");
        jstr(g_flip_path);
        fprintf(evf, ",\"errno\":%d}\n", errno);
        fflush(evf);
        return;
    }
    unsigned char byte = 0;
    if (pread(fd, &byte, 1, (off_t)g_flip_off) != 1) {
        close(fd);
        return;
    }
    unsigned char flipped = byte ^ 0xFF;
    ssize_t w = pwrite(fd, &flipped, 1, (off_t)g_flip_off);
    fsync(fd);
    close(fd);
    fprintf(evf, "{\"event\":\"flip_applied\",\"path\":");
    jstr(g_flip_path);
    fprintf(evf, ",\"offset\":%lld,\"from\":%u,\"to\":%u,\"written\":%zd}\n",
            g_flip_off, byte, flipped, w);
    fflush(evf);
}

/* Stop the whole group with SIGSTOP before any cleanup so nothing else can
 * run, then SIGKILL. This removes the race between "kill delivered" and
 * "process still executing user-space cleanup". */
static void inject_fault(pid_t tid, const char *how, int kind,
                         const char *path, const char *path2) {
    if (g_injected) return;
    g_injected = 1;
    apply_corruption();
    fprintf(evf, "{\"event\":\"fault\",\"at\":\"%s\",\"nth\":%d,\"kind\":\"%s\","
                 "\"ts_ms\":%.3f,\"t_ns\":%lld,\"path\":", how, g_counted, kind_name(kind),
            now_ms(), now_ns());
    if (path && path[0]) jstr(path); else fputs("null", evf);
    fputs(",\"path2\":", evf);
    if (path2 && path2[0]) jstr(path2); else fputs("null", evf);
    fputs("}\n", evf);
    fflush(evf);

    if (opt.action == A_EIO_AFTER) {
        /* The syscall already ran; rewrite its result to -EIO and let the
         * target observe the failure exactly as it would a real device error.
         * The process stays alive so the harness can observe the contract. */
        override_return(tid, -5);
        fprintf(evf, "{\"event\":\"eio_injected\",\"nth\":%d,\"kind\":\"%s\","
                     "\"ts_ms\":%.3f}\n", g_counted, kind_name(kind), now_ms());
        fflush(evf);
        return;
    }
    if (opt.action == A_ABORT_AFTER) {
        /* A Go runtime fatal abort needs its other threads runnable, so this
         * action does not freeze: it delivers SIGABRT to the group at the
         * boundary and lets the runtime's own fatal path run. Any work after
         * the boundary is therefore racy by construction; the harness records
         * the process's exit signal to make that explicit. */
        apply_flip();
        if (opt.snapdir[0]) snapshot_all(path, "atfault");
        /* Deliver SIGABRT through ptrace. A group-directed signal would be
         * consumed as a pending signal-delivery-stop; forwarding it explicitly
         * on the stopped thread lets the Go runtime's fatal handler run. */
        kill(-g_pid, SIGABRT);
        ptrace(PTRACE_CONT, tid, 0, (void *)(long)SIGABRT);
        struct timespec ts = {0, 400 * 1000 * 1000};
        nanosleep(&ts, NULL);
        return;
    }
    if (opt.action == A_TORN_AFTER) {
        /* Simulate a write interrupted by media failure: keep only the first
         * half of the frame that was just handed to the kernel. */
        kill(-g_pid, SIGSTOP);
        kill(g_pid, SIGSTOP);
        struct timespec ts = {0, 2 * 1000 * 1000};
        nanosleep(&ts, NULL);
        if (path[0] == '/' && g_last_write_len > 8) {
            long long keep = g_last_write_off + 8 + g_last_write_len / 2;
            int fd = open(path, O_WRONLY);
            if (fd >= 0) {
                int rc = ftruncate(fd, (off_t)keep);
                fsync(fd);
                close(fd);
                fprintf(evf, "{\"event\":\"torn_applied\",\"path\":");
                jstr(path);
                fprintf(evf, ",\"offset\":%lld,\"kept_bytes\":%lld,"
                             "\"rc\":%d}\n", g_last_write_off, keep, rc);
                fflush(evf);
            }
        }
        if (opt.snapdir[0]) snapshot_all(path, "atfault");
        kill_group();
        ts.tv_nsec = 20 * 1000 * 1000;
        nanosleep(&ts, NULL);
        return;
    }
    /* Freeze first: no thread may run after the boundary. */
    kill(-g_pid, SIGSTOP);
    kill(g_pid, SIGSTOP);
    struct timespec ts = {0, 2 * 1000 * 1000};
    nanosleep(&ts, NULL);
    if (opt.action != A_KILL_IN) apply_flip();
    if (opt.snapdir[0]) snapshot_all(path, "atfault");
    kill_group();
    ts.tv_nsec = 20 * 1000 * 1000;
    nanosleep(&ts, NULL);
}

static void on_entry(pid_t tid, const struct __ptrace_syscall_info *info) {
    uint64_t nr = info->entry.nr;
    int kind = kind_of_nr(nr);
    if (!kind) return;
    int slot = tid_slot(tid);
    struct pending *p = &g_pending[slot];
    memset(p, 0, sizeof *p);

    char path[MAX_PATH] = "", path2[MAX_PATH] = "";
    int fd = -1;
    long long len = -1;
    long long off = -1;
    int candidate = 0;
    int frame_valid = 0;
    long long frame_seq = -1;
    int frame_crc_ok = 0;
    unsigned long frame_len = 0;
    char frame_kind[32] = "";

    switch (kind) {
    case K_WRITE:
        fd = (int)info->entry.args[0];
        len = (long long)info->entry.args[2];
        proc_fd_path(tid, fd, path, sizeof path);
        candidate = path[0] && watched(path);
        off = fd_pos(tid, fd);
        if (candidate) {
            struct frame_info fi = inspect_frame(tid, info->entry.args[1],
                                                 (long long)info->entry.args[2]);
            if (fi.valid) {
                frame_valid = 1;
                frame_seq = fi.seq;
                frame_crc_ok = fi.crc_ok;
                frame_len = (unsigned long)fi.frame_len;
                snprintf(frame_kind, sizeof frame_kind, "%s", fi.kind);
            }
        }
        break;
    case K_FSYNC:
    case K_SYNC:
        fd = (int)info->entry.args[0];
        proc_fd_path(tid, fd, path, sizeof path);
        candidate = path[0] && watched(path);
        break;
    case K_CLOSE:
        return;
    case K_RENAME: {
        /* rename(old,new) has two string args; renameat/renameat2 have
         * (olddirfd, old, newdirfd, new). */
        char rel[MAX_PATH];
#ifdef __NR_rename
        if (nr == __NR_rename) {
            read_cstr(tid, info->entry.args[0], rel, sizeof rel);
            resolve_at(tid, AT_FDCWD, rel, path2, sizeof path2);
            read_cstr(tid, info->entry.args[1], rel, sizeof rel);
            resolve_at(tid, AT_FDCWD, rel, path, sizeof path);
        } else
#endif
        {
            long od = (long)info->entry.args[0];
            long nd = (long)info->entry.args[2];
            read_cstr(tid, info->entry.args[1], rel, sizeof rel);
            resolve_at(tid, od, rel, path2, sizeof path2);
            read_cstr(tid, info->entry.args[3], rel, sizeof rel);
            resolve_at(tid, nd, rel, path, sizeof path);
        }
        candidate = watched(path) || watched(path2);
        break;
    }
    case K_TRUNCATE:
        fd = (int)info->entry.args[0];
        len = (long long)info->entry.args[1];
        proc_fd_path(tid, fd, path, sizeof path);
        candidate = path[0] && watched(path);
        break;
    case K_UNLINK:
    case K_MKDIR:
    case K_OPEN: {
        long d = (long)info->entry.args[0];
        char rel[MAX_PATH];
        read_cstr(tid, info->entry.args[1], rel, sizeof rel);
        resolve_at(tid, d, rel, path, sizeof path);
        candidate = watched(path);
        break;
    }
    default:
        return;
    }
    if (!candidate) {
        if (opt.log_all_writes && kind == K_WRITE) {
            fprintf(evf, "{\"event\":\"syscall\",\"phase\":\"entry\",\"ts_ms\":%.3f,"
                         "\"tid\":%d,\"kind\":\"write\",\"counted\":false,\"path\":",
                    now_ms(), (int)tid);
            if (path[0]) jstr(path); else fputs("null", evf);
            fputs("}\n", evf);
            fflush(evf);
        }
        return;
    }
    if (opt.arm_path[0] && !g_armed && access(opt.arm_path, F_OK) == 0) {
        g_armed = 1;
        fprintf(evf, "{\"event\":\"armed\",\"ts_ms\":%.3f}\n", now_ms());
        fflush(evf);
    }
    int counted = 0, nth = 0;
    if (opt.action && (!opt.kind || kind == opt.kind) &&
        (!opt.arm_path[0] || g_armed)) {
        if (g_seen_skips < opt.skip_first) {
            g_seen_skips++;
        } else {
            counted = 1;
            nth = ++g_counted;
        }
    }
    p->valid = 1;
    p->kind = kind;
    p->nr = nr;
    p->counted = counted;
    p->nth = nth;
    p->fd = fd;
    p->len = len;
    p->off = off;
    p->frame_valid = frame_valid;
    p->frame_seq = frame_seq;
    p->frame_crc_ok = frame_crc_ok;
    p->frame_len = frame_len;
    snprintf(p->frame_kind, sizeof p->frame_kind, "%s", frame_kind);
    snprintf(p->path, sizeof p->path, "%s", path);
    snprintf(p->path2, sizeof p->path2, "%s", path2);

    fprintf(evf, "{\"event\":\"syscall\",\"phase\":\"entry\",\"ts_ms\":%.3f,"
                 "\"tid\":%d,\"nr\":%llu,\"kind\":\"%s\",\"path\":",
            now_ms(), (int)tid, (unsigned long long)nr, kind_name(kind));
    if (path[0]) jstr(path); else fputs("null", evf);
    fputs(",\"path2\":", evf);
    if (path2[0]) jstr(path2); else fputs("null", evf);
    fprintf(evf, ",\"fd\":%d,\"off\":%lld,\"len\":%lld,"
                 "\"frame_valid\":%s,\"frame_seq\":%lld,\"frame_kind\":\"%s\","
                 "\"frame_crc_ok\":%s,\"frame_len\":%lu,"
                 "\"counted\":%s,\"nth\":%d}\n",
            fd, off, len, frame_valid ? "true" : "false", frame_seq, frame_kind,
            frame_crc_ok ? "true" : "false", frame_len,
            counted ? "true" : "false", nth);
    fflush(evf);
    g_events++;

    if (counted && nth == opt.n && opt.action == A_KILL_IN && !g_injected) {
        inject_fault(tid, "kill-in", kind, path, path2);
    }
}

static void handle_exit(pid_t tid, const struct __ptrace_syscall_info *info, long result) {
    (void)info;
    int slot = tid_slot(tid);
    struct pending *p = &g_pending[slot];
    if (!p->valid) return;
    uint64_t nr = p->nr;
    int kind = p->kind;
    if (!kind || kind == K_CLOSE) {
        p->valid = 0;
        return;
    }
    int counted = p->counted, nth = p->nth;
    char path[MAX_PATH], path2[MAX_PATH];
    snprintf(path, sizeof path, "%s", p->path);
    snprintf(path2, sizeof path2, "%s", p->path2);
    int fd = p->fd;
    long long len = p->len;
    long long off = p->off;
    long long size = file_size(path);
    p->valid = 0;

    fprintf(evf, "{\"event\":\"syscall\",\"phase\":\"exit\",\"ts_ms\":%.3f,"
                 "\"tid\":%d,\"nr\":%llu,\"kind\":\"%s\",\"path\":",
            now_ms(), (int)tid, (unsigned long long)nr, kind_name(kind));
    if (path[0]) jstr(path); else fputs("null", evf);
    fputs(",\"path2\":", evf);
    if (path2[0]) jstr(path2); else fputs("null", evf);
    fprintf(evf, ",\"fd\":%d,\"off\":%lld,\"len\":%lld,\"result\":%ld,"
                 "\"size_after\":%lld,\"frame_valid\":%s,\"frame_seq\":%lld,"
                 "\"frame_kind\":\"%s\",\"frame_crc_ok\":%s,"
                 "\"counted\":%s,\"nth\":%d}\n",
            fd, off, len, result, size, p->frame_valid ? "true" : "false",
            p->frame_seq, p->frame_kind, p->frame_crc_ok ? "true" : "false",
            counted ? "true" : "false", nth);
    fflush(evf);
    g_events++;

    if (counted && nth == opt.n && opt.action == A_EIO_AFTER && !g_injected) {
        inject_fault(tid, "eio-after", kind, path, path2);
        return;
    }
    if (counted && nth == opt.n && opt.action != A_KILL_IN && !g_injected) {
        if (opt.corrupt_flip) {
            if (kind == K_WRITE && off >= 0 && len > 8) {
                snprintf(g_flip_path, sizeof g_flip_path, "%s", path);
                g_flip_off = off + 8 + len / 2;
            } else if (kind == K_RENAME) {
                snprintf(g_flip_path, sizeof g_flip_path, "%s", path);
                long long size = file_size(path);
                g_flip_off = size > 1 ? size / 2 : 0;
            } else if (kind == K_TRUNCATE) {
                snprintf(g_flip_path, sizeof g_flip_path, "%s", path);
                g_flip_off = file_size(path) > 0 ? file_size(path) - 1 : 0;
            }
        }
        g_last_write_off = off;
        g_last_write_len = len;
        const char *how = "kill-after";
        if (opt.action == A_ABORT_AFTER) how = "abort-after";
        else if (opt.action == A_TORN_AFTER) how = "torn-after";
        inject_fault(tid, how, kind, path, path2);
    }
}

int main(int argc, char **argv) {
    int argi = 1;
    for (; argi < argc; argi++) {
        if (!strcmp(argv[argi], "--")) { argi++; break; }
        if (!strcmp(argv[argi], "--stop")) {
            const char *spec = argv[++argi];
            char mode[32] = "", kind[32] = "";
            int n = 0;
            if (sscanf(spec, "%31[^:]:%d:%31s", mode, &n, kind) != 3) {
                fprintf(stderr, "bad --stop %s (want mode:N:kind)\n", spec);
                return 2;
            }
            opt.n = n;
            if (!strcmp(mode, "kill-after")) opt.action = A_KILL_AFTER;
            else if (!strcmp(mode, "kill-in")) opt.action = A_KILL_IN;
            else if (!strcmp(mode, "abort-after")) opt.action = A_ABORT_AFTER;
            else if (!strcmp(mode, "eio-after")) opt.action = A_EIO_AFTER;
            else if (!strcmp(mode, "torn-after")) opt.action = A_TORN_AFTER;
            else { fprintf(stderr, "bad mode %s\n", mode); return 2; }
            opt.kind = 0;
            if (!strcmp(kind, "write")) opt.kind = K_WRITE;
            else if (!strcmp(kind, "fsync")) opt.kind = K_FSYNC;
            else if (!strcmp(kind, "rename")) opt.kind = K_RENAME;
            else if (!strcmp(kind, "unlink")) opt.kind = K_UNLINK;
            else if (!strcmp(kind, "mkdir")) opt.kind = K_MKDIR;
            else if (!strcmp(kind, "open")) opt.kind = K_OPEN;
            else if (!strcmp(kind, "sync")) opt.kind = K_SYNC;
            else if (!strcmp(kind, "truncate")) opt.kind = K_TRUNCATE;
            else if (!strcmp(kind, "any")) opt.kind = 0;
            else { fprintf(stderr, "bad kind %s\n", kind); return 2; }
        } else if (!strcmp(argv[argi], "--watch")) {
            if (opt.watch_count >= MAX_WATCH) return 2;
            snprintf(opt.watch[opt.watch_count++].path, MAX_PATH, "%s", argv[++argi]);
        } else if (!strcmp(argv[argi], "--evidence")) {
            snprintf(opt.evidence, sizeof opt.evidence, "%s", argv[++argi]);
        } else if (!strcmp(argv[argi], "--snapshot-dir")) {
            snprintf(opt.snapdir, sizeof opt.snapdir, "%s", argv[++argi]);
        } else if (!strcmp(argv[argi], "--corrupt")) {
            /* path:offset:hexbytes */
            char *spec = argv[++argi];
            char *c1 = strchr(spec, ':');
            char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
            if (!c1 || !c2 || opt.corrupt_count >= 16) {
                fprintf(stderr, "bad --corrupt %s (want path:offset:hex)\n", spec);
                return 2;
            }
            struct corrupt_rule *r = &opt.corrupt[opt.corrupt_count++];
            size_t plen = (size_t)(c1 - spec);
            if (plen >= MAX_PATH) plen = MAX_PATH - 1;
            memcpy(r->path, spec, plen);
            r->path[plen] = 0;
            r->offset = atoll(c1 + 1);
            const char *hex = c2 + 1;
            size_t hl = strlen(hex);
            if (hl % 2 || hl / 2 > (size_t)sizeof r->bytes) {
                fprintf(stderr, "bad hex in --corrupt\n");
                return 2;
            }
            r->length = (int)(hl / 2);
            for (int i = 0; i < r->length; i++) {
                unsigned v = 0;
                sscanf(hex + i * 2, "%2x", &v);
                r->bytes[i] = (unsigned char)v;
            }
        } else if (!strcmp(argv[argi], "--corrupt-flip")) {
            opt.corrupt_flip = 1;
        } else if (!strcmp(argv[argi], "--arm")) {
            snprintf(opt.arm_path, sizeof opt.arm_path, "%s", argv[++argi]);
        } else if (!strcmp(argv[argi], "--skip-first")) {
            opt.skip_first = atoi(argv[++argi]);
        } else if (!strcmp(argv[argi], "--log-all-writes")) {
            opt.log_all_writes = 1;
        } else {
            fprintf(stderr, "unknown option %s\n", argv[argi]);
            return 2;
        }
    }
    if (argi >= argc) { fprintf(stderr, "missing command\n"); return 2; }
    if (opt.evidence[0]) {
        evf = fopen(opt.evidence, "a");
        if (!evf) { perror("evidence"); return 2; }
    } else {
        evf = stdout;
    }
    if (opt.snapdir[0]) mkdir(opt.snapdir, 0700);
    clock_gettime(CLOCK_MONOTONIC, &g_t0);
    memset(g_pending, 0, sizeof g_pending);

    pid_t pid = fork();
    if (pid == 0) {
        setpgid(0, 0);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(126);
        raise(SIGSTOP);
        execv(argv[argi], &argv[argi]);
        _exit(127);
    }
    g_pid = pid;
    int status;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 1; }
    ptrace(PTRACE_SETOPTIONS, pid, 0,
           (void *)(PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL |
                    PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC));
    tid_slot(pid);
    fprintf(evf, "{\"event\":\"launch\",\"pid\":%d,\"stop_n\":%d,"
                 "\"stop_kind\":\"%s\",\"action\":%d,\"watch_count\":%d,"
                 "\"skip_first\":%d,\"corrupt_flip\":%s,\"arm\":", pid, opt.n,
            kind_name(opt.kind), opt.action, opt.watch_count, opt.skip_first,
            opt.corrupt_flip ? "true" : "false");
    if (opt.arm_path[0]) jstr(opt.arm_path); else fputs("null", evf);
    fprintf(evf, ",\"t0_ns\":%lld,\"tracer_start_ms\":%.3f}\n",
            (long long)(g_t0.tv_sec * 1000000000LL + g_t0.tv_nsec), now_ms());
    for (int i = 0; i < opt.watch_count; i++) {
        fprintf(evf, "{\"event\":\"watch\",\"path\":");
        jstr(opt.watch[i].path);
        fputs("}\n", evf);
    }
    fflush(evf);
    ptrace(PTRACE_SYSCALL, pid, 0, 0);

    while (1) {
        pid_t tid = waitpid(-1, &status, __WALL);
        if (tid < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (tid == pid) {
                fprintf(evf, "{\"event\":\"target_exit\",\"exited\":%s,\"code\":%d,"
                             "\"signal\":%d,\"ts_ms\":%.3f}\n",
                        WIFEXITED(status) ? "true" : "false",
                        WIFEXITED(status) ? WEXITSTATUS(status) : 0,
                        WIFSIGNALED(status) ? WTERMSIG(status) : 0, now_ms());
                fflush(evf);
            }
            continue;
        }
        if (!WIFSTOPPED(status)) continue;
        int sig = WSTOPSIG(status);
        int event = status >> 16;
        if (sig == (SIGTRAP | 0x80)) {
            struct __ptrace_syscall_info info;
            memset(&info, 0, sizeof info);
            if (ptrace(PTRACE_GET_SYSCALL_INFO, tid, (void *)sizeof info, &info) > 0) {
                if (info.op == PTRACE_SYSCALL_INFO_ENTRY) on_entry(tid, &info);
                else if (info.op == PTRACE_SYSCALL_INFO_EXIT) handle_exit(tid, &info, info.exit.rval);
            }
            if (!g_injected) ptrace(PTRACE_SYSCALL, tid, 0, 0);
            else ptrace(PTRACE_CONT, tid, 0, 0);
            continue;
        }
        if (sig == SIGTRAP && event == PTRACE_EVENT_CLONE) {
            unsigned long newtid = 0;
            ptrace(PTRACE_GETEVENTMSG, tid, 0, &newtid);
            ptrace(PTRACE_SYSCALL, tid, 0, 0);
            continue;
        }
        if (sig == SIGTRAP && (event == PTRACE_EVENT_EXEC || event == PTRACE_EVENT_STOP)) {
            ptrace(PTRACE_SYSCALL, tid, 0, 0);
            continue;
        }
        if (sig == SIGSTOP || sig == SIGTRAP) {
            ptrace(PTRACE_SYSCALL, tid, 0, 0);
            continue;
        }
        if (sig == SIGABRT && g_injected) {
            ptrace(PTRACE_CONT, tid, 0, (void *)(long)SIGABRT);
            continue;
        }
        ptrace(PTRACE_SYSCALL, tid, 0, (void *)(long)sig);
    }
    fprintf(evf, "{\"event\":\"tracer_done\",\"counted\":%d,\"injected\":%s,"
                 "\"ts_ms\":%.3f}\n",
            g_counted, g_injected ? "true" : "false", now_ms());
    fflush(evf);
    return 0;
}
