// Test-only libc observer. Runs in a fresh test process, independently of the
// provider's access log. Observe both requested paths and opened descriptors so
// symlink targets and write-then-unlink effects remain visible.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// The observed child runs one test thread, so plain process state avoids TLS
// access from metadata hooks that libSystem calls during early process setup.
static char root[PATH_MAX];
static int active, bootstrap, violations, observing;
static int resolve_existing_prefix(const char *path, char *out);

void wallet_probe_begin(const char *path, int boot) {
    char resolved[PATH_MAX];
    const char *value = resolve_existing_prefix(path, resolved) == 0 ? resolved : path;
    snprintf(root, sizeof(root), "%s", value);
    bootstrap = boot;
    violations = 0;
    active = 1;
}
int wallet_probe_end(void) { active = 0; return violations; }

static int below(const char *path, const char *base) {
    size_t n = strlen(base);
    return strncmp(path, base, n) == 0 && (path[n] == 0 || path[n] == '/');
}
static int fd_path(int fd, char *path) {
#ifdef __APPLE__
    return fcntl(fd, F_GETPATH, path);
#else
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, PATH_MAX - 1);
    if (n < 0) return -1;
    path[n] = 0;
    return 0;
#endif
}
static void normalize(char *path) {
    char copy[PATH_MAX], result[PATH_MAX] = "", *state;
    snprintf(copy, sizeof(copy), "%s", path);
    for (char *p = strtok_r(copy, "/", &state); p; p = strtok_r(NULL, "/", &state)) {
        if (!strcmp(p, ".")) continue;
        if (!strcmp(p, "..")) {
            char *last = strrchr(result, '/');
            if (last) *last = 0;
        } else {
            size_t n = strlen(result);
            snprintf(result + n, sizeof(result) - n, "/%s", p);
        }
    }
    snprintf(path, PATH_MAX, "%s", result[0] ? result : "/");
}
// Resolve symlinked aliases in the existing prefix so a canonical root and an
// uncanonicalized syscall path compare equal. Missing suffixes stay literal.
static int resolve_existing_prefix(const char *path, char *out) {
    char candidate[PATH_MAX];
    snprintf(candidate, sizeof(candidate), "%s", path);
    while (1) {
        char resolved[PATH_MAX];
        if (realpath(candidate, resolved)) {
            snprintf(out, PATH_MAX, "%s%s", resolved, path + strlen(candidate));
            return 0;
        }
        char *slash = strrchr(candidate, '/');
        if (!slash || slash == candidate) return -1;
        *slash = 0;
    }
}
static void observe_impl(int dirfd, const char *path, int directory, int symlink,
                         int opened, int metadata, int failed) {
    if (!active) return;
    char absolute[PATH_MAX], parent[PATH_MAX];
    if (opened >= 0 && fd_path(opened, absolute) == 0) {
        struct stat st;
        if (!fstat(opened, &st)) {
            directory = S_ISDIR(st.st_mode);
            symlink = S_ISLNK(st.st_mode);
        }
    } else if (path[0] == '/') {
        snprintf(absolute, sizeof(absolute), "%s", path);
    } else {
        if (dirfd == AT_FDCWD) {
            if (!getcwd(parent, sizeof(parent))) parent[0] = 0;
        } else if (fd_path(dirfd, parent)) parent[0] = 0;
        snprintf(absolute, sizeof(absolute), "%s/%s", parent, path);
    }
    normalize(absolute);
    char resolved[PATH_MAX];
    if (resolve_existing_prefix(absolute, resolved) == 0) {
        snprintf(absolute, sizeof(absolute), "%s", resolved);
    }
    if (below(absolute, root)) return;
    int ancestor = below(root, absolute) || !strcmp(absolute, "/");
    // Bootstrap may inspect ancestor directories, symlink aliases, and probe
    // whether a missing ancestor exists, but not metadata of existing ancestor
    // files, nor any effect.
    if (bootstrap && ancestor &&
        (metadata ? (failed || directory || symlink) : directory)) return;
    ++violations;
    fprintf(stderr,
            "wallet IO observer: outside access %s (bootstrap=%d metadata=%d dir=%d symlink=%d opened=%d failed=%d)\n",
            absolute, bootstrap, metadata, directory, symlink, opened, failed);
}
static void observe(int dirfd, const char *path, int directory, int symlink,
                    int opened, int metadata, int failed) {
    if (observing) return;
    int saved_errno = errno;
    observing = 1;
    observe_impl(dirfd, path, directory, symlink, opened, metadata, failed);
    observing = 0;
    errno = saved_errno;
}
#ifdef __APPLE__
#define HOOK(name) watched_##name
#define REAL(name) name
#define INTERPOSE(name) \
    __attribute__((used)) static struct { const void *replacement, *original; } pair_##name \
    __attribute__((section("__DATA,__interpose"))) = { (void *)watched_##name, (void *)name };
#else
#define HOOK(name) name
#define REAL(name) ((__typeof__(&name))dlsym(RTLD_NEXT, #name))
#define INTERPOSE(name)
#endif

#define OPEN_HOOK(name) \
int HOOK(name)(const char *path, int flags, ...) { \
    mode_t mode = 0; \
    if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); } \
    int fd = REAL(name)(path, flags, mode); \
    observe(AT_FDCWD, path, flags & O_DIRECTORY, 0, fd, 0, 0); \
    return fd; \
} \
INTERPOSE(name)
OPEN_HOOK(open)
#ifndef __APPLE__
OPEN_HOOK(open64)
#endif

#define OPENAT_HOOK(name) \
int HOOK(name)(int dir, const char *path, int flags, ...) { \
    mode_t mode = 0; \
    if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); } \
    int fd = REAL(name)(dir, path, flags, mode); \
    observe(dir, path, flags & O_DIRECTORY, 0, fd, 0, 0); \
    return fd; \
} \
INTERPOSE(name)
OPENAT_HOOK(openat)
#ifndef __APPLE__
OPENAT_HOOK(openat64)
#endif

int HOOK(unlink)(const char *path) {
    observe(AT_FDCWD, path, 0, 0, -1, 0, 0);
    return REAL(unlink)(path);
}
INTERPOSE(unlink)
int HOOK(unlinkat)(int dir, const char *path, int flags) {
    observe(dir, path, flags & AT_REMOVEDIR, 0, -1, 0, 0);
    return REAL(unlinkat)(dir, path, flags);
}
INTERPOSE(unlinkat)
int HOOK(mkdir)(const char *path, mode_t mode) {
    observe(AT_FDCWD, path, 1, 0, -1, 0, 0);
    return REAL(mkdir)(path, mode);
}
INTERPOSE(mkdir)
int HOOK(mkdirat)(int dir, const char *path, mode_t mode) {
    observe(dir, path, 1, 0, -1, 0, 0);
    return REAL(mkdirat)(dir, path, mode);
}
INTERPOSE(mkdirat)
int HOOK(rename)(const char *from, const char *to) {
    observe(AT_FDCWD, from, 0, 0, -1, 0, 0); observe(AT_FDCWD, to, 0, 0, -1, 0, 0);
    return REAL(rename)(from, to);
}
INTERPOSE(rename)
int HOOK(renameat)(int a, const char *from, int b, const char *to) {
    observe(a, from, 0, 0, -1, 0, 0); observe(b, to, 0, 0, -1, 0, 0);
    return REAL(renameat)(a, from, b, to);
}
INTERPOSE(renameat)
int HOOK(link)(const char *from, const char *to) {
    observe(AT_FDCWD, from, 0, 0, -1, 0, 0); observe(AT_FDCWD, to, 0, 0, -1, 0, 0);
    return REAL(link)(from, to);
}
INTERPOSE(link)
int HOOK(linkat)(int a, const char *from, int b, const char *to, int flags) {
    observe(a, from, 0, 0, -1, 0, 0); observe(b, to, 0, 0, -1, 0, 0);
    return REAL(linkat)(a, from, b, to, flags);
}
INTERPOSE(linkat)

// Metadata inspection and descriptor permission changes are effects too: a
// stat of an outside file, or an fchmod through an outside hard link, must not
// disappear from the observation.
#define STAT_HOOK(name) \
int HOOK(name)(const char *path, struct stat *buf) { \
    int result = REAL(name)(path, buf); \
    int ok = result == 0; \
    observe(AT_FDCWD, path, ok && S_ISDIR(buf->st_mode), ok && S_ISLNK(buf->st_mode), -1, 1, ok ? 0 : 1); \
    return result; \
} \
INTERPOSE(name)
STAT_HOOK(stat)
STAT_HOOK(lstat)

int HOOK(fstat)(int fd, struct stat *buf) {
    int result = REAL(fstat)(fd, buf);
    int ok = result == 0;
    observe(AT_FDCWD, "", ok && S_ISDIR(buf->st_mode), ok && S_ISLNK(buf->st_mode), fd, 1, ok ? 0 : 1);
    return result;
}
INTERPOSE(fstat)

int HOOK(fstatat)(int dir, const char *path, struct stat *buf, int flags) {
    int result = REAL(fstatat)(dir, path, buf, flags);
    int ok = result == 0;
    observe(dir, path, ok && S_ISDIR(buf->st_mode), ok && S_ISLNK(buf->st_mode), -1, 1, ok ? 0 : 1);
    return result;
}
INTERPOSE(fstatat)

int HOOK(chmod)(const char *path, mode_t mode) {
    int result = REAL(chmod)(path, mode);
    observe(AT_FDCWD, path, 0, 0, -1, 0, 0);
    return result;
}
INTERPOSE(chmod)

int HOOK(fchmod)(int fd, mode_t mode) {
    int result = REAL(fchmod)(fd, mode);
    observe(AT_FDCWD, "", 0, 0, fd, 0, 0);
    return result;
}
INTERPOSE(fchmod)

int HOOK(fchmodat)(int dir, const char *path, mode_t mode, int flags) {
    int result = REAL(fchmodat)(dir, path, mode, flags);
    observe(dir, path, 0, 0, -1, 0, 0);
    return result;
}
INTERPOSE(fchmodat)
