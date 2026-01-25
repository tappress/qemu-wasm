/*
 * SABFS integration for virtio-9p
 *
 * Provides SABFS-accelerated file operations that bypass Emscripten's
 * syscall proxy, running directly in the worker thread.
 */

#ifdef __EMSCRIPTEN__

#include "qemu/osdep.h"
#include "9p-sabfs.h"
#include <emscripten.h>
#include <string.h>
#include <errno.h>

/* Path prefix that SABFS handles */
#define SABFS_PREFIX "/pack"
#define SABFS_PREFIX_LEN 5

/*
 * ELF Cache - Cache executable files for fast execve
 *
 * When execve is detected, we preload the file from SABFS/9p into
 * a local cache. Subsequent reads during the kernel's ELF loading
 * are served from this cache, avoiding slow 9p round-trips.
 */
#define ELF_CACHE_MAX_FILES 32
#define ELF_CACHE_MAX_FILE_SIZE (16 * 1024 * 1024)  /* 16MB per file */

typedef struct ElfCacheEntry {
    char path[256];
    uint8_t *data;
    size_t size;
    uint32_t mode;
    uint32_t refcount;
    int active;
} ElfCacheEntry;

static ElfCacheEntry elf_cache[ELF_CACHE_MAX_FILES];
static int elf_cache_initialized = 0;

/* Virtual FD for cached files: uses ELF_CACHE_FD_BASE from header */
#define ELF_CACHE_MAX_FDS 256

typedef struct ElfCacheFd {
    int cache_idx;      /* Index into elf_cache */
    off_t offset;       /* Current file offset */
    int active;
} ElfCacheFd;

static ElfCacheFd elf_cache_fds[ELF_CACHE_MAX_FDS];
static int elf_cache_next_fd = ELF_CACHE_FD_BASE;

static void elf_cache_init(void)
{
    if (elf_cache_initialized) return;

    for (int i = 0; i < ELF_CACHE_MAX_FILES; i++) {
        elf_cache[i].path[0] = '\0';
        elf_cache[i].data = NULL;
        elf_cache[i].size = 0;
        elf_cache[i].active = 0;
    }
    for (int i = 0; i < ELF_CACHE_MAX_FDS; i++) {
        elf_cache_fds[i].active = 0;
    }
    elf_cache_initialized = 1;
}

/* Find cache entry by path */
static int elf_cache_find(const char *path)
{
    for (int i = 0; i < ELF_CACHE_MAX_FILES; i++) {
        if (elf_cache[i].active && strcmp(elf_cache[i].path, path) == 0) {
            return i;
        }
    }
    return -1;
}

/* Find free cache slot */
static int elf_cache_find_free(void)
{
    for (int i = 0; i < ELF_CACHE_MAX_FILES; i++) {
        if (!elf_cache[i].active) {
            return i;
        }
    }
    /* Evict first entry with refcount 0 */
    for (int i = 0; i < ELF_CACHE_MAX_FILES; i++) {
        if (elf_cache[i].refcount == 0) {
            if (elf_cache[i].data) {
                free(elf_cache[i].data);
                elf_cache[i].data = NULL;
            }
            elf_cache[i].active = 0;
            return i;
        }
    }
    return -1;
}

/*
 * Preload file using POSIX I/O - this goes through Emscripten's syscalls
 * which properly access the 9p-mounted container filesystem.
 *
 * The 9p export directory is /mnt/wasi1 (container rootfs).
 * Guest paths like /bin/ls map to host /mnt/wasi1/bin/ls.
 */
#include <fcntl.h>
#include <unistd.h>

/*
 * SABFS JavaScript bridge functions
 * These EM_JS functions call into the globalThis.SABFS JavaScript object
 * to access the SharedArrayBuffer-backed filesystem.
 */

/* Check if SABFS module is loaded and available */
EM_JS(int, sabfs_js_is_available, (void), {
    const SABFS = globalThis.SABFS;
    const available = (SABFS && typeof SABFS.stat === 'function') ? 1 : 0;
    return available;
});

/* Stat file by path */
EM_JS(int, sabfs_js_stat, (const char *path,
                           uint32_t *mode,
                           uint32_t *size_lo, uint32_t *size_hi,
                           uint32_t *ino), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    try {
        const pathStr = UTF8ToString(path);
        const st = SABFS.stat(pathStr);
        if (!st) return -1;

        HEAPU32[mode >> 2] = st.mode;
        HEAPU32[size_lo >> 2] = st.size & 0xFFFFFFFF;
        HEAPU32[size_hi >> 2] = Math.floor(st.size / 0x100000000);
        HEAPU32[ino >> 2] = st.ino & 0xFFFFFFFF;

        return 0;
    } catch (e) {
        return -1;
    }
});

/* Open file in SABFS */
EM_JS(int, sabfs_js_open, (const char *path, int flags, int mode), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    try {
        const pathStr = UTF8ToString(path);
        const fd = SABFS.open(pathStr, flags, mode);
        return fd;
    } catch (e) {
        return -1;
    }
});

/* Read from file at offset (pread) */
EM_JS(ssize_t, sabfs_js_pread, (int fd, void *buf, size_t count, double offset), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    try {
        const buffer = new Uint8Array(HEAPU8.buffer, buf, count);
        return SABFS.pread(fd, buffer, count, offset);
    } catch (e) {
        return -1;
    }
});

/* Close file in SABFS */
EM_JS(int, sabfs_js_close, (int fd), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    try {
        return SABFS.close(fd);
    } catch (e) {
        return -1;
    }
});

/* Log function for preload status */
EM_JS(void, elf_cache_log, (const char *msg), {
    console.log('[ELF-Cache]', UTF8ToString(msg));
});

/*
 * Try to preload file from SABFS directly.
 * SABFS stores files under /pack prefix (e.g., /bin/busybox -> /pack/bin/busybox)
 *
 * Returns bytes read on success, -1 if SABFS not available or file not found.
 */
static int elf_cache_sabfs_preload(const char *path, void *buf, size_t max_size)
{
    char sabfs_path[512];
    char log_msg[256];
    int sabfs_fd;
    ssize_t bytes_read;

    /* Check if SABFS is available */
    if (!sabfs_js_is_available()) {
        return -1;
    }

    /* Map guest path to SABFS path: /bin/busybox -> /pack/bin/busybox */
    snprintf(sabfs_path, sizeof(sabfs_path), "/pack%s", path);

    snprintf(log_msg, sizeof(log_msg), "SABFS preload: %s -> %s", path, sabfs_path);
    elf_cache_log(log_msg);

    /* Stat via SABFS */
    uint32_t mode, size_lo, size_hi, ino;
    if (sabfs_js_stat(sabfs_path, &mode, &size_lo, &size_hi, &ino) < 0) {
        snprintf(log_msg, sizeof(log_msg), "SABFS stat failed: %s", sabfs_path);
        elf_cache_log(log_msg);
        return -1;
    }

    size_t file_size = size_lo + ((uint64_t)size_hi << 32);
    if (file_size > max_size) {
        snprintf(log_msg, sizeof(log_msg), "File too large: %lu > %lu",
                 (unsigned long)file_size, (unsigned long)max_size);
        elf_cache_log(log_msg);
        return -1;
    }

    /* Open via SABFS */
    sabfs_fd = sabfs_js_open(sabfs_path, O_RDONLY, 0);
    if (sabfs_fd < 0) {
        snprintf(log_msg, sizeof(log_msg), "SABFS open failed: %s", sabfs_path);
        elf_cache_log(log_msg);
        return -1;
    }

    /* Read entire file from SABFS */
    bytes_read = sabfs_js_pread(sabfs_fd, buf, file_size, 0);
    sabfs_js_close(sabfs_fd);

    if (bytes_read < 0) {
        snprintf(log_msg, sizeof(log_msg), "SABFS read failed: %s", sabfs_path);
        elf_cache_log(log_msg);
        return -1;
    }

    snprintf(log_msg, sizeof(log_msg), "SABFS loaded %ld bytes from %s",
             (long)bytes_read, sabfs_path);
    elf_cache_log(log_msg);

    return (int)bytes_read;
}

static int elf_cache_posix_preload(const char *path, void *buf, size_t max_size)
{
    char host_path[512];
    char log_msg[256];
    struct stat st;
    int fd;
    ssize_t total_read = 0;
    ssize_t bytes_read;

    /* Try SABFS first - use original path without /mnt/wasi1 prefix */
    int sabfs_result = elf_cache_sabfs_preload(path, buf, max_size);
    if (sabfs_result >= 0) {
        return sabfs_result;
    }

    /* Fall back to POSIX I/O for non-SABFS files */
    /* Map guest path to host path:
     * Guest /bin/ls -> Host /mnt/wasi1/bin/ls
     * Guest /usr/bin/env -> Host /mnt/wasi1/usr/bin/env
     */
    if (strncmp(path, "/bin/", 5) == 0 ||
        strncmp(path, "/lib/", 5) == 0 ||
        strncmp(path, "/usr/", 5) == 0 ||
        strncmp(path, "/sbin/", 6) == 0 ||
        strncmp(path, "/etc/", 5) == 0 ||
        strncmp(path, "/opt/", 5) == 0) {
        snprintf(host_path, sizeof(host_path), "/mnt/wasi1%s", path);
    } else {
        /* For other paths, try direct */
        strncpy(host_path, path, sizeof(host_path) - 1);
        host_path[sizeof(host_path) - 1] = '\0';
    }

    snprintf(log_msg, sizeof(log_msg), "POSIX preload: %s -> %s", path, host_path);
    elf_cache_log(log_msg);

    /* Stat to get file size */
    if (stat(host_path, &st) < 0) {
        snprintf(log_msg, sizeof(log_msg), "stat failed: %s (errno=%d)", host_path, errno);
        elf_cache_log(log_msg);
        return -1;
    }

    if ((size_t)st.st_size > max_size) {
        snprintf(log_msg, sizeof(log_msg), "File too large: %ld > %lu", (long)st.st_size, (unsigned long)max_size);
        elf_cache_log(log_msg);
        return -1;
    }

    /* Open file */
    fd = open(host_path, O_RDONLY);
    if (fd < 0) {
        snprintf(log_msg, sizeof(log_msg), "open failed: %s (errno=%d)", host_path, errno);
        elf_cache_log(log_msg);
        return -1;
    }

    /* Read entire file */
    while (total_read < st.st_size) {
        bytes_read = read(fd, (uint8_t *)buf + total_read, st.st_size - total_read);
        if (bytes_read < 0) {
            if (errno == EINTR) continue;
            snprintf(log_msg, sizeof(log_msg), "read failed at %ld (errno=%d)", (long)total_read, errno);
            elf_cache_log(log_msg);
            close(fd);
            return -1;
        }
        if (bytes_read == 0) break;  /* EOF */
        total_read += bytes_read;
    }

    close(fd);

    snprintf(log_msg, sizeof(log_msg), "POSIX loaded %ld bytes from %s", (long)total_read, host_path);
    elf_cache_log(log_msg);

    return (int)total_read;
}

/* Public API: Preload file into cache */
int elf_cache_preload(const char *path)
{
    elf_cache_init();

    /* Already cached? */
    if (elf_cache_find(path) >= 0) {
        return 0;
    }

    /* Find free slot */
    int idx = elf_cache_find_free();
    if (idx < 0) {
        fprintf(stderr, "[ELF-Cache] No free cache slots\n");
        return -1;
    }

    /* Allocate buffer for file data */
    uint8_t *buf = malloc(ELF_CACHE_MAX_FILE_SIZE);
    if (!buf) {
        fprintf(stderr, "[ELF-Cache] Failed to allocate buffer\n");
        return -1;
    }

    /* Load file using POSIX I/O (goes through 9p for container files) */
    int size = elf_cache_posix_preload(path, buf, ELF_CACHE_MAX_FILE_SIZE);
    if (size < 0) {
        free(buf);
        return -1;
    }

    /* Shrink buffer to actual size */
    uint8_t *data = realloc(buf, size);
    if (!data) {
        data = buf;  /* Keep original if realloc fails */
    }

    /* Store in cache */
    strncpy(elf_cache[idx].path, path, sizeof(elf_cache[idx].path) - 1);
    elf_cache[idx].path[sizeof(elf_cache[idx].path) - 1] = '\0';
    elf_cache[idx].data = data;
    elf_cache[idx].size = size;
    elf_cache[idx].mode = 0100755;  /* Regular file, executable */
    elf_cache[idx].refcount = 0;
    elf_cache[idx].active = 1;

    fprintf(stderr, "[ELF-Cache] Cached %s (%d bytes)\n", path, size);
    return 0;
}

/* Check if file is in cache */
int elf_cache_is_cached(const char *path)
{
    elf_cache_init();
    return elf_cache_find(path) >= 0;
}

/* Check if fd is an ELF cache fd */
int elf_cache_is_cache_fd(int fd)
{
    if (fd < ELF_CACHE_FD_BASE) return 0;
    int idx = fd - ELF_CACHE_FD_BASE;
    if (idx >= ELF_CACHE_MAX_FDS) return 0;
    return elf_cache_fds[idx].active;
}

/* Open cached file */
int elf_cache_open(const char *path)
{
    elf_cache_init();

    int cache_idx = elf_cache_find(path);
    if (cache_idx < 0) {
        return -1;
    }

    /* Find free fd slot */
    int fd_idx = elf_cache_next_fd - ELF_CACHE_FD_BASE;
    if (fd_idx >= ELF_CACHE_MAX_FDS) {
        /* Wrap around and find first free */
        for (fd_idx = 0; fd_idx < ELF_CACHE_MAX_FDS; fd_idx++) {
            if (!elf_cache_fds[fd_idx].active) break;
        }
        if (fd_idx >= ELF_CACHE_MAX_FDS) {
            fprintf(stderr, "[ELF-Cache] No free fd slots\n");
            return -1;
        }
    }

    int fd = ELF_CACHE_FD_BASE + fd_idx;
    elf_cache_fds[fd_idx].cache_idx = cache_idx;
    elf_cache_fds[fd_idx].offset = 0;
    elf_cache_fds[fd_idx].active = 1;
    elf_cache[cache_idx].refcount++;

    elf_cache_next_fd = fd + 1;
    fprintf(stderr, "[ELF-Cache] Opened %s as fd %d\n", path, fd);
    return fd;
}

/* Read from cached file (pread) */
ssize_t elf_cache_pread(int fd, void *buf, size_t count, off_t offset)
{
    if (!elf_cache_is_cache_fd(fd)) {
        return -1;
    }

    int fd_idx = fd - ELF_CACHE_FD_BASE;
    int cache_idx = elf_cache_fds[fd_idx].cache_idx;

    if (!elf_cache[cache_idx].active) {
        return -1;
    }

    size_t file_size = elf_cache[cache_idx].size;
    if (offset >= (off_t)file_size) {
        return 0;  /* EOF */
    }

    size_t available = file_size - offset;
    size_t to_read = count < available ? count : available;

    memcpy(buf, elf_cache[cache_idx].data + offset, to_read);
    return to_read;
}

/* Read from cached file (sequential) */
ssize_t elf_cache_read(int fd, void *buf, size_t count)
{
    if (!elf_cache_is_cache_fd(fd)) {
        return -1;
    }

    int fd_idx = fd - ELF_CACHE_FD_BASE;
    ssize_t ret = elf_cache_pread(fd, buf, count, elf_cache_fds[fd_idx].offset);
    if (ret > 0) {
        elf_cache_fds[fd_idx].offset += ret;
    }
    return ret;
}

/* Seek on cached file */
off_t elf_cache_lseek(int fd, off_t offset, int whence)
{
    if (!elf_cache_is_cache_fd(fd)) {
        return -1;
    }

    int fd_idx = fd - ELF_CACHE_FD_BASE;
    int cache_idx = elf_cache_fds[fd_idx].cache_idx;
    size_t file_size = elf_cache[cache_idx].size;
    off_t new_offset;

    switch (whence) {
        case SEEK_SET:
            new_offset = offset;
            break;
        case SEEK_CUR:
            new_offset = elf_cache_fds[fd_idx].offset + offset;
            break;
        case SEEK_END:
            new_offset = file_size + offset;
            break;
        default:
            return -1;
    }

    if (new_offset < 0) {
        return -1;
    }

    elf_cache_fds[fd_idx].offset = new_offset;
    return new_offset;
}

/* Get file stat from cache */
int elf_cache_fstat(int fd, struct stat *st)
{
    if (!elf_cache_is_cache_fd(fd)) {
        return -1;
    }

    int fd_idx = fd - ELF_CACHE_FD_BASE;
    int cache_idx = elf_cache_fds[fd_idx].cache_idx;

    memset(st, 0, sizeof(*st));
    st->st_mode = elf_cache[cache_idx].mode;
    st->st_size = elf_cache[cache_idx].size;
    st->st_ino = 1000000 + cache_idx;
    st->st_nlink = 1;
    st->st_blksize = 4096;
    st->st_blocks = (st->st_size + 511) / 512;

    return 0;
}

/* Stat by path from cache */
int elf_cache_stat(const char *path, struct stat *st)
{
    elf_cache_init();

    int cache_idx = elf_cache_find(path);
    if (cache_idx < 0) {
        return -1;
    }

    memset(st, 0, sizeof(*st));
    st->st_mode = elf_cache[cache_idx].mode;
    st->st_size = elf_cache[cache_idx].size;
    st->st_ino = 1000000 + cache_idx;
    st->st_nlink = 1;
    st->st_blksize = 4096;
    st->st_blocks = (st->st_size + 511) / 512;

    return 0;
}

/* Close cached file */
int elf_cache_close(int fd)
{
    if (!elf_cache_is_cache_fd(fd)) {
        return -1;
    }

    int fd_idx = fd - ELF_CACHE_FD_BASE;
    int cache_idx = elf_cache_fds[fd_idx].cache_idx;

    elf_cache_fds[fd_idx].active = 0;
    if (elf_cache[cache_idx].refcount > 0) {
        elf_cache[cache_idx].refcount--;
    }

    return 0;
}

/* Vectored read from cache */
ssize_t elf_cache_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    if (!elf_cache_is_cache_fd(fd)) {
        return -1;
    }

    int fd_idx = fd - ELF_CACHE_FD_BASE;
    int cache_idx = elf_cache_fds[fd_idx].cache_idx;

    if (!elf_cache[cache_idx].active) {
        return -1;
    }

    size_t file_size = elf_cache[cache_idx].size;
    if (offset >= (off_t)file_size) {
        return 0;  /* EOF */
    }

    size_t total_read = 0;
    off_t cur_offset = offset;

    for (int i = 0; i < iovcnt && cur_offset < (off_t)file_size; i++) {
        size_t available = file_size - cur_offset;
        size_t to_read = iov[i].iov_len < available ? iov[i].iov_len : available;

        memcpy(iov[i].iov_base, elf_cache[cache_idx].data + cur_offset, to_read);
        total_read += to_read;
        cur_offset += to_read;

        if (to_read < iov[i].iov_len) {
            break;  /* EOF reached */
        }
    }

    return total_read;
}

/* Check if SABFS is initialized with data */
EM_JS(int, sabfs_js_is_ready, (void), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) {
        console.log('[SABFS C] is_ready: SABFS undefined');
        return 0;
    }
    try {
        const st = SABFS.stat('/pack');
        const ready = st ? 1 : 0;
        console.log('[SABFS C] is_ready:', ready, 'stat:', st);
        return ready;
    } catch (e) {
        console.log('[SABFS C] is_ready: error', e.message);
        return 0;
    }
});

/* Write to file at offset (pwrite) */
EM_JS(ssize_t, sabfs_js_pwrite, (int fd, const void *buf, size_t count, double offset), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    try {
        const buffer = new Uint8Array(HEAPU8.buffer, buf, count);
        return SABFS.pwrite(fd, buffer, count, offset);
    } catch (e) {
        console.error('[SABFS] pwrite failed:', e);
        return -1;
    }
});

/* Stat file by fd */
EM_JS(int, sabfs_js_fstat, (int fd,
                            uint32_t *mode,
                            uint32_t *size_lo, uint32_t *size_hi,
                            uint32_t *ino), {
    try {
        /* SABFS doesn't have fstat, so we need to track fd→path mapping */
        /* For now, return error - caller should use stat() instead */
        return -1;
    } catch (e) {
        return -1;
    }
});

/* Static initialization flag */
static int sabfs_initialized = 0;
static int sabfs_available = 0;

/*
 * FD mapping: maps virtual fd to SABFS fd
 * Handles both regular POSIX fds (0-255) and SABFS-only fds (20000+)
 */
#define SABFS_MAX_FDS 256
static int sabfs_fd_map[SABFS_MAX_FDS];  /* index -> sabfs_fd, -1 = not mapped */

static void sabfs_fd_map_init(void)
{
    for (int i = 0; i < SABFS_MAX_FDS; i++) {
        sabfs_fd_map[i] = -1;
    }
}

/* Convert virtual fd to array index */
static int sabfs_fd_to_index(int fd)
{
    if (fd >= SABFS_FD_BASE && fd < ELF_CACHE_FD_BASE) {
        /* SABFS-only FD: offset to get index */
        return fd - SABFS_FD_BASE;
    } else if (fd >= 0 && fd < SABFS_MAX_FDS) {
        /* Regular POSIX fd */
        return fd;
    }
    return -1;
}

void sabfs_fd_map_add(int posix_fd, int sabfs_fd)
{
    int idx = sabfs_fd_to_index(posix_fd);
    if (idx >= 0 && idx < SABFS_MAX_FDS) {
        sabfs_fd_map[idx] = sabfs_fd;
    }
}

void sabfs_fd_map_remove(int posix_fd)
{
    int idx = sabfs_fd_to_index(posix_fd);
    if (idx >= 0 && idx < SABFS_MAX_FDS) {
        if (sabfs_fd_map[idx] >= 0) {
            sabfs_js_close(sabfs_fd_map[idx]);
        }
        sabfs_fd_map[idx] = -1;
    }
}

int sabfs_fd_map_get(int posix_fd)
{
    int idx = sabfs_fd_to_index(posix_fd);
    if (idx >= 0 && idx < SABFS_MAX_FDS) {
        return sabfs_fd_map[idx];
    }
    return -1;
}

/* Vectored I/O helper: convert iovec to linear buffer and call SABFS */
ssize_t sabfs_preadv(int posix_fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    int sabfs_fd = sabfs_fd_map_get(posix_fd);
    if (sabfs_fd < 0) {
        errno = EBADF;
        return -1;
    }

    /* Calculate total size */
    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        total += iov[i].iov_len;
    }

    /* Allocate temp buffer */
    uint8_t *buf = malloc(total);
    if (!buf) {
        errno = ENOMEM;
        return -1;
    }

    /* Read from SABFS */
    ssize_t ret = sabfs_js_pread(sabfs_fd, buf, total, (double)offset);

    if (ret > 0) {
        /* Scatter to iovec */
        size_t copied = 0;
        for (int i = 0; i < iovcnt && copied < (size_t)ret; i++) {
            size_t chunk = (ret - copied < iov[i].iov_len) ?
                           (ret - copied) : iov[i].iov_len;
            memcpy(iov[i].iov_base, buf + copied, chunk);
            copied += chunk;
        }
    }

    free(buf);
    return ret;
}

ssize_t sabfs_pwritev(int posix_fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    int sabfs_fd = sabfs_fd_map_get(posix_fd);
    if (sabfs_fd < 0) {
        errno = EBADF;
        return -1;
    }

    /* Calculate total size */
    size_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        total += iov[i].iov_len;
    }

    /* Allocate temp buffer and gather from iovec */
    uint8_t *buf = malloc(total);
    if (!buf) {
        errno = ENOMEM;
        return -1;
    }

    size_t copied = 0;
    for (int i = 0; i < iovcnt; i++) {
        memcpy(buf + copied, iov[i].iov_base, iov[i].iov_len);
        copied += iov[i].iov_len;
    }

    /* Write to SABFS */
    ssize_t ret = sabfs_js_pwrite(sabfs_fd, buf, total, (double)offset);

    free(buf);
    return ret;
}

int sabfs_should_handle(const char *path)
{
    if (!sabfs_available) {
        return 0;
    }
    if (!path) {
        return 0;
    }
    /* Handle paths starting with /pack */
    return strncmp(path, SABFS_PREFIX, SABFS_PREFIX_LEN) == 0;
}

int sabfs_init(void)
{
    if (sabfs_initialized) {
        return sabfs_available ? 0 : -1;
    }

    sabfs_initialized = 1;
    sabfs_fd_map_init();
    sabfs_available = sabfs_js_is_available();

    if (sabfs_available) {
        fprintf(stderr, "[SABFS] Available and ready\n");
    } else {
        fprintf(stderr, "[SABFS] Not available, using standard I/O\n");
    }

    return sabfs_available ? 0 : -1;
}

int sabfs_is_ready(void)
{
    if (!sabfs_initialized) {
        sabfs_init();
    }
    return sabfs_available && sabfs_js_is_ready();
}

int sabfs_open(const char *path, int flags, mode_t mode)
{
    if (!sabfs_available) {
        errno = ENOENT;
        return -1;
    }
    int fd = sabfs_js_open(path, flags, mode);
    if (fd < 0) {
        errno = ENOENT;
    }
    return fd;
}

int sabfs_close(int fd)
{
    if (!sabfs_available) {
        errno = EBADF;
        return -1;
    }
    return sabfs_js_close(fd);
}

ssize_t sabfs_pread(int fd, void *buf, size_t count, off_t offset)
{
    if (!sabfs_available) {
        errno = EBADF;
        return -1;
    }
    ssize_t ret = sabfs_js_pread(fd, buf, count, (double)offset);
    if (ret < 0) {
        errno = EIO;
    }
    return ret;
}

ssize_t sabfs_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    if (!sabfs_available) {
        errno = EBADF;
        return -1;
    }
    ssize_t ret = sabfs_js_pwrite(fd, buf, count, (double)offset);
    if (ret < 0) {
        errno = EIO;
    }
    return ret;
}

int sabfs_stat(const char *path, struct stat *st)
{
    if (!sabfs_available) {
        errno = ENOENT;
        return -1;
    }

    uint32_t mode, size_lo, size_hi, ino;
    int ret = sabfs_js_stat(path, &mode, &size_lo, &size_hi, &ino);

    if (ret == 0) {
        memset(st, 0, sizeof(*st));
        st->st_mode = mode;
        st->st_size = size_lo + ((uint64_t)size_hi << 32);
        st->st_ino = ino;
        st->st_nlink = 1;
        st->st_blksize = 4096;
        st->st_blocks = (st->st_size + 511) / 512;
    } else {
        errno = ENOENT;
    }

    return ret;
}

int sabfs_fstat(int fd, struct stat *st)
{
    /* Not implemented - SABFS doesn't track fd→path mapping */
    errno = EBADF;
    return -1;
}

#endif /* __EMSCRIPTEN__ */
