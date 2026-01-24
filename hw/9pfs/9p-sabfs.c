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

/* Check if SABFS module is loaded and available */
EM_JS(int, sabfs_js_is_available, (void), {
    return (typeof SABFS !== 'undefined' &&
            typeof SABFS.stat === 'function') ? 1 : 0;
});

/* Check if SABFS is initialized with data */
EM_JS(int, sabfs_js_is_ready, (void), {
    if (typeof SABFS === 'undefined') return 0;
    try {
        const st = SABFS.stat('/pack');
        return st ? 1 : 0;
    } catch (e) {
        return 0;
    }
});

/* Open file in SABFS */
EM_JS(int, sabfs_js_open, (const char *path, int flags, int mode), {
    try {
        const pathStr = UTF8ToString(path);
        const fd = SABFS.open(pathStr, flags, mode);
        return fd;
    } catch (e) {
        console.error('[SABFS] open failed:', e);
        return -1;
    }
});

/* Close file in SABFS */
EM_JS(int, sabfs_js_close, (int fd), {
    try {
        return SABFS.close(fd);
    } catch (e) {
        return -1;
    }
});

/* Read from file at offset (pread) */
EM_JS(ssize_t, sabfs_js_pread, (int fd, void *buf, size_t count, double offset), {
    try {
        const buffer = new Uint8Array(HEAPU8.buffer, buf, count);
        return SABFS.pread(fd, buffer, count, offset);
    } catch (e) {
        console.error('[SABFS] pread failed:', e);
        return -1;
    }
});

/* Write to file at offset (pwrite) */
EM_JS(ssize_t, sabfs_js_pwrite, (int fd, const void *buf, size_t count, double offset), {
    try {
        const buffer = new Uint8Array(HEAPU8.buffer, buf, count);
        return SABFS.pwrite(fd, buffer, count, offset);
    } catch (e) {
        console.error('[SABFS] pwrite failed:', e);
        return -1;
    }
});

/* Stat file by path */
EM_JS(int, sabfs_js_stat, (const char *path,
                           uint32_t *mode,
                           uint32_t *size_lo, uint32_t *size_hi,
                           uint32_t *ino), {
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
        console.error('[SABFS] stat failed:', e);
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
 * FD mapping: maps POSIX fd to SABFS fd
 * This allows us to intercept I/O on files opened via SABFS
 */
#define SABFS_MAX_FDS 256
static int sabfs_fd_map[SABFS_MAX_FDS];  /* posix_fd -> sabfs_fd, -1 = not mapped */

static void sabfs_fd_map_init(void)
{
    for (int i = 0; i < SABFS_MAX_FDS; i++) {
        sabfs_fd_map[i] = -1;
    }
}

void sabfs_fd_map_add(int posix_fd, int sabfs_fd)
{
    if (posix_fd >= 0 && posix_fd < SABFS_MAX_FDS) {
        sabfs_fd_map[posix_fd] = sabfs_fd;
    }
}

void sabfs_fd_map_remove(int posix_fd)
{
    if (posix_fd >= 0 && posix_fd < SABFS_MAX_FDS) {
        if (sabfs_fd_map[posix_fd] >= 0) {
            sabfs_js_close(sabfs_fd_map[posix_fd]);
        }
        sabfs_fd_map[posix_fd] = -1;
    }
}

int sabfs_fd_map_get(int posix_fd)
{
    if (posix_fd >= 0 && posix_fd < SABFS_MAX_FDS) {
        return sabfs_fd_map[posix_fd];
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
