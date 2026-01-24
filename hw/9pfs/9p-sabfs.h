/*
 * SABFS integration for virtio-9p
 *
 * This header provides SABFS-accelerated file operations for 9p.
 * When SABFS is available, file I/O bypasses Emscripten's syscall proxy.
 */

#ifndef QEMU_9P_SABFS_H
#define QEMU_9P_SABFS_H

#ifdef __EMSCRIPTEN__

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/*
 * Check if SABFS is available for a given path
 * Returns 1 if SABFS should handle this path, 0 otherwise
 */
int sabfs_should_handle(const char *path);

/*
 * SABFS file operations - these run directly in the worker thread
 * without going through Emscripten's syscall proxy
 */

int sabfs_open(const char *path, int flags, mode_t mode);
int sabfs_close(int fd);
ssize_t sabfs_pread(int fd, void *buf, size_t count, off_t offset);
ssize_t sabfs_pwrite(int fd, const void *buf, size_t count, off_t offset);
int sabfs_fstat(int fd, struct stat *st);
int sabfs_stat(const char *path, struct stat *st);

/*
 * Initialize SABFS (called once at startup)
 */
int sabfs_init(void);

/*
 * Check if SABFS is initialized and ready
 */
int sabfs_is_ready(void);

/*
 * FD mapping functions - map POSIX fd to SABFS fd
 */
void sabfs_fd_map_add(int posix_fd, int sabfs_fd);
void sabfs_fd_map_remove(int posix_fd);
int sabfs_fd_map_get(int posix_fd);

/*
 * Vectored I/O - these handle the iovec conversion
 */
ssize_t sabfs_preadv(int posix_fd, const struct iovec *iov, int iovcnt, off_t offset);
ssize_t sabfs_pwritev(int posix_fd, const struct iovec *iov, int iovcnt, off_t offset);

#else /* !__EMSCRIPTEN__ */

/* Stubs for non-Emscripten builds */
static inline int sabfs_should_handle(const char *path) { return 0; }
static inline int sabfs_init(void) { return -1; }
static inline int sabfs_is_ready(void) { return 0; }

#endif /* __EMSCRIPTEN__ */

#endif /* QEMU_9P_SABFS_H */
