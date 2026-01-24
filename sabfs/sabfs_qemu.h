/*
 * SABFS - SharedArrayBuffer Filesystem for QEMU-wasm
 *
 * This header provides C functions to access SABFS from QEMU.
 * These functions bypass Emscripten's filesystem proxy by using
 * SharedArrayBuffer for direct memory access from worker threads.
 */

#ifndef SABFS_QEMU_H
#define SABFS_QEMU_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* File types */
#define SABFS_S_IFDIR  0040000
#define SABFS_S_IFREG  0100000

/* Open flags */
#define SABFS_O_RDONLY 0x0000
#define SABFS_O_WRONLY 0x0001
#define SABFS_O_RDWR   0x0002
#define SABFS_O_CREAT  0x0040
#define SABFS_O_TRUNC  0x0200
#define SABFS_O_APPEND 0x0400

/* Seek whence */
#define SABFS_SEEK_SET 0
#define SABFS_SEEK_CUR 1
#define SABFS_SEEK_END 2

/* Stat structure */
typedef struct {
    uint64_t ino;
    uint32_t mode;
    uint64_t size;
    uint32_t blocks;
    int is_directory;
    int is_file;
} sabfs_stat_t;

/* Directory entry */
typedef struct {
    char name[256];
    uint64_t ino;
    uint32_t type;
} sabfs_dirent_t;

/*
 * Initialize SABFS with given size
 * Must be called from main thread before workers start
 * Returns 0 on success, -1 on error
 */
int sabfs_init(size_t size_bytes);

/*
 * Attach to existing SABFS (for worker threads)
 * Returns 0 on success, -1 on error
 */
int sabfs_attach(void);

/*
 * Import a file from host buffer into SABFS
 * Returns 0 on success, -1 on error
 */
int sabfs_import_file(const char *path, const void *data, size_t size);

/*
 * stat - get file status
 * Returns 0 on success, -1 on error
 */
int sabfs_stat(const char *path, sabfs_stat_t *st);

/*
 * open - open a file
 * Returns file descriptor on success, -1 on error
 */
int sabfs_open(const char *path, int flags, int mode);

/*
 * close - close file descriptor
 * Returns 0 on success, -1 on error
 */
int sabfs_close(int fd);

/*
 * read - read from file at current position
 * Returns bytes read, 0 on EOF, -1 on error
 */
ssize_t sabfs_read(int fd, void *buf, size_t count);

/*
 * write - write to file at current position
 * Returns bytes written, -1 on error
 */
ssize_t sabfs_write(int fd, const void *buf, size_t count);

/*
 * pread - read at offset without changing position
 * Returns bytes read, -1 on error
 */
ssize_t sabfs_pread(int fd, void *buf, size_t count, off_t offset);

/*
 * pwrite - write at offset without changing position
 * Returns bytes written, -1 on error
 */
ssize_t sabfs_pwrite(int fd, const void *buf, size_t count, off_t offset);

/*
 * lseek - reposition file offset
 * Returns new position, -1 on error
 */
off_t sabfs_lseek(int fd, off_t offset, int whence);

/*
 * mkdir - create directory
 * Returns 0 on success, -1 on error
 */
int sabfs_mkdir(const char *path, int mode);

/*
 * readdir - read directory entries
 * Returns number of entries read, -1 on error
 * Caller must free entries with sabfs_free_dirents()
 */
int sabfs_readdir(const char *path, sabfs_dirent_t **entries);

/*
 * Free directory entries
 */
void sabfs_free_dirents(sabfs_dirent_t *entries);

/*
 * Check if SABFS is initialized and available
 */
int sabfs_is_available(void);

#ifdef __cplusplus
}
#endif

#endif /* SABFS_QEMU_H */
