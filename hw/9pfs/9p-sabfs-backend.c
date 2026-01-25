/*
 * 9p SABFS backend - SharedArrayBuffer Filesystem
 *
 * This backend serves files from JavaScript's SABFS instead of the host
 * filesystem. All operations are synchronous memory accesses without
 * syscall proxying overhead.
 *
 * For Emscripten/browser builds only.
 */

#ifdef __EMSCRIPTEN__

#include "qemu/osdep.h"
#include "9p.h"
#include "9p-local.h"
#include "qapi/error.h"
#include <emscripten.h>
#include <errno.h>
#include <string.h>

/* ========== JavaScript SABFS bindings ========== */

EM_JS(int, sabfs_be_js_stat, (const char *path,
                           uint32_t *mode, uint32_t *nlink,
                           uint32_t *uid, uint32_t *gid,
                           uint32_t *size_lo, uint32_t *size_hi,
                           uint32_t *atime, uint32_t *mtime, uint32_t *ctime,
                           uint32_t *ino, uint32_t *blocks), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    const st = SABFS.stat(pathStr);
    if (!st) return -1;

    HEAPU32[mode >> 2] = st.mode;
    HEAPU32[nlink >> 2] = st.nlink || 1;
    HEAPU32[uid >> 2] = st.uid || 0;
    HEAPU32[gid >> 2] = st.gid || 0;
    HEAPU32[size_lo >> 2] = st.size & 0xFFFFFFFF;
    HEAPU32[size_hi >> 2] = Math.floor(st.size / 0x100000000);
    HEAPU32[atime >> 2] = st.atime || 0;
    HEAPU32[mtime >> 2] = st.mtime || 0;
    HEAPU32[ctime >> 2] = st.ctime || 0;
    HEAPU32[ino >> 2] = st.ino;
    HEAPU32[blocks >> 2] = st.blocks || 0;
    return 0;
});

EM_JS(int, sabfs_be_js_lstat, (const char *path,
                            uint32_t *mode, uint32_t *nlink,
                            uint32_t *uid, uint32_t *gid,
                            uint32_t *size_lo, uint32_t *size_hi,
                            uint32_t *atime, uint32_t *mtime, uint32_t *ctime,
                            uint32_t *ino, uint32_t *blocks), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    const st = SABFS.lstat ? SABFS.lstat(pathStr) : SABFS.stat(pathStr);
    if (!st) return -1;

    HEAPU32[mode >> 2] = st.mode;
    HEAPU32[nlink >> 2] = st.nlink || 1;
    HEAPU32[uid >> 2] = st.uid || 0;
    HEAPU32[gid >> 2] = st.gid || 0;
    HEAPU32[size_lo >> 2] = st.size & 0xFFFFFFFF;
    HEAPU32[size_hi >> 2] = Math.floor(st.size / 0x100000000);
    HEAPU32[atime >> 2] = st.atime || 0;
    HEAPU32[mtime >> 2] = st.mtime || 0;
    HEAPU32[ctime >> 2] = st.ctime || 0;
    HEAPU32[ino >> 2] = st.ino;
    HEAPU32[blocks >> 2] = st.blocks || 0;
    return 0;
});

EM_JS(int, sabfs_be_js_open, (const char *path, int flags, int mode), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    return SABFS.open(pathStr, flags, mode);
});

EM_JS(int, sabfs_be_js_close, (int fd), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    return SABFS.close(fd);
});

EM_JS(ssize_t, sabfs_be_js_pread, (int fd, void *buf, size_t count, double offset), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const buffer = new Uint8Array(count);
    const ret = SABFS.pread(fd, buffer, count, offset);
    if (ret > 0) {
        HEAPU8.set(buffer.subarray(0, ret), buf);
    }
    return ret;
});

EM_JS(ssize_t, sabfs_be_js_pwrite, (int fd, const void *buf, size_t count, double offset), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const buffer = new Uint8Array(HEAPU8.buffer, buf, count);
    return SABFS.pwrite(fd, buffer, count, offset);
});

EM_JS(int, sabfs_be_js_mkdir, (const char *path, int mode), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    return SABFS.mkdir(pathStr, mode);
});

EM_JS(int, sabfs_be_js_rmdir, (const char *path), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    return SABFS.rmdir(pathStr);
});

EM_JS(int, sabfs_be_js_unlink, (const char *path), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    return SABFS.unlink(pathStr);
});

EM_JS(int, sabfs_be_js_rename, (const char *oldpath, const char *newpath), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const oldStr = UTF8ToString(oldpath);
    const newStr = UTF8ToString(newpath);
    return SABFS.rename(oldStr, newStr);
});

EM_JS(int, sabfs_be_js_symlink, (const char *target, const char *linkpath), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const targetStr = UTF8ToString(target);
    const linkStr = UTF8ToString(linkpath);
    return SABFS.symlink(targetStr, linkStr);
});

EM_JS(int, sabfs_be_js_readlink, (const char *path, char *buf, size_t bufsiz), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    const target = SABFS.readlink(pathStr);
    if (!target) return -1;

    const bytes = new TextEncoder().encode(target);
    const len = Math.min(bytes.length, bufsiz);
    HEAPU8.set(bytes.subarray(0, len), buf);
    return len;
});

EM_JS(int, sabfs_be_js_link, (const char *oldpath, const char *newpath), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const oldStr = UTF8ToString(oldpath);
    const newStr = UTF8ToString(newpath);
    return SABFS.link(oldStr, newStr);
});

EM_JS(int, sabfs_be_js_chmod, (const char *path, int mode), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    return SABFS.chmod(pathStr, mode);
});

EM_JS(int, sabfs_be_js_chown, (const char *path, int uid, int gid), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    return SABFS.chown(pathStr, uid, gid);
});

EM_JS(int, sabfs_be_js_truncate, (const char *path, double length), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    return SABFS.truncate(pathStr, length);
});

EM_JS(int, sabfs_be_js_utimes, (const char *path, double atime, double mtime), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    return SABFS.utimes(pathStr, atime, mtime);
});

/* Directory reading - returns JSON array of entries */
EM_JS(int, sabfs_be_js_readdir_count, (const char *path), {
    const SABFS = globalThis.SABFS;
    if (!SABFS) return -1;
    const pathStr = UTF8ToString(path);
    const entries = SABFS.readdir(pathStr);
    if (!entries) return -1;
    // Store entries for subsequent calls
    globalThis._sabfs_readdir_entries = entries;
    return entries.length;
});

EM_JS(int, sabfs_be_js_readdir_entry, (int idx, char *name, size_t name_size, uint32_t *ino, uint32_t *type), {
    const entries = globalThis._sabfs_readdir_entries;
    if (!entries || idx >= entries.length) return -1;

    const entry = entries[idx];
    const nameBytes = new TextEncoder().encode(entry.name);
    const len = Math.min(nameBytes.length, name_size - 1);
    HEAPU8.set(nameBytes.subarray(0, len), name);
    HEAPU8[name + len] = 0;
    HEAPU32[ino >> 2] = entry.ino;
    HEAPU32[type >> 2] = entry.type || 0;
    return 0;
});

EM_JS(int, sabfs_be_js_statfs, (uint32_t *bsize, uint32_t *blocks, uint32_t *bfree,
                             uint32_t *files, uint32_t *ffree), {
    const SABFS = globalThis.SABFS;
    if (!SABFS || !SABFS.statfs) return -1;
    const st = SABFS.statfs();
    if (!st) return -1;

    HEAPU32[bsize >> 2] = st.bsize || 4096;
    HEAPU32[blocks >> 2] = st.blocks || 0;
    HEAPU32[bfree >> 2] = st.bfree || 0;
    HEAPU32[files >> 2] = st.files || 0;
    HEAPU32[ffree >> 2] = st.ffree || 0;
    return 0;
});

EM_JS(int, sabfs_be_js_is_available, (void), {
    const SABFS = globalThis.SABFS;
    return (SABFS && SABFS.stat) ? 1 : 0;
});

/* ========== 9p Backend Implementation ========== */

typedef struct SabfsFileState {
    int fd;
    char path[PATH_MAX];
} SabfsFileState;

typedef struct SabfsDirState {
    char path[PATH_MAX];
    int count;
    int pos;
} SabfsDirState;

static int sabfs_init(FsContext *ctx, Error **errp)
{
    if (!sabfs_be_js_is_available()) {
        error_setg(errp, "SABFS not available");
        return -1;
    }
    return 0;
}

static void sabfs_cleanup(FsContext *ctx)
{
    /* Nothing to clean up */
}

static int sabfs_lstat(FsContext *ctx, V9fsPath *fs_path, struct stat *stbuf)
{
    uint32_t mode, nlink, uid, gid, size_lo, size_hi;
    uint32_t atime, mtime, ctime, ino, blocks;

    int ret = sabfs_be_js_lstat(fs_path->data, &mode, &nlink, &uid, &gid,
                              &size_lo, &size_hi, &atime, &mtime, &ctime,
                              &ino, &blocks);
    if (ret < 0) {
        errno = ENOENT;
        return -1;
    }

    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode = mode;
    stbuf->st_nlink = nlink;
    stbuf->st_uid = uid;
    stbuf->st_gid = gid;
    stbuf->st_size = size_lo + ((uint64_t)size_hi << 32);
    stbuf->st_atime = atime;
    stbuf->st_mtime = mtime;
    stbuf->st_ctime = ctime;
    stbuf->st_ino = ino;
    stbuf->st_blocks = blocks;
    stbuf->st_blksize = 4096;

    return 0;
}

static ssize_t sabfs_readlink(FsContext *ctx, V9fsPath *fs_path,
                              char *buf, size_t bufsz)
{
    int ret = sabfs_be_js_readlink(fs_path->data, buf, bufsz);
    if (ret < 0) {
        errno = EINVAL;
        return -1;
    }
    return ret;
}

static int sabfs_close(FsContext *ctx, V9fsFidOpenState *fs)
{
    SabfsFileState *state = (SabfsFileState *)fs->private;
    if (state) {
        sabfs_be_js_close(state->fd);
        g_free(state);
        fs->private = NULL;
    }
    return 0;
}

static int sabfs_closedir(FsContext *ctx, V9fsFidOpenState *fs)
{
    SabfsDirState *state = (SabfsDirState *)fs->private;
    if (state) {
        g_free(state);
        fs->private = NULL;
    }
    return 0;
}

static int sabfs_open(FsContext *ctx, V9fsPath *fs_path,
                      int flags, V9fsFidOpenState *fs)
{
    int fd = sabfs_be_js_open(fs_path->data, flags, 0);
    if (fd < 0) {
        errno = ENOENT;
        return -1;
    }

    SabfsFileState *state = g_new0(SabfsFileState, 1);
    state->fd = fd;
    strncpy(state->path, fs_path->data, sizeof(state->path) - 1);
    fs->private = state;

    return 0;
}

static int sabfs_opendir(FsContext *ctx, V9fsPath *fs_path,
                         V9fsFidOpenState *fs)
{
    int count = sabfs_be_js_readdir_count(fs_path->data);
    if (count < 0) {
        errno = ENOENT;
        return -1;
    }

    SabfsDirState *state = g_new0(SabfsDirState, 1);
    strncpy(state->path, fs_path->data, sizeof(state->path) - 1);
    state->count = count;
    state->pos = 0;
    fs->private = state;

    return 0;
}

static void sabfs_rewinddir(FsContext *ctx, V9fsFidOpenState *fs)
{
    SabfsDirState *state = (SabfsDirState *)fs->private;
    if (state) {
        state->pos = 0;
        /* Refresh entries */
        state->count = sabfs_be_js_readdir_count(state->path);
    }
}

static off_t sabfs_telldir(FsContext *ctx, V9fsFidOpenState *fs)
{
    SabfsDirState *state = (SabfsDirState *)fs->private;
    return state ? state->pos : 0;
}

static struct dirent *sabfs_readdir(FsContext *ctx, V9fsFidOpenState *fs)
{
    static struct dirent entry;
    SabfsDirState *state = (SabfsDirState *)fs->private;

    if (!state || state->pos >= state->count) {
        return NULL;
    }

    uint32_t ino, type;
    if (sabfs_be_js_readdir_entry(state->pos, entry.d_name, sizeof(entry.d_name),
                                &ino, &type) < 0) {
        return NULL;
    }

    entry.d_ino = ino;
    entry.d_type = type;
    state->pos++;

    return &entry;
}

static void sabfs_seekdir(FsContext *ctx, V9fsFidOpenState *fs, off_t off)
{
    SabfsDirState *state = (SabfsDirState *)fs->private;
    if (state) {
        state->pos = off;
    }
}

static ssize_t sabfs_preadv(FsContext *ctx, V9fsFidOpenState *fs,
                            const struct iovec *iov, int iovcnt, off_t offset)
{
    SabfsFileState *state = (SabfsFileState *)fs->private;
    if (!state) {
        errno = EBADF;
        return -1;
    }

    ssize_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        ssize_t ret = sabfs_be_js_pread(state->fd, iov[i].iov_base,
                                      iov[i].iov_len, offset + total);
        if (ret < 0) {
            if (total == 0) return -1;
            break;
        }
        if (ret == 0) break;
        total += ret;
        if ((size_t)ret < iov[i].iov_len) break;
    }

    return total;
}

static ssize_t sabfs_pwritev(FsContext *ctx, V9fsFidOpenState *fs,
                             const struct iovec *iov, int iovcnt, off_t offset)
{
    SabfsFileState *state = (SabfsFileState *)fs->private;
    if (!state) {
        errno = EBADF;
        return -1;
    }

    ssize_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        ssize_t ret = sabfs_be_js_pwrite(state->fd, iov[i].iov_base,
                                       iov[i].iov_len, offset + total);
        if (ret < 0) {
            if (total == 0) return -1;
            break;
        }
        total += ret;
        if ((size_t)ret < iov[i].iov_len) break;
    }

    return total;
}

static int sabfs_chmod(FsContext *ctx, V9fsPath *fs_path, FsCred *credp)
{
    return sabfs_be_js_chmod(fs_path->data, credp->fc_mode);
}

static int sabfs_mknod(FsContext *ctx, V9fsPath *fs_path, const char *name,
                       FsCred *credp)
{
    /* SABFS doesn't support device nodes, create regular file instead */
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", fs_path->data, name);

    int fd = sabfs_be_js_open(path, 0x40 | 0x200, credp->fc_mode); /* O_CREAT | O_TRUNC */
    if (fd < 0) {
        errno = EPERM;
        return -1;
    }
    sabfs_be_js_close(fd);
    return 0;
}

static int sabfs_mkdir(FsContext *ctx, V9fsPath *fs_path, const char *name,
                       FsCred *credp)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", fs_path->data, name);
    return sabfs_be_js_mkdir(path, credp->fc_mode);
}

static int sabfs_fstat(FsContext *ctx, int fid_type,
                       V9fsFidOpenState *fs, struct stat *stbuf)
{
    if (fid_type == P9_FID_DIR) {
        SabfsDirState *state = (SabfsDirState *)fs->private;
        if (!state) {
            errno = EBADF;
            return -1;
        }
        uint32_t mode, nlink, uid, gid, size_lo, size_hi;
        uint32_t atime, mtime, ctime, ino, blocks;

        if (sabfs_be_js_stat(state->path, &mode, &nlink, &uid, &gid,
                          &size_lo, &size_hi, &atime, &mtime, &ctime,
                          &ino, &blocks) < 0) {
            errno = ENOENT;
            return -1;
        }

        memset(stbuf, 0, sizeof(*stbuf));
        stbuf->st_mode = mode;
        stbuf->st_nlink = nlink;
        stbuf->st_uid = uid;
        stbuf->st_gid = gid;
        stbuf->st_size = size_lo + ((uint64_t)size_hi << 32);
        stbuf->st_atime = atime;
        stbuf->st_mtime = mtime;
        stbuf->st_ctime = ctime;
        stbuf->st_ino = ino;
        stbuf->st_blocks = blocks;
        stbuf->st_blksize = 4096;
        return 0;
    } else {
        SabfsFileState *state = (SabfsFileState *)fs->private;
        if (!state) {
            errno = EBADF;
            return -1;
        }
        uint32_t mode, nlink, uid, gid, size_lo, size_hi;
        uint32_t atime, mtime, ctime, ino, blocks;

        if (sabfs_be_js_stat(state->path, &mode, &nlink, &uid, &gid,
                          &size_lo, &size_hi, &atime, &mtime, &ctime,
                          &ino, &blocks) < 0) {
            errno = ENOENT;
            return -1;
        }

        memset(stbuf, 0, sizeof(*stbuf));
        stbuf->st_mode = mode;
        stbuf->st_nlink = nlink;
        stbuf->st_uid = uid;
        stbuf->st_gid = gid;
        stbuf->st_size = size_lo + ((uint64_t)size_hi << 32);
        stbuf->st_atime = atime;
        stbuf->st_mtime = mtime;
        stbuf->st_ctime = ctime;
        stbuf->st_ino = ino;
        stbuf->st_blocks = blocks;
        stbuf->st_blksize = 4096;
        return 0;
    }
}

static int sabfs_open2(FsContext *ctx, V9fsPath *fs_path, const char *name,
                       int flags, FsCred *credp, V9fsFidOpenState *fs)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", fs_path->data, name);

    int fd = sabfs_be_js_open(path, flags | 0x40, credp->fc_mode); /* O_CREAT */
    if (fd < 0) {
        errno = ENOENT;
        return -1;
    }

    SabfsFileState *state = g_new0(SabfsFileState, 1);
    state->fd = fd;
    strncpy(state->path, path, sizeof(state->path) - 1);
    fs->private = state;

    return 0;
}

static int sabfs_symlink(FsContext *ctx, const char *oldpath,
                         V9fsPath *fs_path, const char *name, FsCred *credp)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", fs_path->data, name);
    return sabfs_be_js_symlink(oldpath, path);
}

static int sabfs_link(FsContext *ctx, V9fsPath *oldpath,
                      V9fsPath *newpath, const char *name)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", newpath->data, name);
    return sabfs_be_js_link(oldpath->data, path);
}

static int sabfs_truncate(FsContext *ctx, V9fsPath *fs_path, off_t size)
{
    return sabfs_be_js_truncate(fs_path->data, (double)size);
}

static int sabfs_rename(FsContext *ctx, const char *oldpath, const char *newpath)
{
    return sabfs_be_js_rename(oldpath, newpath);
}

static int sabfs_chown(FsContext *ctx, V9fsPath *fs_path, FsCred *credp)
{
    return sabfs_be_js_chown(fs_path->data, credp->fc_uid, credp->fc_gid);
}

static int sabfs_utimensat(FsContext *ctx, V9fsPath *fs_path,
                           const struct timespec *ts)
{
    double atime = ts[0].tv_sec + ts[0].tv_nsec / 1e9;
    double mtime = ts[1].tv_sec + ts[1].tv_nsec / 1e9;
    return sabfs_be_js_utimes(fs_path->data, atime, mtime);
}

static int sabfs_remove(FsContext *ctx, const char *path)
{
    /* Try unlink first, then rmdir */
    if (sabfs_be_js_unlink(path) == 0) return 0;
    return sabfs_be_js_rmdir(path);
}

static int sabfs_fsync(FsContext *ctx, int fid_type,
                       V9fsFidOpenState *fs, int datasync)
{
    /* SABFS is in-memory, fsync is a no-op */
    return 0;
}

static int sabfs_statfs(FsContext *ctx, V9fsPath *fs_path, struct statfs *stbuf)
{
    uint32_t bsize, blocks, bfree, files, ffree;

    if (sabfs_be_js_statfs(&bsize, &blocks, &bfree, &files, &ffree) < 0) {
        /* Provide defaults */
        bsize = 4096;
        blocks = 1024 * 1024;
        bfree = 512 * 1024;
        files = 65536;
        ffree = 32768;
    }

    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->f_type = 0x53414246; /* "SABF" */
    stbuf->f_bsize = bsize;
    stbuf->f_blocks = blocks;
    stbuf->f_bfree = bfree;
    stbuf->f_bavail = bfree;
    stbuf->f_files = files;
    stbuf->f_ffree = ffree;
    stbuf->f_namelen = 255;

    return 0;
}

/* xattr stubs - SABFS doesn't support xattrs */
static ssize_t sabfs_lgetxattr(FsContext *ctx, V9fsPath *fs_path,
                               const char *name, void *value, size_t size)
{
    errno = ENOTSUP;
    return -1;
}

static ssize_t sabfs_llistxattr(FsContext *ctx, V9fsPath *fs_path,
                                void *value, size_t size)
{
    errno = ENOTSUP;
    return -1;
}

static int sabfs_lsetxattr(FsContext *ctx, V9fsPath *fs_path,
                           const char *name, void *value, size_t size, int flags)
{
    errno = ENOTSUP;
    return -1;
}

static int sabfs_lremovexattr(FsContext *ctx, V9fsPath *fs_path,
                              const char *name)
{
    errno = ENOTSUP;
    return -1;
}

static int sabfs_name_to_path(FsContext *ctx, V9fsPath *dir_path,
                              const char *name, V9fsPath *target)
{
    if (dir_path) {
        if (strcmp(name, ".") == 0) {
            target->data = g_strdup(dir_path->data);
        } else if (strcmp(name, "..") == 0) {
            /* Go up one level */
            char *last_slash = strrchr(dir_path->data, '/');
            if (last_slash && last_slash != dir_path->data) {
                target->data = g_strndup(dir_path->data, last_slash - dir_path->data);
            } else {
                target->data = g_strdup("/");
            }
        } else {
            target->data = g_strdup_printf("%s/%s", dir_path->data, name);
        }
    } else {
        target->data = g_strdup(name);
    }
    target->size = strlen(target->data) + 1;
    return 0;
}

static int sabfs_renameat(FsContext *ctx, V9fsPath *olddir,
                          const char *old_name, V9fsPath *newdir,
                          const char *new_name)
{
    char oldpath[PATH_MAX], newpath[PATH_MAX];
    snprintf(oldpath, sizeof(oldpath), "%s/%s", olddir->data, old_name);
    snprintf(newpath, sizeof(newpath), "%s/%s", newdir->data, new_name);
    return sabfs_be_js_rename(oldpath, newpath);
}

static int sabfs_unlinkat(FsContext *ctx, V9fsPath *dir,
                          const char *name, int flags)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", dir->data, name);

    if (flags & AT_REMOVEDIR) {
        return sabfs_be_js_rmdir(path);
    }
    return sabfs_be_js_unlink(path);
}

FileOperations sabfs_ops = {
    .parse_opts = NULL,
    .init = sabfs_init,
    .cleanup = sabfs_cleanup,
    .lstat = sabfs_lstat,
    .readlink = sabfs_readlink,
    .close = sabfs_close,
    .closedir = sabfs_closedir,
    .open = sabfs_open,
    .opendir = sabfs_opendir,
    .rewinddir = sabfs_rewinddir,
    .telldir = sabfs_telldir,
    .readdir = sabfs_readdir,
    .seekdir = sabfs_seekdir,
    .preadv = sabfs_preadv,
    .pwritev = sabfs_pwritev,
    .chmod = sabfs_chmod,
    .mknod = sabfs_mknod,
    .mkdir = sabfs_mkdir,
    .fstat = sabfs_fstat,
    .open2 = sabfs_open2,
    .symlink = sabfs_symlink,
    .link = sabfs_link,
    .truncate = sabfs_truncate,
    .rename = sabfs_rename,
    .chown = sabfs_chown,
    .utimensat = sabfs_utimensat,
    .remove = sabfs_remove,
    .fsync = sabfs_fsync,
    .statfs = sabfs_statfs,
    .lgetxattr = sabfs_lgetxattr,
    .llistxattr = sabfs_llistxattr,
    .lsetxattr = sabfs_lsetxattr,
    .lremovexattr = sabfs_lremovexattr,
    .name_to_path = sabfs_name_to_path,
    .renameat = sabfs_renameat,
    .unlinkat = sabfs_unlinkat,
};

#endif /* __EMSCRIPTEN__ */
