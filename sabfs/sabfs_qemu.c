/*
 * SABFS - SharedArrayBuffer Filesystem for QEMU-wasm
 *
 * C implementation using EM_JS to call JavaScript SABFS module.
 * All operations run directly in the worker thread without proxying.
 */

#include "sabfs_qemu.h"
#include <emscripten.h>
#include <stdlib.h>
#include <string.h>

/* Check if SABFS is available */
EM_JS(int, sabfs_js_is_available, (void), {
    return (typeof SABFS !== 'undefined' && SABFS.getBuffer() !== null) ? 1 : 0;
});

/* Initialize SABFS */
EM_JS(int, sabfs_js_init, (size_t size), {
    try {
        if (typeof SABFS === 'undefined') {
            console.error('SABFS module not loaded');
            return -1;
        }
        SABFS.init(size);
        return 0;
    } catch (e) {
        console.error('SABFS init failed:', e);
        return -1;
    }
});

/* Attach to existing SABFS */
EM_JS(int, sabfs_js_attach, (void), {
    try {
        if (typeof SABFS === 'undefined') {
            return -1;
        }
        // SAB should be passed via Module.sabfsBuffer
        if (Module.sabfsBuffer) {
            SABFS.attach(Module.sabfsBuffer);
            return 0;
        }
        return -1;
    } catch (e) {
        console.error('SABFS attach failed:', e);
        return -1;
    }
});

/* Import file */
EM_JS(int, sabfs_js_import_file, (const char *path, const void *data, size_t size), {
    try {
        const pathStr = UTF8ToString(path);
        const dataArray = new Uint8Array(HEAPU8.buffer, data, size);
        // Make a copy since SABFS stores the data
        const dataCopy = new Uint8Array(size);
        dataCopy.set(dataArray);
        return SABFS.importFile(pathStr, dataCopy) ? 0 : -1;
    } catch (e) {
        console.error('SABFS import failed:', e);
        return -1;
    }
});

/* Stat */
EM_JS(int, sabfs_js_stat, (const char *path, uint64_t *ino, uint32_t *mode,
                           uint64_t *size, uint32_t *blocks, int *is_dir, int *is_file), {
    try {
        const pathStr = UTF8ToString(path);
        const st = SABFS.stat(pathStr);
        if (!st) return -1;

        // Write results to pointers
        // Use setValue for 64-bit values
        setValue(ino, st.ino, 'i64');
        HEAPU32[mode >> 2] = st.mode;
        setValue(size, st.size, 'i64');
        HEAPU32[blocks >> 2] = st.blocks;
        HEAP32[is_dir >> 2] = st.isDirectory ? 1 : 0;
        HEAP32[is_file >> 2] = st.isFile ? 1 : 0;

        return 0;
    } catch (e) {
        console.error('SABFS stat failed:', e);
        return -1;
    }
});

/* Open */
EM_JS(int, sabfs_js_open, (const char *path, int flags, int mode), {
    try {
        const pathStr = UTF8ToString(path);
        return SABFS.open(pathStr, flags, mode);
    } catch (e) {
        console.error('SABFS open failed:', e);
        return -1;
    }
});

/* Close */
EM_JS(int, sabfs_js_close, (int fd), {
    try {
        return SABFS.close(fd);
    } catch (e) {
        return -1;
    }
});

/* Read */
EM_JS(ssize_t, sabfs_js_read, (int fd, void *buf, size_t count), {
    try {
        const buffer = new Uint8Array(HEAPU8.buffer, buf, count);
        return SABFS.read(fd, buffer, count);
    } catch (e) {
        console.error('SABFS read failed:', e);
        return -1;
    }
});

/* Write */
EM_JS(ssize_t, sabfs_js_write, (int fd, const void *buf, size_t count), {
    try {
        const buffer = new Uint8Array(HEAPU8.buffer, buf, count);
        return SABFS.write(fd, buffer, count);
    } catch (e) {
        console.error('SABFS write failed:', e);
        return -1;
    }
});

/* Pread */
EM_JS(ssize_t, sabfs_js_pread, (int fd, void *buf, size_t count, double offset), {
    try {
        const buffer = new Uint8Array(HEAPU8.buffer, buf, count);
        return SABFS.pread(fd, buffer, count, offset);
    } catch (e) {
        console.error('SABFS pread failed:', e);
        return -1;
    }
});

/* Pwrite */
EM_JS(ssize_t, sabfs_js_pwrite, (int fd, const void *buf, size_t count, double offset), {
    try {
        const buffer = new Uint8Array(HEAPU8.buffer, buf, count);
        return SABFS.pwrite(fd, buffer, count, offset);
    } catch (e) {
        console.error('SABFS pwrite failed:', e);
        return -1;
    }
});

/* Lseek - use double for offset to handle 64-bit values */
EM_JS(double, sabfs_js_lseek, (int fd, double offset, int whence), {
    try {
        return SABFS.lseek(fd, offset, whence);
    } catch (e) {
        return -1;
    }
});

/* Mkdir */
EM_JS(int, sabfs_js_mkdir, (const char *path, int mode), {
    try {
        const pathStr = UTF8ToString(path);
        return SABFS.mkdir(pathStr, mode);
    } catch (e) {
        console.error('SABFS mkdir failed:', e);
        return -1;
    }
});

/* Readdir - returns JSON string of entries */
EM_JS(char*, sabfs_js_readdir, (const char *path), {
    try {
        const pathStr = UTF8ToString(path);
        const entries = SABFS.readdir(pathStr);
        if (!entries) return 0;

        const json = JSON.stringify(entries);
        const len = lengthBytesUTF8(json) + 1;
        const ptr = _malloc(len);
        stringToUTF8(json, ptr, len);
        return ptr;
    } catch (e) {
        console.error('SABFS readdir failed:', e);
        return 0;
    }
});

/* C wrapper functions */

int sabfs_init(size_t size_bytes) {
    return sabfs_js_init(size_bytes);
}

int sabfs_attach(void) {
    return sabfs_js_attach();
}

int sabfs_import_file(const char *path, const void *data, size_t size) {
    return sabfs_js_import_file(path, data, size);
}

int sabfs_stat(const char *path, sabfs_stat_t *st) {
    uint64_t ino;
    uint32_t mode;
    uint64_t size;
    uint32_t blocks;
    int is_dir, is_file;

    int ret = sabfs_js_stat(path, &ino, &mode, &size, &blocks, &is_dir, &is_file);
    if (ret == 0) {
        st->ino = ino;
        st->mode = mode;
        st->size = size;
        st->blocks = blocks;
        st->is_directory = is_dir;
        st->is_file = is_file;
    }
    return ret;
}

int sabfs_open(const char *path, int flags, int mode) {
    return sabfs_js_open(path, flags, mode);
}

int sabfs_close(int fd) {
    return sabfs_js_close(fd);
}

ssize_t sabfs_read(int fd, void *buf, size_t count) {
    return sabfs_js_read(fd, buf, count);
}

ssize_t sabfs_write(int fd, const void *buf, size_t count) {
    return sabfs_js_write(fd, buf, count);
}

ssize_t sabfs_pread(int fd, void *buf, size_t count, off_t offset) {
    return sabfs_js_pread(fd, buf, count, (double)offset);
}

ssize_t sabfs_pwrite(int fd, const void *buf, size_t count, off_t offset) {
    return sabfs_js_pwrite(fd, buf, count, (double)offset);
}

off_t sabfs_lseek(int fd, off_t offset, int whence) {
    double result = sabfs_js_lseek(fd, (double)offset, whence);
    return (off_t)result;
}

int sabfs_mkdir(const char *path, int mode) {
    return sabfs_js_mkdir(path, mode);
}

int sabfs_readdir(const char *path, sabfs_dirent_t **entries) {
    char *json = sabfs_js_readdir(path);
    if (!json) {
        *entries = NULL;
        return -1;
    }

    /* Parse JSON - simple parser for array of {name, ino, type} */
    /* For now, just return the count and let caller parse */
    /* TODO: implement proper JSON parsing or use different format */

    *entries = NULL;
    free(json);
    return 0;
}

void sabfs_free_dirents(sabfs_dirent_t *entries) {
    if (entries) {
        free(entries);
    }
}

int sabfs_is_available(void) {
    return sabfs_js_is_available();
}
