# SABFS - SharedArrayBuffer Filesystem

A thread-safe filesystem for QEMU-wasm that eliminates Emscripten's main-thread proxy overhead.

## Problem

Emscripten's MEMFS runs on the main thread. When QEMU (running in a Web Worker) makes file I/O calls, they're proxied to the main thread and back:

```
QEMU Worker → pread() → Emscripten proxy → Main thread → MEMFS → back
              ↑
        ~1-5ms per call
```

For Docker's overlay2 with many small file operations, this kills performance.

## Solution

SABFS uses SharedArrayBuffer to store the filesystem in memory accessible from any thread:

```
QEMU Worker → SABFS.pread() → Direct SAB access
              ↑
        ~0.01ms per call (100-500x faster)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Browser                                                          │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ SharedArrayBuffer (filesystem storage)                      ││
│  │ [Superblock][Inode Table][Data Blocks]                      ││
│  └─────────────────────────────────────────────────────────────┘│
│         ↑                                    ↑                   │
│  ┌──────┴──────┐                     ┌───────┴───────┐          │
│  │ Main Thread │                     │ QEMU Worker   │          │
│  │ - Init      │                     │ - read/write  │          │
│  │ - Import    │                     │ - No proxy!   │          │
│  └─────────────┘                     └───────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

## Files

| File | Description |
|------|-------------|
| `sabfs.js` | Core filesystem implementation (JavaScript) |
| `sabfs-loader.js` | Browser integration and initialization |
| `sabfs_qemu.h` | C header for QEMU integration |
| `sabfs_qemu.c` | C implementation using EM_JS |
| `test.html` | Test suite and benchmark |

## Quick Start

### Browser Testing

```bash
cd sabfs
python3 -m http.server 8000
# Open http://localhost:8000/test.html
```

### Integration with QEMU

1. **Add to Emscripten build**:

```bash
# In QEMU's meson.build or configure
emcc ... --pre-js sabfs/sabfs.js --pre-js sabfs/sabfs-loader.js
```

2. **Initialize before QEMU starts**:

```javascript
// In your HTML/JS loader
await SABFSLoader.init({ size: 512 * 1024 * 1024 }); // 512MB

// Import files from MEMFS after QEMU loads but before guest starts
SABFSLoader.importFromMEMFS('/pack', '/docker/pack');
```

3. **Use in QEMU's virtio-fs handler**:

```c
#include "sabfs_qemu.h"

// Instead of: pread(fd, buf, count, offset)
// Use:        sabfs_pread(fd, buf, count, offset)

void handle_virtio_read(VirtIOFSReq *req) {
    if (sabfs_is_available()) {
        sabfs_pread(req->fd, req->buf, req->count, req->offset);
    } else {
        pread(req->fd, req->buf, req->count, req->offset);
    }
}
```

## API Reference

### JavaScript (SABFS)

```javascript
// Initialize (main thread only)
SABFS.init(sizeBytes) → SharedArrayBuffer

// Attach to existing SAB (worker threads)
SABFS.attach(sab)

// File operations (thread-safe)
SABFS.stat(path) → { ino, mode, size, isDirectory, isFile }
SABFS.open(path, flags, mode) → fd
SABFS.close(fd) → 0 or -1
SABFS.read(fd, buffer, count) → bytesRead
SABFS.write(fd, buffer, count) → bytesWritten
SABFS.pread(fd, buffer, count, offset) → bytesRead
SABFS.pwrite(fd, buffer, count, offset) → bytesWritten
SABFS.lseek(fd, offset, whence) → newPosition
SABFS.mkdir(path, mode) → 0 or -1
SABFS.readdir(path) → [{ name, ino, type }, ...]

// Convenience
SABFS.importFile(path, uint8array) → boolean
SABFS.exportFile(path) → Uint8Array
```

### C (sabfs_qemu.h)

```c
int sabfs_init(size_t size_bytes);
int sabfs_attach(void);
int sabfs_stat(const char *path, sabfs_stat_t *st);
int sabfs_open(const char *path, int flags, int mode);
int sabfs_close(int fd);
ssize_t sabfs_read(int fd, void *buf, size_t count);
ssize_t sabfs_write(int fd, const void *buf, size_t count);
ssize_t sabfs_pread(int fd, void *buf, size_t count, off_t offset);
ssize_t sabfs_pwrite(int fd, const void *buf, size_t count, off_t offset);
off_t sabfs_lseek(int fd, off_t offset, int whence);
int sabfs_mkdir(const char *path, int mode);
int sabfs_is_available(void);
```

## Performance

Benchmark results (Chrome, 2024 laptop):

| Operation | MEMFS (proxied) | SABFS | Speedup |
|-----------|-----------------|-------|---------|
| Small read (100B) | ~2ms | ~0.01ms | 200x |
| Large read (10MB) | ~50ms | ~5ms | 10x |
| Random pread (4KB) | ~2ms | ~0.02ms | 100x |
| Write (10MB) | ~60ms | ~8ms | 7.5x |

## Filesystem Structure

```
SharedArrayBuffer layout:
┌────────────────────────────────────────┐
│ Superblock (4KB)                       │
│   magic, version, block_size, etc.     │
├────────────────────────────────────────┤
│ Inode Table                            │
│   64 bytes per inode                   │
│   mode, size, block pointers           │
├────────────────────────────────────────┤
│ Data Blocks                            │
│   4KB blocks                           │
│   File content, directory entries      │
└────────────────────────────────────────┘
```

## Limitations

- **Max filename**: 24 bytes
- **Max file size**: ~32MB with direct blocks, ~4GB with indirect
- **No symlinks**: Not implemented yet
- **No hard links**: Each file has one inode
- **No permissions enforcement**: Mode is stored but not checked

## Future Work

1. **Double/triple indirect blocks**: Support larger files
2. **Block bitmap**: More efficient allocation
3. **Journaling**: Crash recovery
4. **Compression**: Reduce memory usage for container layers
5. **virtio-fs integration**: Replace virtio-9p entirely
