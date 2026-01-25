/**
 * SABFS v2 - SharedArrayBuffer Filesystem
 *
 * Full POSIX-compatible filesystem for direct worker thread access.
 * Designed to replace 9p for container filesystem in browser.
 *
 * Extended inode structure (128 bytes):
 *   0-3:   mode (file type + permissions)
 *   4-7:   nlink (link count)
 *   8-11:  uid
 *   12-15: gid
 *   16-23: size (64-bit)
 *   24-27: atime (seconds)
 *   28-31: mtime (seconds)
 *   32-35: ctime (seconds)
 *   36-39: blocks (number of data blocks)
 *   40-71: direct[0-7] - 8 direct block pointers
 *   72-75: indirect (single indirect)
 *   76-79: double_indirect
 *   80-83: flags
 *   84-127: reserved
 *
 * Max file size with double indirect:
 *   Direct: 8 * 4KB = 32KB
 *   Indirect: 1024 * 4KB = 4MB
 *   Double indirect: 1024 * 1024 * 4KB = 4GB
 */

const SABFS = (function() {
    'use strict';

    // Constants
    const MAGIC = 0x53414247; // "SABG" (v2)
    const VERSION = 2;
    const BLOCK_SIZE = 4096;
    const INODE_SIZE = 128;
    const DIRENT_SIZE = 32;
    const DIRENTS_PER_BLOCK = Math.floor(BLOCK_SIZE / DIRENT_SIZE);
    const DIRECT_BLOCKS = 8;
    const PTRS_PER_BLOCK = Math.floor(BLOCK_SIZE / 4);
    const MAX_NAME_LEN = 255;

    // File types
    const S_IFMT   = 0o170000;
    const S_IFDIR  = 0o040000;
    const S_IFREG  = 0o100000;
    const S_IFLNK  = 0o120000;
    const S_IFBLK  = 0o060000;
    const S_IFCHR  = 0o020000;
    const S_IFIFO  = 0o010000;
    const S_IFSOCK = 0o140000;

    // Directory entry types (for d_type)
    const DT_UNKNOWN = 0;
    const DT_FIFO = 1;
    const DT_CHR = 2;
    const DT_DIR = 4;
    const DT_BLK = 6;
    const DT_REG = 8;
    const DT_LNK = 10;
    const DT_SOCK = 12;

    // Open flags
    const O_RDONLY = 0;
    const O_WRONLY = 1;
    const O_RDWR = 2;
    const O_CREAT = 0o100;
    const O_EXCL = 0o200;
    const O_TRUNC = 0o1000;
    const O_APPEND = 0o2000;
    const O_NOFOLLOW = 0o400000;

    // Superblock offsets
    const SB_MAGIC = 0;
    const SB_VERSION = 4;
    const SB_BLOCK_SIZE = 8;
    const SB_TOTAL_BLOCKS = 12;
    const SB_INODE_COUNT = 16;
    const SB_FREE_BLOCK = 20;
    const SB_FREE_INODE = 24;
    const SB_ROOT_INODE = 28;
    const SB_DATA_BLOCKS = 32;

    // Inode field offsets
    const INO_MODE = 0;
    const INO_NLINK = 4;
    const INO_UID = 8;
    const INO_GID = 12;
    const INO_SIZE_LO = 16;
    const INO_SIZE_HI = 20;
    const INO_ATIME = 24;
    const INO_MTIME = 28;
    const INO_CTIME = 32;
    const INO_BLOCKS = 36;
    const INO_DIRECT = 40;
    const INO_INDIRECT = 72;
    const INO_DOUBLE_INDIRECT = 76;
    const INO_FLAGS = 80;

    // Internal state
    let sab = null;
    let view = null;
    let u8 = null;
    let u32 = null;
    let inodeTableOffset = 0;
    let dataBlocksOffset = 0;
    let totalDataBlocks = 0;

    // File descriptor table
    const fdTable = new Map();
    let nextFd = 3;

    // Path cache
    const pathCache = new Map();

    // Current time helper
    function now() {
        return Math.floor(Date.now() / 1000);
    }

    /**
     * Initialize filesystem
     */
    function init(sizeBytes, options = {}) {
        const totalBlocks = Math.floor(sizeBytes / BLOCK_SIZE);
        const inodeCount = options.inodeCount || Math.min(Math.floor(totalBlocks / 4), 65536);
        const inodeTableBlocks = Math.ceil((inodeCount * INODE_SIZE) / BLOCK_SIZE);

        sab = new SharedArrayBuffer(sizeBytes);
        view = new DataView(sab);
        u8 = new Uint8Array(sab);
        u32 = new Uint32Array(sab);

        inodeTableOffset = BLOCK_SIZE;
        dataBlocksOffset = inodeTableOffset + (inodeTableBlocks * BLOCK_SIZE);
        totalDataBlocks = totalBlocks - 1 - inodeTableBlocks;

        // Initialize superblock
        view.setUint32(SB_MAGIC, MAGIC, true);
        view.setUint32(SB_VERSION, VERSION, true);
        view.setUint32(SB_BLOCK_SIZE, BLOCK_SIZE, true);
        view.setUint32(SB_TOTAL_BLOCKS, totalBlocks, true);
        view.setUint32(SB_INODE_COUNT, inodeCount, true);
        view.setUint32(SB_FREE_BLOCK, 1, true);
        view.setUint32(SB_FREE_INODE, 1, true);
        view.setUint32(SB_ROOT_INODE, 0, true);
        view.setUint32(SB_DATA_BLOCKS, totalDataBlocks, true);

        // Initialize free block list
        for (let i = 1; i < totalDataBlocks - 1; i++) {
            const off = dataBlocksOffset + (i * BLOCK_SIZE);
            view.setUint32(off, i + 1, true);
        }
        view.setUint32(dataBlocksOffset + ((totalDataBlocks - 1) * BLOCK_SIZE), 0xFFFFFFFF, true);

        // Initialize root directory (inode 0)
        const t = now();
        const rootOff = inodeTableOffset;
        view.setUint32(rootOff + INO_MODE, S_IFDIR | 0o755, true);
        view.setUint32(rootOff + INO_NLINK, 2, true);
        view.setUint32(rootOff + INO_UID, 0, true);
        view.setUint32(rootOff + INO_GID, 0, true);
        view.setUint32(rootOff + INO_SIZE_LO, 0, true);
        view.setUint32(rootOff + INO_SIZE_HI, 0, true);
        view.setUint32(rootOff + INO_ATIME, t, true);
        view.setUint32(rootOff + INO_MTIME, t, true);
        view.setUint32(rootOff + INO_CTIME, t, true);

        console.log(`SABFS v2 initialized: ${totalBlocks} blocks, ${inodeCount} inodes, ${totalDataBlocks} data blocks`);
        return sab;
    }

    /**
     * Attach to existing SAB
     */
    function attach(existingSab) {
        sab = existingSab;
        view = new DataView(sab);
        u8 = new Uint8Array(sab);
        u32 = new Uint32Array(sab);

        const magic = view.getUint32(SB_MAGIC, true);
        if (magic !== MAGIC) {
            throw new Error(`Invalid SABFS magic: 0x${magic.toString(16)} (expected 0x${MAGIC.toString(16)})`);
        }

        const inodeCount = view.getUint32(SB_INODE_COUNT, true);
        const inodeTableBlocks = Math.ceil((inodeCount * INODE_SIZE) / BLOCK_SIZE);
        inodeTableOffset = BLOCK_SIZE;
        dataBlocksOffset = inodeTableOffset + (inodeTableBlocks * BLOCK_SIZE);
        totalDataBlocks = view.getUint32(SB_DATA_BLOCKS, true) ||
            (view.getUint32(SB_TOTAL_BLOCKS, true) - 1 - inodeTableBlocks);

        console.log('SABFS v2 attached');
    }

    // Block allocation
    function allocBlock() {
        const freeBlock = Atomics.load(u32, SB_FREE_BLOCK / 4);
        if (freeBlock === 0xFFFFFFFF || freeBlock === 0) return -1;

        const blockOff = dataBlocksOffset + (freeBlock * BLOCK_SIZE);
        const nextFree = view.getUint32(blockOff, true);

        if (Atomics.compareExchange(u32, SB_FREE_BLOCK / 4, freeBlock, nextFree) !== freeBlock) {
            return allocBlock();
        }

        u8.fill(0, blockOff, blockOff + BLOCK_SIZE);
        return freeBlock;
    }

    function freeBlock(blockNum) {
        if (blockNum === 0 || blockNum === 0xFFFFFFFF) return;
        const blockOff = dataBlocksOffset + (blockNum * BLOCK_SIZE);

        while (true) {
            const freeHead = Atomics.load(u32, SB_FREE_BLOCK / 4);
            view.setUint32(blockOff, freeHead, true);
            if (Atomics.compareExchange(u32, SB_FREE_BLOCK / 4, freeHead, blockNum) === freeHead) {
                break;
            }
        }
    }

    function allocInode() {
        const inodeCount = view.getUint32(SB_INODE_COUNT, true);
        while (true) {
            const freeInode = Atomics.load(u32, SB_FREE_INODE / 4);
            if (freeInode >= inodeCount) return -1;
            if (Atomics.compareExchange(u32, SB_FREE_INODE / 4, freeInode, freeInode + 1) === freeInode) {
                const off = inodeTableOffset + (freeInode * INODE_SIZE);
                u8.fill(0, off, off + INODE_SIZE);
                return freeInode;
            }
        }
    }

    function inodeOffset(ino) {
        return inodeTableOffset + (ino * INODE_SIZE);
    }

    function blockOffset(blockNum) {
        return dataBlocksOffset + (blockNum * BLOCK_SIZE);
    }

    // Inode operations
    function readInode(ino) {
        const off = inodeOffset(ino);
        return {
            mode: view.getUint32(off + INO_MODE, true),
            nlink: view.getUint32(off + INO_NLINK, true),
            uid: view.getUint32(off + INO_UID, true),
            gid: view.getUint32(off + INO_GID, true),
            size: view.getUint32(off + INO_SIZE_LO, true) +
                  (view.getUint32(off + INO_SIZE_HI, true) * 0x100000000),
            atime: view.getUint32(off + INO_ATIME, true),
            mtime: view.getUint32(off + INO_MTIME, true),
            ctime: view.getUint32(off + INO_CTIME, true),
            blocks: view.getUint32(off + INO_BLOCKS, true),
            direct: Array.from({length: DIRECT_BLOCKS}, (_, i) =>
                view.getUint32(off + INO_DIRECT + i * 4, true)),
            indirect: view.getUint32(off + INO_INDIRECT, true),
            doubleIndirect: view.getUint32(off + INO_DOUBLE_INDIRECT, true),
            flags: view.getUint32(off + INO_FLAGS, true),
        };
    }

    function writeInode(ino, data) {
        const off = inodeOffset(ino);
        if (data.mode !== undefined) view.setUint32(off + INO_MODE, data.mode, true);
        if (data.nlink !== undefined) view.setUint32(off + INO_NLINK, data.nlink, true);
        if (data.uid !== undefined) view.setUint32(off + INO_UID, data.uid, true);
        if (data.gid !== undefined) view.setUint32(off + INO_GID, data.gid, true);
        if (data.size !== undefined) {
            view.setUint32(off + INO_SIZE_LO, data.size & 0xFFFFFFFF, true);
            view.setUint32(off + INO_SIZE_HI, Math.floor(data.size / 0x100000000), true);
        }
        if (data.atime !== undefined) view.setUint32(off + INO_ATIME, data.atime, true);
        if (data.mtime !== undefined) view.setUint32(off + INO_MTIME, data.mtime, true);
        if (data.ctime !== undefined) view.setUint32(off + INO_CTIME, data.ctime, true);
        if (data.blocks !== undefined) view.setUint32(off + INO_BLOCKS, data.blocks, true);
        if (data.direct) {
            for (let i = 0; i < DIRECT_BLOCKS; i++) {
                view.setUint32(off + INO_DIRECT + i * 4, data.direct[i] || 0, true);
            }
        }
        if (data.indirect !== undefined) view.setUint32(off + INO_INDIRECT, data.indirect, true);
        if (data.doubleIndirect !== undefined) view.setUint32(off + INO_DOUBLE_INDIRECT, data.doubleIndirect, true);
        if (data.flags !== undefined) view.setUint32(off + INO_FLAGS, data.flags, true);
    }

    // Block mapping with double indirect support
    function getBlockNum(inode, fileBlock) {
        if (fileBlock < DIRECT_BLOCKS) {
            const blk = inode.direct[fileBlock];
            return blk === 0 ? -1 : blk;
        }

        const indirectIdx = fileBlock - DIRECT_BLOCKS;
        if (indirectIdx < PTRS_PER_BLOCK) {
            if (inode.indirect === 0) return -1;
            const ptr = view.getUint32(blockOffset(inode.indirect) + indirectIdx * 4, true);
            return ptr === 0 ? -1 : ptr;
        }

        // Double indirect
        const doubleIdx = indirectIdx - PTRS_PER_BLOCK;
        const l1 = Math.floor(doubleIdx / PTRS_PER_BLOCK);
        const l2 = doubleIdx % PTRS_PER_BLOCK;

        if (inode.doubleIndirect === 0) return -1;
        const l1Ptr = view.getUint32(blockOffset(inode.doubleIndirect) + l1 * 4, true);
        if (l1Ptr === 0) return -1;
        const ptr = view.getUint32(blockOffset(l1Ptr) + l2 * 4, true);
        return ptr === 0 ? -1 : ptr;
    }

    function allocBlockForFile(ino, fileBlock) {
        const newBlock = allocBlock();
        if (newBlock === -1) return -1;

        const off = inodeOffset(ino);

        if (fileBlock < DIRECT_BLOCKS) {
            view.setUint32(off + INO_DIRECT + fileBlock * 4, newBlock, true);
        } else {
            const indirectIdx = fileBlock - DIRECT_BLOCKS;
            if (indirectIdx < PTRS_PER_BLOCK) {
                let indirect = view.getUint32(off + INO_INDIRECT, true);
                if (indirect === 0) {
                    indirect = allocBlock();
                    if (indirect === -1) { freeBlock(newBlock); return -1; }
                    view.setUint32(off + INO_INDIRECT, indirect, true);
                }
                view.setUint32(blockOffset(indirect) + indirectIdx * 4, newBlock, true);
            } else {
                // Double indirect
                const doubleIdx = indirectIdx - PTRS_PER_BLOCK;
                const l1 = Math.floor(doubleIdx / PTRS_PER_BLOCK);
                const l2 = doubleIdx % PTRS_PER_BLOCK;

                let dblIndirect = view.getUint32(off + INO_DOUBLE_INDIRECT, true);
                if (dblIndirect === 0) {
                    dblIndirect = allocBlock();
                    if (dblIndirect === -1) { freeBlock(newBlock); return -1; }
                    view.setUint32(off + INO_DOUBLE_INDIRECT, dblIndirect, true);
                }

                let l1Ptr = view.getUint32(blockOffset(dblIndirect) + l1 * 4, true);
                if (l1Ptr === 0) {
                    l1Ptr = allocBlock();
                    if (l1Ptr === -1) { freeBlock(newBlock); return -1; }
                    view.setUint32(blockOffset(dblIndirect) + l1 * 4, l1Ptr, true);
                }

                view.setUint32(blockOffset(l1Ptr) + l2 * 4, newBlock, true);
            }
        }

        const blocks = view.getUint32(off + INO_BLOCKS, true);
        view.setUint32(off + INO_BLOCKS, blocks + 1, true);
        return newBlock;
    }

    // Directory operations
    function lookupInDir(dirIno, name) {
        const dir = readInode(dirIno);
        if ((dir.mode & S_IFMT) !== S_IFDIR) return -1;

        const numBlocks = Math.ceil(dir.size / BLOCK_SIZE) || 1;

        for (let b = 0; b < numBlocks; b++) {
            const blkNum = getBlockNum(dir, b);
            if (blkNum === -1) continue;

            const blkOff = blockOffset(blkNum);
            for (let i = 0; i < DIRENTS_PER_BLOCK; i++) {
                const entOff = blkOff + i * DIRENT_SIZE;
                const entIno = view.getUint32(entOff, true);
                if (entIno === 0) continue;

                const nameLen = view.getUint16(entOff + 4, true);
                const entName = new TextDecoder().decode(u8.slice(entOff + 8, entOff + 8 + nameLen));
                if (entName === name) return entIno;
            }
        }
        return -1;
    }

    function addDirEntry(dirIno, name, ino, type) {
        const dir = readInode(dirIno);
        if ((dir.mode & S_IFMT) !== S_IFDIR) return false;

        const nameBytes = new TextEncoder().encode(name);
        if (nameBytes.length > 24) return false;

        const numBlocks = Math.ceil(dir.size / BLOCK_SIZE) || 1;

        for (let b = 0; b < numBlocks + 1; b++) {
            let blkNum = getBlockNum(dir, b);
            if (blkNum === -1) {
                blkNum = allocBlockForFile(dirIno, b);
                if (blkNum === -1) return false;
            }

            const blkOff = blockOffset(blkNum);
            for (let i = 0; i < DIRENTS_PER_BLOCK; i++) {
                const entOff = blkOff + i * DIRENT_SIZE;
                if (view.getUint32(entOff, true) === 0) {
                    view.setUint32(entOff, ino, true);
                    view.setUint16(entOff + 4, nameBytes.length, true);
                    view.setUint16(entOff + 6, type, true);
                    u8.fill(0, entOff + 8, entOff + 32);
                    u8.set(nameBytes, entOff + 8);

                    const newSize = (b * BLOCK_SIZE) + ((i + 1) * DIRENT_SIZE);
                    if (newSize > dir.size) {
                        writeInode(dirIno, { size: newSize, mtime: now(), ctime: now() });
                    }
                    return true;
                }
            }
        }
        return false;
    }

    // Path resolution
    function normalizePath(path) {
        const parts = path.split('/').filter(p => p.length > 0);
        const normalized = [];
        for (const part of parts) {
            if (part === '.') continue;
            if (part === '..') normalized.pop();
            else normalized.push(part);
        }
        return '/' + normalized.join('/');
    }

    function resolvePathInternal(path, followLinks = true, maxDepth = 40) {
        if (maxDepth <= 0) return -1;

        path = normalizePath(path);
        const parts = path.split('/').filter(p => p.length > 0);
        let ino = 0;
        let currentPath = '';

        for (let i = 0; i < parts.length; i++) {
            currentPath += '/' + parts[i];
            ino = lookupInDir(ino, parts[i]);
            if (ino === -1) return -1;

            const inode = readInode(ino);

            if ((inode.mode & S_IFMT) === S_IFLNK) {
                if (!followLinks && i === parts.length - 1) {
                    return ino;
                }

                const target = readSymlinkTarget(ino);
                if (!target) return -1;

                let resolvedTarget;
                if (target.startsWith('/')) {
                    resolvedTarget = target;
                } else {
                    const parentPath = currentPath.substring(0, currentPath.lastIndexOf('/')) || '/';
                    resolvedTarget = parentPath + '/' + target;
                }

                const remaining = parts.slice(i + 1).join('/');
                if (remaining) {
                    resolvedTarget += '/' + remaining;
                }

                return resolvePathInternal(resolvedTarget, followLinks, maxDepth - 1);
            }
        }

        return ino;
    }

    function resolvePath(path) {
        const cached = pathCache.get(path);
        if (cached !== undefined) return cached;

        const ino = resolvePathInternal(path, true);
        if (ino !== -1) pathCache.set(path, ino);
        return ino;
    }

    function lresolvePath(path) {
        return resolvePathInternal(path, false);
    }

    function resolveParent(path) {
        const parts = normalizePath(path).split('/').filter(p => p.length > 0);
        if (parts.length === 0) return [0, ''];
        const basename = parts.pop();
        const parentPath = '/' + parts.join('/');
        const parentIno = resolvePath(parentPath);
        return [parentIno, basename];
    }

    // Symlink helpers
    function readSymlinkTarget(ino) {
        const inode = readInode(ino);
        if ((inode.mode & S_IFMT) !== S_IFLNK) return null;

        const size = inode.size;
        if (size === 0) return '';

        const data = new Uint8Array(size);
        let pos = 0;
        let fileBlock = 0;

        while (pos < size) {
            const blkNum = getBlockNum(inode, fileBlock);
            if (blkNum === -1) break;

            const blkOff = blockOffset(blkNum);
            const chunkSize = Math.min(size - pos, BLOCK_SIZE);
            data.set(u8.slice(blkOff, blkOff + chunkSize), pos);
            pos += chunkSize;
            fileBlock++;
        }

        return new TextDecoder().decode(data);
    }

    // Mode helpers
    function modeToType(mode) {
        const type = mode & S_IFMT;
        switch (type) {
            case S_IFDIR: return DT_DIR;
            case S_IFREG: return DT_REG;
            case S_IFLNK: return DT_LNK;
            case S_IFBLK: return DT_BLK;
            case S_IFCHR: return DT_CHR;
            case S_IFIFO: return DT_FIFO;
            case S_IFSOCK: return DT_SOCK;
            default: return DT_UNKNOWN;
        }
    }

    // =========== PUBLIC API ===========

    function stat(path) {
        const ino = resolvePath(path);
        if (ino === -1) return null;
        const inode = readInode(ino);
        writeInode(ino, { atime: now() });
        return {
            ino,
            mode: inode.mode,
            nlink: inode.nlink,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            atime: inode.atime,
            mtime: inode.mtime,
            ctime: inode.ctime,
            blocks: inode.blocks,
            blksize: BLOCK_SIZE,
            isDirectory: (inode.mode & S_IFMT) === S_IFDIR,
            isFile: (inode.mode & S_IFMT) === S_IFREG,
            isSymlink: (inode.mode & S_IFMT) === S_IFLNK,
        };
    }

    function lstat(path) {
        const ino = lresolvePath(path);
        if (ino === -1) return null;
        const inode = readInode(ino);
        return {
            ino,
            mode: inode.mode,
            nlink: inode.nlink,
            uid: inode.uid,
            gid: inode.gid,
            size: inode.size,
            atime: inode.atime,
            mtime: inode.mtime,
            ctime: inode.ctime,
            blocks: inode.blocks,
            blksize: BLOCK_SIZE,
            isDirectory: (inode.mode & S_IFMT) === S_IFDIR,
            isFile: (inode.mode & S_IFMT) === S_IFREG,
            isSymlink: (inode.mode & S_IFMT) === S_IFLNK,
        };
    }

    function open(path, flags = 0, mode = 0o644) {
        const followLinks = !(flags & O_NOFOLLOW);
        let ino = followLinks ? resolvePath(path) : lresolvePath(path);

        if (ino === -1) {
            if (!(flags & O_CREAT)) return -1;

            const [parentIno, basename] = resolveParent(path);
            if (parentIno === -1) return -1;

            ino = allocInode();
            if (ino === -1) return -1;

            const t = now();
            writeInode(ino, {
                mode: S_IFREG | (mode & 0o7777),
                nlink: 1,
                uid: 0,
                gid: 0,
                size: 0,
                atime: t,
                mtime: t,
                ctime: t,
                blocks: 0,
            });

            if (!addDirEntry(parentIno, basename, ino, DT_REG)) {
                return -1;
            }
            pathCache.set(normalizePath(path), ino);
        }

        const inode = readInode(ino);
        if ((inode.mode & S_IFMT) === S_IFDIR) return -1;

        if (flags & O_TRUNC) {
            writeInode(ino, {
                size: 0,
                blocks: 0,
                mtime: now(),
                ctime: now(),
                direct: [0,0,0,0,0,0,0,0],
                indirect: 0,
                doubleIndirect: 0,
            });
        }

        const fd = nextFd++;
        fdTable.set(fd, {
            ino,
            path,
            flags,
            pos: (flags & O_APPEND) ? inode.size : 0,
        });
        return fd;
    }

    function close(fd) {
        if (!fdTable.has(fd)) return -1;
        fdTable.delete(fd);
        return 0;
    }

    function read(fd, buffer, count) {
        const file = fdTable.get(fd);
        if (!file) return -1;

        const inode = readInode(file.ino);
        if (file.pos >= inode.size) return 0;

        const toRead = Math.min(count, inode.size - file.pos);
        let bytesRead = 0;

        while (bytesRead < toRead) {
            const fileBlockIdx = Math.floor((file.pos + bytesRead) / BLOCK_SIZE);
            const blockOff = (file.pos + bytesRead) % BLOCK_SIZE;
            const blockNum = getBlockNum(inode, fileBlockIdx);

            const chunkSize = Math.min(toRead - bytesRead, BLOCK_SIZE - blockOff);

            if (blockNum === -1) {
                buffer.fill(0, bytesRead, bytesRead + chunkSize);
            } else {
                const dataOff = blockOffset(blockNum) + blockOff;
                buffer.set(u8.slice(dataOff, dataOff + chunkSize), bytesRead);
            }
            bytesRead += chunkSize;
        }

        file.pos += bytesRead;
        writeInode(file.ino, { atime: now() });
        return bytesRead;
    }

    function write(fd, buffer, count) {
        const file = fdTable.get(fd);
        if (!file) return -1;

        if (file.flags & O_APPEND) {
            const inode = readInode(file.ino);
            file.pos = inode.size;
        }

        let bytesWritten = 0;

        while (bytesWritten < count) {
            const fileBlockIdx = Math.floor((file.pos + bytesWritten) / BLOCK_SIZE);
            const blockOff = (file.pos + bytesWritten) % BLOCK_SIZE;

            const inode = readInode(file.ino);
            let blockNum = getBlockNum(inode, fileBlockIdx);

            if (blockNum === -1) {
                blockNum = allocBlockForFile(file.ino, fileBlockIdx);
                if (blockNum === -1) break;
            }

            const dataOff = blockOffset(blockNum) + blockOff;
            const chunkSize = Math.min(count - bytesWritten, BLOCK_SIZE - blockOff);
            u8.set(buffer.slice(bytesWritten, bytesWritten + chunkSize), dataOff);
            bytesWritten += chunkSize;
        }

        file.pos += bytesWritten;

        const inode = readInode(file.ino);
        const t = now();
        if (file.pos > inode.size) {
            writeInode(file.ino, { size: file.pos, mtime: t, ctime: t });
        } else {
            writeInode(file.ino, { mtime: t, ctime: t });
        }

        return bytesWritten;
    }

    function pread(fd, buffer, count, offset) {
        const file = fdTable.get(fd);
        if (!file) return -1;
        const savedPos = file.pos;
        file.pos = offset;
        const result = read(fd, buffer, count);
        file.pos = savedPos;
        return result;
    }

    function pwrite(fd, buffer, count, offset) {
        const file = fdTable.get(fd);
        if (!file) return -1;
        const savedPos = file.pos;
        file.pos = offset;
        const result = write(fd, buffer, count);
        file.pos = savedPos;
        return result;
    }

    function lseek(fd, offset, whence) {
        const file = fdTable.get(fd);
        if (!file) return -1;

        const inode = readInode(file.ino);

        switch (whence) {
            case 0: file.pos = offset; break;
            case 1: file.pos += offset; break;
            case 2: file.pos = inode.size + offset; break;
            default: return -1;
        }

        if (file.pos < 0) file.pos = 0;
        return file.pos;
    }

    function mkdir(path, mode = 0o755) {
        if (resolvePath(path) !== -1) return -1;

        const [parentIno, basename] = resolveParent(path);
        if (parentIno === -1) return -1;

        const ino = allocInode();
        if (ino === -1) return -1;

        const t = now();
        writeInode(ino, {
            mode: S_IFDIR | (mode & 0o7777),
            nlink: 2,
            uid: 0,
            gid: 0,
            size: 0,
            atime: t,
            mtime: t,
            ctime: t,
            blocks: 0,
        });

        if (!addDirEntry(parentIno, basename, ino, DT_DIR)) {
            return -1;
        }

        const parent = readInode(parentIno);
        writeInode(parentIno, { nlink: parent.nlink + 1, mtime: t, ctime: t });

        pathCache.set(normalizePath(path), ino);
        return 0;
    }

    function rmdir(path) {
        const ino = resolvePath(path);
        if (ino === -1) return -1;
        if (ino === 0) return -1;

        const inode = readInode(ino);
        if ((inode.mode & S_IFMT) !== S_IFDIR) return -1;

        const entries = readdir(path);
        if (entries && entries.length > 0) return -1;

        const [parentIno, basename] = resolveParent(path);
        if (parentIno === -1) return -1;

        removeDirEntry(parentIno, basename);

        const parent = readInode(parentIno);
        writeInode(parentIno, { nlink: Math.max(2, parent.nlink - 1), mtime: now(), ctime: now() });

        pathCache.delete(normalizePath(path));
        return 0;
    }

    function removeDirEntry(dirIno, name) {
        const dir = readInode(dirIno);
        if ((dir.mode & S_IFMT) !== S_IFDIR) return -1;

        const numBlocks = Math.ceil(dir.size / BLOCK_SIZE) || 1;

        for (let b = 0; b < numBlocks; b++) {
            const blkNum = getBlockNum(dir, b);
            if (blkNum === -1) continue;

            const blkOff = blockOffset(blkNum);
            for (let i = 0; i < DIRENTS_PER_BLOCK; i++) {
                const entOff = blkOff + i * DIRENT_SIZE;
                const entIno = view.getUint32(entOff, true);
                if (entIno === 0) continue;

                const nameLen = view.getUint16(entOff + 4, true);
                const entName = new TextDecoder().decode(u8.slice(entOff + 8, entOff + 8 + nameLen));

                if (entName === name) {
                    u8.fill(0, entOff, entOff + DIRENT_SIZE);
                    writeInode(dirIno, { mtime: now(), ctime: now() });
                    return entIno;
                }
            }
        }
        return -1;
    }

    function unlink(path) {
        const ino = lresolvePath(path);
        if (ino === -1) return -1;

        const inode = readInode(ino);
        if ((inode.mode & S_IFMT) === S_IFDIR) return -1;

        const [parentIno, basename] = resolveParent(path);
        if (parentIno === -1) return -1;

        removeDirEntry(parentIno, basename);

        const newNlink = inode.nlink - 1;
        if (newNlink === 0) {
            writeInode(ino, { mode: 0, nlink: 0 });
        } else {
            writeInode(ino, { nlink: newNlink, ctime: now() });
        }

        pathCache.delete(normalizePath(path));
        return 0;
    }

    function symlink(target, path) {
        if (lresolvePath(path) !== -1) return -1;

        const [parentIno, basename] = resolveParent(path);
        if (parentIno === -1) return -1;

        const ino = allocInode();
        if (ino === -1) return -1;

        const t = now();
        const targetBytes = new TextEncoder().encode(target);

        writeInode(ino, {
            mode: S_IFLNK | 0o777,
            nlink: 1,
            uid: 0,
            gid: 0,
            size: targetBytes.length,
            atime: t,
            mtime: t,
            ctime: t,
            blocks: 0,
        });

        let pos = 0;
        let fileBlock = 0;
        while (pos < targetBytes.length) {
            const blkNum = allocBlockForFile(ino, fileBlock);
            if (blkNum === -1) return -1;

            const blkOff = blockOffset(blkNum);
            const chunkSize = Math.min(targetBytes.length - pos, BLOCK_SIZE);
            u8.set(targetBytes.slice(pos, pos + chunkSize), blkOff);
            pos += chunkSize;
            fileBlock++;
        }

        if (!addDirEntry(parentIno, basename, ino, DT_LNK)) {
            return -1;
        }

        return 0;
    }

    function readlink(path) {
        const ino = lresolvePath(path);
        if (ino === -1) return null;
        return readSymlinkTarget(ino);
    }

    function link(oldPath, newPath) {
        const ino = resolvePath(oldPath);
        if (ino === -1) return -1;

        const inode = readInode(ino);
        if ((inode.mode & S_IFMT) === S_IFDIR) return -1;

        if (lresolvePath(newPath) !== -1) return -1;

        const [parentIno, basename] = resolveParent(newPath);
        if (parentIno === -1) return -1;

        if (!addDirEntry(parentIno, basename, ino, modeToType(inode.mode))) {
            return -1;
        }

        writeInode(ino, { nlink: inode.nlink + 1, ctime: now() });
        return 0;
    }

    function rename(oldPath, newPath) {
        const ino = lresolvePath(oldPath);
        if (ino === -1) return -1;

        const [oldParent, oldName] = resolveParent(oldPath);
        const [newParent, newName] = resolveParent(newPath);
        if (oldParent === -1 || newParent === -1) return -1;

        removeDirEntry(oldParent, oldName);

        const existingIno = lookupInDir(newParent, newName);
        if (existingIno !== -1) {
            removeDirEntry(newParent, newName);
        }

        const inode = readInode(ino);
        if (!addDirEntry(newParent, newName, ino, modeToType(inode.mode))) {
            return -1;
        }

        writeInode(ino, { ctime: now() });
        pathCache.clear();
        return 0;
    }

    function truncate(path, length) {
        const ino = resolvePath(path);
        if (ino === -1) return -1;

        const inode = readInode(ino);
        if ((inode.mode & S_IFMT) !== S_IFREG) return -1;

        writeInode(ino, { size: length, mtime: now(), ctime: now() });
        return 0;
    }

    function chmod(path, mode) {
        const ino = resolvePath(path);
        if (ino === -1) return -1;

        const inode = readInode(ino);
        writeInode(ino, {
            mode: (inode.mode & S_IFMT) | (mode & 0o7777),
            ctime: now()
        });
        return 0;
    }

    function chown(path, uid, gid) {
        const ino = resolvePath(path);
        if (ino === -1) return -1;

        const updates = { ctime: now() };
        if (uid !== -1) updates.uid = uid;
        if (gid !== -1) updates.gid = gid;
        writeInode(ino, updates);
        return 0;
    }

    function utimes(path, atime, mtime) {
        const ino = resolvePath(path);
        if (ino === -1) return -1;

        writeInode(ino, {
            atime: Math.floor(atime),
            mtime: Math.floor(mtime),
            ctime: now()
        });
        return 0;
    }

    function readdir(path) {
        const ino = resolvePath(path);
        if (ino === -1) return null;

        const inode = readInode(ino);
        if ((inode.mode & S_IFMT) !== S_IFDIR) return null;

        const entries = [];
        const numBlocks = Math.ceil(inode.size / BLOCK_SIZE) || 1;

        for (let b = 0; b < numBlocks; b++) {
            const blkNum = getBlockNum(inode, b);
            if (blkNum === -1) continue;

            const blkOff = blockOffset(blkNum);
            for (let i = 0; i < DIRENTS_PER_BLOCK; i++) {
                const entOff = blkOff + i * DIRENT_SIZE;
                const entIno = view.getUint32(entOff, true);
                if (entIno === 0) continue;

                const nameLen = view.getUint16(entOff + 4, true);
                const type = view.getUint16(entOff + 6, true);
                const name = new TextDecoder().decode(u8.slice(entOff + 8, entOff + 8 + nameLen));

                entries.push({ name, ino: entIno, type });
            }
        }

        writeInode(ino, { atime: now() });
        return entries;
    }

    function statfs() {
        const totalBlocks = view.getUint32(SB_TOTAL_BLOCKS, true);
        const inodeCount = view.getUint32(SB_INODE_COUNT, true);
        const freeInode = view.getUint32(SB_FREE_INODE, true);

        let freeBlocks = 0;
        let blk = view.getUint32(SB_FREE_BLOCK, true);
        while (blk !== 0xFFFFFFFF && blk !== 0 && freeBlocks < totalDataBlocks) {
            freeBlocks++;
            const off = dataBlocksOffset + blk * BLOCK_SIZE;
            blk = view.getUint32(off, true);
        }

        return {
            type: MAGIC,
            bsize: BLOCK_SIZE,
            blocks: totalDataBlocks,
            bfree: freeBlocks,
            bavail: freeBlocks,
            files: inodeCount,
            ffree: inodeCount - freeInode,
            namelen: MAX_NAME_LEN,
        };
    }

    function importFile(path, data, mode = 0o644) {
        const fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);
        if (fd === -1) return false;
        const written = write(fd, data, data.length);
        close(fd);
        return written === data.length;
    }

    function exportFile(path) {
        const st = stat(path);
        if (!st || st.isDirectory) return null;

        const fd = open(path, O_RDONLY);
        if (fd === -1) return null;

        const data = new Uint8Array(st.size);
        read(fd, data, st.size);
        close(fd);

        return data;
    }

    function getBuffer() { return sab; }
    function clearCache() { pathCache.clear(); }

    return {
        init,
        attach,
        getBuffer,
        clearCache,

        // Stat
        stat,
        lstat,
        statfs,

        // File ops
        open,
        close,
        read,
        write,
        pread,
        pwrite,
        lseek,
        truncate,

        // Directory ops
        mkdir,
        rmdir,
        readdir,

        // Link ops
        unlink,
        symlink,
        readlink,
        link,
        rename,

        // Permissions
        chmod,
        chown,
        utimes,

        // Bulk
        importFile,
        exportFile,

        // Constants
        O_RDONLY,
        O_WRONLY,
        O_RDWR,
        O_CREAT,
        O_EXCL,
        O_TRUNC,
        O_APPEND,
        O_NOFOLLOW,
        SEEK_SET: 0,
        SEEK_CUR: 1,
        SEEK_END: 2,
        S_IFMT,
        S_IFDIR,
        S_IFREG,
        S_IFLNK,
        S_IFBLK,
        S_IFCHR,
        S_IFIFO,
        S_IFSOCK,
        DT_UNKNOWN,
        DT_DIR,
        DT_REG,
        DT_LNK,
    };
})();

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SABFS;
} else if (typeof globalThis !== 'undefined') {
    globalThis.SABFS = SABFS;
}

// Worker support
(function setupWorkerSABFS() {
    const isWorker = typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope;
    if (isWorker) {
        self.addEventListener('message', function(e) {
            if (e.data && e.data.cmd === 'SABFS_BUFFER' && e.data.buffer instanceof SharedArrayBuffer) {
                try {
                    SABFS.attach(e.data.buffer);
                    console.log('[SABFS Worker] Attached to shared buffer');
                } catch (err) {
                    console.error('[SABFS Worker] Failed to attach:', err);
                }
            }
        });
        self.postMessage({ cmd: 'SABFS_REQUEST' });
        console.log('[SABFS Worker] Requested buffer from main thread');
    }
})();
