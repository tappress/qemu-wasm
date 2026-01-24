/**
 * SABFS - SharedArrayBuffer Filesystem
 *
 * A thread-safe filesystem that can be accessed directly from Web Workers
 * without going through Emscripten's main-thread proxy.
 *
 * Design:
 * - Fixed-size blocks (4KB)
 * - Simple inode-based structure
 * - All operations are synchronous and lock-free for reads
 * - Writes use Atomics for thread safety
 *
 * Memory Layout:
 * [Superblock 4KB][Inode Table][Data Blocks]
 *
 * Superblock (4KB):
 *   0-3:   magic (0x53414246 = "SABF")
 *   4-7:   version
 *   8-11:  block_size
 *   12-15: total_blocks
 *   16-19: inode_count
 *   20-23: free_block_ptr (next free block)
 *   24-27: free_inode_ptr (next free inode)
 *   28-31: root_inode
 *
 * Inode (64 bytes):
 *   0-3:   mode (file type + permissions)
 *   4-7:   size (low 32 bits)
 *   8-11:  size (high 32 bits)
 *   12-15: blocks (number of data blocks)
 *   16-19: direct[0] - block pointer
 *   20-23: direct[1]
 *   24-27: direct[2]
 *   28-31: direct[3]
 *   32-35: direct[4]
 *   36-39: direct[5]
 *   40-43: direct[6]
 *   44-47: direct[7]
 *   48-51: indirect (single indirect block)
 *   52-55: flags
 *   56-63: reserved
 *
 * Directory Entry (32 bytes):
 *   0-3:   inode
 *   4-5:   name_len
 *   6-7:   type
 *   8-31:  name (24 bytes, null-terminated)
 */

const SABFS = (function() {
    'use strict';

    // Constants
    const MAGIC = 0x53414246; // "SABF"
    const VERSION = 1;
    const BLOCK_SIZE = 4096;
    const INODE_SIZE = 64;
    const DIRENT_SIZE = 32;
    const DIRENTS_PER_BLOCK = Math.floor(BLOCK_SIZE / DIRENT_SIZE);
    const DIRECT_BLOCKS = 8;
    const PTRS_PER_BLOCK = Math.floor(BLOCK_SIZE / 4);

    // File types (matching Linux)
    const S_IFMT   = 0o170000;
    const S_IFDIR  = 0o040000;
    const S_IFREG  = 0o100000;
    const S_IFLNK  = 0o120000;

    // Superblock offsets
    const SB_MAGIC = 0;
    const SB_VERSION = 4;
    const SB_BLOCK_SIZE = 8;
    const SB_TOTAL_BLOCKS = 12;
    const SB_INODE_COUNT = 16;
    const SB_FREE_BLOCK = 20;
    const SB_FREE_INODE = 24;
    const SB_ROOT_INODE = 28;

    // Internal state
    let sab = null;
    let view = null;
    let u8 = null;
    let u32 = null;
    let inodeTableOffset = 0;
    let dataBlocksOffset = 0;

    // File descriptor table
    const fdTable = new Map();
    let nextFd = 3; // 0,1,2 reserved for stdin/stdout/stderr

    // Path cache for faster lookups
    const pathCache = new Map();

    /**
     * Initialize the filesystem with a SharedArrayBuffer
     * @param {number} sizeBytes - Total size in bytes (must be multiple of BLOCK_SIZE)
     * @param {Object} options - Options
     * @returns {SharedArrayBuffer} The created SAB
     */
    function init(sizeBytes, options = {}) {
        const totalBlocks = Math.floor(sizeBytes / BLOCK_SIZE);
        const inodeCount = options.inodeCount || Math.min(totalBlocks / 4, 65536);
        const inodeTableBlocks = Math.ceil((inodeCount * INODE_SIZE) / BLOCK_SIZE);

        // Create SharedArrayBuffer
        sab = new SharedArrayBuffer(sizeBytes);
        view = new DataView(sab);
        u8 = new Uint8Array(sab);
        u32 = new Uint32Array(sab);

        // Calculate offsets
        inodeTableOffset = BLOCK_SIZE; // After superblock
        dataBlocksOffset = inodeTableOffset + (inodeTableBlocks * BLOCK_SIZE);
        const dataBlocks = totalBlocks - 1 - inodeTableBlocks;

        // Initialize superblock
        view.setUint32(SB_MAGIC, MAGIC, true);
        view.setUint32(SB_VERSION, VERSION, true);
        view.setUint32(SB_BLOCK_SIZE, BLOCK_SIZE, true);
        view.setUint32(SB_TOTAL_BLOCKS, totalBlocks, true);
        view.setUint32(SB_INODE_COUNT, inodeCount, true);
        view.setUint32(SB_FREE_BLOCK, 0, true); // First data block is free
        view.setUint32(SB_FREE_INODE, 1, true); // Inode 0 is root, 1 is first free
        view.setUint32(SB_ROOT_INODE, 0, true);

        // Initialize free block list (each block points to next)
        for (let i = 0; i < dataBlocks - 1; i++) {
            const blockOffset = dataBlocksOffset + (i * BLOCK_SIZE);
            view.setUint32(blockOffset, i + 1, true);
        }
        // Last block points to -1 (end of list)
        view.setUint32(dataBlocksOffset + ((dataBlocks - 1) * BLOCK_SIZE), 0xFFFFFFFF, true);

        // Initialize root directory (inode 0)
        const rootInodeOffset = inodeTableOffset;
        view.setUint32(rootInodeOffset + 0, S_IFDIR | 0o755, true); // mode
        view.setUint32(rootInodeOffset + 4, 0, true);  // size low
        view.setUint32(rootInodeOffset + 8, 0, true);  // size high
        view.setUint32(rootInodeOffset + 12, 0, true); // blocks

        console.log(`SABFS initialized: ${totalBlocks} blocks, ${inodeCount} inodes, ${dataBlocks} data blocks`);

        return sab;
    }

    /**
     * Attach to an existing SharedArrayBuffer
     * @param {SharedArrayBuffer} existingSab
     */
    function attach(existingSab) {
        sab = existingSab;
        view = new DataView(sab);
        u8 = new Uint8Array(sab);
        u32 = new Uint32Array(sab);

        // Verify magic
        const magic = view.getUint32(SB_MAGIC, true);
        if (magic !== MAGIC) {
            throw new Error(`Invalid SABFS magic: ${magic.toString(16)}`);
        }

        const inodeCount = view.getUint32(SB_INODE_COUNT, true);
        const inodeTableBlocks = Math.ceil((inodeCount * INODE_SIZE) / BLOCK_SIZE);
        inodeTableOffset = BLOCK_SIZE;
        dataBlocksOffset = inodeTableOffset + (inodeTableBlocks * BLOCK_SIZE);

        console.log('SABFS attached');
    }

    /**
     * Allocate a free block
     * @returns {number} Block number or -1 if full
     */
    function allocBlock() {
        const freeBlock = Atomics.load(u32, SB_FREE_BLOCK / 4);
        if (freeBlock === 0xFFFFFFFF) return -1;

        const blockOffset = dataBlocksOffset + (freeBlock * BLOCK_SIZE);
        const nextFree = view.getUint32(blockOffset, true);

        // CAS to claim the block
        const result = Atomics.compareExchange(u32, SB_FREE_BLOCK / 4, freeBlock, nextFree);
        if (result !== freeBlock) {
            // Contention, retry
            return allocBlock();
        }

        // Zero the block
        u8.fill(0, blockOffset, blockOffset + BLOCK_SIZE);

        return freeBlock;
    }

    /**
     * Free a block
     * @param {number} blockNum
     */
    function freeBlock(blockNum) {
        const blockOffset = dataBlocksOffset + (blockNum * BLOCK_SIZE);

        while (true) {
            const freeHead = Atomics.load(u32, SB_FREE_BLOCK / 4);
            view.setUint32(blockOffset, freeHead, true);

            if (Atomics.compareExchange(u32, SB_FREE_BLOCK / 4, freeHead, blockNum) === freeHead) {
                break;
            }
        }
    }

    /**
     * Allocate a free inode
     * @returns {number} Inode number or -1 if full
     */
    function allocInode() {
        const inodeCount = view.getUint32(SB_INODE_COUNT, true);

        while (true) {
            const freeInode = Atomics.load(u32, SB_FREE_INODE / 4);
            if (freeInode >= inodeCount) return -1;

            if (Atomics.compareExchange(u32, SB_FREE_INODE / 4, freeInode, freeInode + 1) === freeInode) {
                // Zero the inode
                const inodeOffset = inodeTableOffset + (freeInode * INODE_SIZE);
                u8.fill(0, inodeOffset, inodeOffset + INODE_SIZE);
                return freeInode;
            }
        }
    }

    /**
     * Get inode offset in the buffer
     * @param {number} ino
     * @returns {number}
     */
    function inodeOffset(ino) {
        return inodeTableOffset + (ino * INODE_SIZE);
    }

    /**
     * Get data block offset in the buffer
     * @param {number} blockNum
     * @returns {number}
     */
    function blockOffset(blockNum) {
        return dataBlocksOffset + (blockNum * BLOCK_SIZE);
    }

    /**
     * Read inode data
     * @param {number} ino
     * @returns {Object}
     */
    function readInode(ino) {
        const off = inodeOffset(ino);
        const sizeLow = view.getUint32(off + 4, true);
        const sizeHigh = view.getUint32(off + 8, true);

        return {
            mode: view.getUint32(off + 0, true),
            size: sizeLow + (sizeHigh * 0x100000000),
            blocks: view.getUint32(off + 12, true),
            direct: [
                view.getUint32(off + 16, true),
                view.getUint32(off + 20, true),
                view.getUint32(off + 24, true),
                view.getUint32(off + 28, true),
                view.getUint32(off + 32, true),
                view.getUint32(off + 36, true),
                view.getUint32(off + 40, true),
                view.getUint32(off + 44, true),
            ],
            indirect: view.getUint32(off + 48, true),
            flags: view.getUint32(off + 52, true),
        };
    }

    /**
     * Write inode data
     * @param {number} ino
     * @param {Object} data
     */
    function writeInode(ino, data) {
        const off = inodeOffset(ino);

        if (data.mode !== undefined) view.setUint32(off + 0, data.mode, true);
        if (data.size !== undefined) {
            view.setUint32(off + 4, data.size & 0xFFFFFFFF, true);
            view.setUint32(off + 8, Math.floor(data.size / 0x100000000), true);
        }
        if (data.blocks !== undefined) view.setUint32(off + 12, data.blocks, true);
        if (data.direct) {
            for (let i = 0; i < DIRECT_BLOCKS; i++) {
                view.setUint32(off + 16 + (i * 4), data.direct[i] || 0, true);
            }
        }
        if (data.indirect !== undefined) view.setUint32(off + 48, data.indirect, true);
        if (data.flags !== undefined) view.setUint32(off + 52, data.flags, true);
    }

    /**
     * Get block number for a file offset
     * @param {Object} inode
     * @param {number} fileBlock - Block index within file
     * @returns {number} Block number or -1
     */
    function getBlockNum(inode, fileBlock) {
        if (fileBlock < DIRECT_BLOCKS) {
            const blk = inode.direct[fileBlock];
            return blk === 0 ? -1 : blk;
        }

        // Indirect block
        const indirectIdx = fileBlock - DIRECT_BLOCKS;
        if (indirectIdx >= PTRS_PER_BLOCK) {
            return -1; // Would need double indirect
        }

        if (inode.indirect === 0) return -1;

        const indirectOff = blockOffset(inode.indirect);
        return view.getUint32(indirectOff + (indirectIdx * 4), true);
    }

    /**
     * Allocate a block for a file at given file block index
     * @param {number} ino
     * @param {number} fileBlock
     * @returns {number} Block number or -1
     */
    function allocBlockForFile(ino, fileBlock) {
        const newBlock = allocBlock();
        if (newBlock === -1) return -1;

        const off = inodeOffset(ino);

        if (fileBlock < DIRECT_BLOCKS) {
            view.setUint32(off + 16 + (fileBlock * 4), newBlock, true);
        } else {
            const indirectIdx = fileBlock - DIRECT_BLOCKS;
            let indirect = view.getUint32(off + 48, true);

            if (indirect === 0) {
                indirect = allocBlock();
                if (indirect === -1) {
                    freeBlock(newBlock);
                    return -1;
                }
                view.setUint32(off + 48, indirect, true);
            }

            const indirectOff = blockOffset(indirect);
            view.setUint32(indirectOff + (indirectIdx * 4), newBlock, true);
        }

        // Update block count
        const blocks = view.getUint32(off + 12, true);
        view.setUint32(off + 12, blocks + 1, true);

        return newBlock;
    }

    /**
     * Look up a name in a directory
     * @param {number} dirIno
     * @param {string} name
     * @returns {number} Inode number or -1
     */
    function lookupInDir(dirIno, name) {
        const dir = readInode(dirIno);
        if ((dir.mode & S_IFMT) !== S_IFDIR) return -1;

        const numBlocks = Math.ceil(dir.size / BLOCK_SIZE);

        for (let b = 0; b < numBlocks; b++) {
            const blkNum = getBlockNum(dir, b);
            if (blkNum === -1) continue;

            const blkOff = blockOffset(blkNum);

            for (let i = 0; i < DIRENTS_PER_BLOCK; i++) {
                const entOff = blkOff + (i * DIRENT_SIZE);
                const entIno = view.getUint32(entOff, true);
                if (entIno === 0) continue;

                const nameLen = view.getUint16(entOff + 4, true);
                const entName = new TextDecoder().decode(u8.slice(entOff + 8, entOff + 8 + nameLen));

                if (entName === name) {
                    return entIno;
                }
            }
        }

        return -1;
    }

    /**
     * Add entry to directory
     * @param {number} dirIno
     * @param {string} name
     * @param {number} ino
     * @param {number} type
     * @returns {boolean}
     */
    function addDirEntry(dirIno, name, ino, type) {
        const dir = readInode(dirIno);
        if ((dir.mode & S_IFMT) !== S_IFDIR) return false;

        const nameBytes = new TextEncoder().encode(name);
        if (nameBytes.length > 24) return false;

        const numBlocks = Math.ceil(dir.size / BLOCK_SIZE) || 1;

        // Find free slot
        for (let b = 0; b < numBlocks; b++) {
            let blkNum = getBlockNum(dir, b);
            if (blkNum === -1) {
                blkNum = allocBlockForFile(dirIno, b);
                if (blkNum === -1) return false;
            }

            const blkOff = blockOffset(blkNum);

            for (let i = 0; i < DIRENTS_PER_BLOCK; i++) {
                const entOff = blkOff + (i * DIRENT_SIZE);
                const entIno = view.getUint32(entOff, true);

                if (entIno === 0) {
                    // Found free slot
                    view.setUint32(entOff, ino, true);
                    view.setUint16(entOff + 4, nameBytes.length, true);
                    view.setUint16(entOff + 6, type, true);
                    u8.set(nameBytes, entOff + 8);

                    // Update directory size if needed
                    const newSize = (b * BLOCK_SIZE) + ((i + 1) * DIRENT_SIZE);
                    if (newSize > dir.size) {
                        writeInode(dirIno, { size: newSize });
                    }

                    return true;
                }
            }
        }

        // Need new block
        const newBlockIdx = numBlocks;
        const blkNum = allocBlockForFile(dirIno, newBlockIdx);
        if (blkNum === -1) return false;

        const blkOff = blockOffset(blkNum);
        view.setUint32(blkOff, ino, true);
        view.setUint16(blkOff + 4, nameBytes.length, true);
        view.setUint16(blkOff + 6, type, true);
        u8.set(nameBytes, blkOff + 8);

        writeInode(dirIno, { size: (newBlockIdx * BLOCK_SIZE) + DIRENT_SIZE });

        return true;
    }

    /**
     * Resolve path to inode
     * @param {string} path
     * @returns {number} Inode number or -1
     */
    function resolvePath(path) {
        // Check cache
        if (pathCache.has(path)) {
            return pathCache.get(path);
        }

        const parts = path.split('/').filter(p => p.length > 0);
        let ino = 0; // Start at root

        for (const part of parts) {
            ino = lookupInDir(ino, part);
            if (ino === -1) return -1;
        }

        pathCache.set(path, ino);
        return ino;
    }

    /**
     * Get parent directory and basename
     * @param {string} path
     * @returns {[number, string]} [parent inode, basename]
     */
    function resolveParent(path) {
        const parts = path.split('/').filter(p => p.length > 0);
        if (parts.length === 0) return [0, ''];

        const basename = parts.pop();
        const parentPath = '/' + parts.join('/');
        const parentIno = resolvePath(parentPath);

        return [parentIno, basename];
    }

    // Public API

    /**
     * stat - get file status
     * @param {string} path
     * @returns {Object|null}
     */
    function stat(path) {
        const ino = resolvePath(path);
        if (ino === -1) return null;

        const inode = readInode(ino);
        return {
            ino,
            mode: inode.mode,
            size: inode.size,
            blocks: inode.blocks,
            isDirectory: (inode.mode & S_IFMT) === S_IFDIR,
            isFile: (inode.mode & S_IFMT) === S_IFREG,
        };
    }

    /**
     * open - open a file
     * @param {string} path
     * @param {number} flags - O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200
     * @param {number} mode - permissions for new file
     * @returns {number} File descriptor or -1
     */
    function open(path, flags = 0, mode = 0o644) {
        const O_CREAT = 0x40;
        const O_TRUNC = 0x200;

        let ino = resolvePath(path);

        if (ino === -1) {
            if (!(flags & O_CREAT)) return -1;

            // Create new file
            const [parentIno, basename] = resolveParent(path);
            if (parentIno === -1) return -1;

            ino = allocInode();
            if (ino === -1) return -1;

            writeInode(ino, {
                mode: S_IFREG | (mode & 0o7777),
                size: 0,
                blocks: 0,
            });

            if (!addDirEntry(parentIno, basename, ino, S_IFREG >> 12)) {
                return -1;
            }

            pathCache.set(path, ino);
        }

        const inode = readInode(ino);
        if ((inode.mode & S_IFMT) === S_IFDIR) {
            return -1; // Can't open directory as file
        }

        // Truncate if requested
        if (flags & O_TRUNC) {
            // TODO: free existing blocks
            writeInode(ino, { size: 0, blocks: 0 });
        }

        const fd = nextFd++;
        fdTable.set(fd, {
            ino,
            path,
            flags,
            pos: 0,
        });

        return fd;
    }

    /**
     * close - close file descriptor
     * @param {number} fd
     * @returns {number} 0 on success, -1 on error
     */
    function close(fd) {
        if (!fdTable.has(fd)) return -1;
        fdTable.delete(fd);
        return 0;
    }

    /**
     * read - read from file
     * @param {number} fd
     * @param {Uint8Array} buffer
     * @param {number} count
     * @returns {number} Bytes read or -1
     */
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

            if (blockNum === -1) {
                // Sparse file - return zeros
                const chunkSize = Math.min(toRead - bytesRead, BLOCK_SIZE - blockOff);
                buffer.fill(0, bytesRead, bytesRead + chunkSize);
                bytesRead += chunkSize;
            } else {
                const dataOff = blockOffset(blockNum) + blockOff;
                const chunkSize = Math.min(toRead - bytesRead, BLOCK_SIZE - blockOff);
                buffer.set(u8.slice(dataOff, dataOff + chunkSize), bytesRead);
                bytesRead += chunkSize;
            }
        }

        file.pos += bytesRead;
        return bytesRead;
    }

    /**
     * write - write to file
     * @param {number} fd
     * @param {Uint8Array} buffer
     * @param {number} count
     * @returns {number} Bytes written or -1
     */
    function write(fd, buffer, count) {
        const file = fdTable.get(fd);
        if (!file) return -1;

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

        // Update file size
        const inode = readInode(file.ino);
        if (file.pos > inode.size) {
            writeInode(file.ino, { size: file.pos });
        }

        return bytesWritten;
    }

    /**
     * pread - read at offset without changing position
     * @param {number} fd
     * @param {Uint8Array} buffer
     * @param {number} count
     * @param {number} offset
     * @returns {number}
     */
    function pread(fd, buffer, count, offset) {
        const file = fdTable.get(fd);
        if (!file) return -1;

        const savedPos = file.pos;
        file.pos = offset;
        const result = read(fd, buffer, count);
        file.pos = savedPos;
        return result;
    }

    /**
     * pwrite - write at offset without changing position
     * @param {number} fd
     * @param {Uint8Array} buffer
     * @param {number} count
     * @param {number} offset
     * @returns {number}
     */
    function pwrite(fd, buffer, count, offset) {
        const file = fdTable.get(fd);
        if (!file) return -1;

        const savedPos = file.pos;
        file.pos = offset;
        const result = write(fd, buffer, count);
        file.pos = savedPos;
        return result;
    }

    /**
     * lseek - reposition file offset
     * @param {number} fd
     * @param {number} offset
     * @param {number} whence - 0=SEEK_SET, 1=SEEK_CUR, 2=SEEK_END
     * @returns {number} New position or -1
     */
    function lseek(fd, offset, whence) {
        const file = fdTable.get(fd);
        if (!file) return -1;

        const inode = readInode(file.ino);

        switch (whence) {
            case 0: // SEEK_SET
                file.pos = offset;
                break;
            case 1: // SEEK_CUR
                file.pos += offset;
                break;
            case 2: // SEEK_END
                file.pos = inode.size + offset;
                break;
            default:
                return -1;
        }

        if (file.pos < 0) file.pos = 0;
        return file.pos;
    }

    /**
     * mkdir - create directory
     * @param {string} path
     * @param {number} mode
     * @returns {number} 0 on success, -1 on error
     */
    function mkdir(path, mode = 0o755) {
        if (resolvePath(path) !== -1) return -1; // Already exists

        const [parentIno, basename] = resolveParent(path);
        if (parentIno === -1) return -1;

        const ino = allocInode();
        if (ino === -1) return -1;

        writeInode(ino, {
            mode: S_IFDIR | (mode & 0o7777),
            size: 0,
            blocks: 0,
        });

        if (!addDirEntry(parentIno, basename, ino, S_IFDIR >> 12)) {
            return -1;
        }

        pathCache.set(path, ino);
        return 0;
    }

    /**
     * readdir - read directory entries
     * @param {string} path
     * @returns {Array|null}
     */
    function readdir(path) {
        const ino = resolvePath(path);
        if (ino === -1) return null;

        const inode = readInode(ino);
        if ((inode.mode & S_IFMT) !== S_IFDIR) return null;

        const entries = [];
        const numBlocks = Math.ceil(inode.size / BLOCK_SIZE);

        for (let b = 0; b < numBlocks; b++) {
            const blkNum = getBlockNum(inode, b);
            if (blkNum === -1) continue;

            const blkOff = blockOffset(blkNum);

            for (let i = 0; i < DIRENTS_PER_BLOCK; i++) {
                const entOff = blkOff + (i * DIRENT_SIZE);
                const entIno = view.getUint32(entOff, true);
                if (entIno === 0) continue;

                const nameLen = view.getUint16(entOff + 4, true);
                const type = view.getUint16(entOff + 6, true);
                const name = new TextDecoder().decode(u8.slice(entOff + 8, entOff + 8 + nameLen));

                entries.push({ name, ino: entIno, type });
            }
        }

        return entries;
    }

    /**
     * Import file data from Uint8Array
     * @param {string} path
     * @param {Uint8Array} data
     * @returns {boolean}
     */
    function importFile(path, data) {
        const fd = open(path, 0x40 | 0x200, 0o644); // O_CREAT | O_TRUNC
        if (fd === -1) return false;

        const written = write(fd, data, data.length);
        close(fd);

        return written === data.length;
    }

    /**
     * Export file data to Uint8Array
     * @param {string} path
     * @returns {Uint8Array|null}
     */
    function exportFile(path) {
        const st = stat(path);
        if (!st || st.isDirectory) return null;

        const fd = open(path, 0);
        if (fd === -1) return null;

        const data = new Uint8Array(st.size);
        read(fd, data, st.size);
        close(fd);

        return data;
    }

    /**
     * Get the underlying SharedArrayBuffer
     * @returns {SharedArrayBuffer}
     */
    function getBuffer() {
        return sab;
    }

    /**
     * Clear path cache (call after modifications)
     */
    function clearCache() {
        pathCache.clear();
    }

    return {
        init,
        attach,
        getBuffer,
        stat,
        open,
        close,
        read,
        write,
        pread,
        pwrite,
        lseek,
        mkdir,
        readdir,
        importFile,
        exportFile,
        clearCache,

        // Constants
        O_RDONLY: 0,
        O_WRONLY: 1,
        O_RDWR: 2,
        O_CREAT: 0x40,
        O_TRUNC: 0x200,
        O_APPEND: 0x400,

        SEEK_SET: 0,
        SEEK_CUR: 1,
        SEEK_END: 2,
    };
})();

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SABFS;
} else if (typeof globalThis !== 'undefined') {
    globalThis.SABFS = SABFS;
}

// Worker support: request SAB from main thread
// Workers post a request, main thread responds with the buffer
(function setupWorkerSABFS() {
    const isWorker = typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope;

    if (isWorker) {
        // In worker: listen for SABFS buffer from main thread
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
        // Request buffer from main thread
        self.postMessage({ cmd: 'SABFS_REQUEST' });
        console.log('[SABFS Worker] Requested buffer from main thread');
    }
})();
