/**
 * SABFS Loader - Browser integration for QEMU-wasm
 *
 * This script initializes SABFS and populates it with files before QEMU starts.
 * It should be loaded after sabfs.js and before QEMU's Module initialization.
 *
 * Usage:
 *   <script src="sabfs.js"></script>
 *   <script src="sabfs-loader.js"></script>
 *   <script>
 *     SABFSLoader.init({ size: 512 * 1024 * 1024 }).then(() => {
 *       // Start QEMU
 *     });
 *   </script>
 */

const SABFSLoader = (function() {
    'use strict';

    let initialized = false;
    let sabBuffer = null;

    /**
     * Initialize SABFS and create directory structure
     * @param {Object} options
     * @param {number} options.size - Filesystem size in bytes (default 256MB)
     * @param {string} options.rootPath - Path prefix for Docker data (default /docker)
     * @returns {Promise<SharedArrayBuffer>}
     */
    async function init(options = {}) {
        if (initialized) {
            console.warn('SABFSLoader already initialized');
            return sabBuffer;
        }

        const size = options.size || 256 * 1024 * 1024; // 256MB default
        const rootPath = options.rootPath || '/docker';

        console.log(`SABFSLoader: Initializing ${(size / 1024 / 1024).toFixed(0)}MB filesystem...`);

        // Initialize SABFS
        sabBuffer = SABFS.init(size);

        // Create Docker directory structure
        const dirs = [
            rootPath,
            `${rootPath}/overlay2`,
            `${rootPath}/overlay2/l`,      // layer links
            `${rootPath}/image`,
            `${rootPath}/image/overlay2`,
            `${rootPath}/containers`,
            `${rootPath}/volumes`,
            `${rootPath}/tmp`,
            `${rootPath}/buildkit`,
        ];

        for (const dir of dirs) {
            SABFS.mkdir(dir, 0o755);
        }

        console.log('SABFSLoader: Directory structure created');

        // Make SAB available to workers via Module
        if (typeof Module !== 'undefined') {
            Module.sabfsBuffer = sabBuffer;
        } else {
            // Module not yet defined, set up pre-init hook
            globalThis.Module = globalThis.Module || {};
            globalThis.Module.sabfsBuffer = sabBuffer;
        }

        initialized = true;
        return sabBuffer;
    }

    /**
     * Import files from Emscripten's MEMFS into SABFS
     * @param {string} memfsPath - Path in MEMFS (e.g., /pack)
     * @param {string} sabfsPath - Path in SABFS (e.g., /docker/pack)
     * @returns {Promise<number>} Number of files imported
     */
    async function importFromMEMFS(memfsPath, sabfsPath) {
        if (!initialized) {
            throw new Error('SABFSLoader not initialized');
        }

        // Ensure parent directories exist
        const parts = sabfsPath.split('/').filter(p => p);
        let path = '';
        for (const part of parts) {
            path += '/' + part;
            const st = SABFS.stat(path);
            if (!st) {
                SABFS.mkdir(path, 0o755);
            }
        }

        let count = 0;

        try {
            // Read MEMFS directory
            const entries = FS.readdir(memfsPath);

            for (const name of entries) {
                if (name === '.' || name === '..') continue;

                const srcPath = memfsPath + '/' + name;
                const dstPath = sabfsPath + '/' + name;

                try {
                    const stat = FS.stat(srcPath);

                    if (FS.isDir(stat.mode)) {
                        SABFS.mkdir(dstPath, stat.mode & 0o7777);
                        count += await importFromMEMFS(srcPath, dstPath);
                    } else if (FS.isFile(stat.mode)) {
                        const data = FS.readFile(srcPath);
                        if (SABFS.importFile(dstPath, data)) {
                            count++;
                            console.log(`SABFSLoader: Imported ${dstPath} (${data.length} bytes)`);
                        }
                    }
                } catch (e) {
                    console.warn(`SABFSLoader: Failed to import ${srcPath}:`, e);
                }
            }
        } catch (e) {
            console.error(`SABFSLoader: Failed to read ${memfsPath}:`, e);
        }

        return count;
    }

    /**
     * Import a single file
     * @param {string} path - Path in SABFS
     * @param {Uint8Array|ArrayBuffer|string} data - File contents
     * @returns {boolean}
     */
    function importFile(path, data) {
        if (!initialized) {
            throw new Error('SABFSLoader not initialized');
        }

        // Ensure parent directory exists
        const parentPath = path.substring(0, path.lastIndexOf('/'));
        if (parentPath) {
            const parts = parentPath.split('/').filter(p => p);
            let p = '';
            for (const part of parts) {
                p += '/' + part;
                if (!SABFS.stat(p)) {
                    SABFS.mkdir(p, 0o755);
                }
            }
        }

        // Convert data to Uint8Array if needed
        let bytes;
        if (data instanceof Uint8Array) {
            bytes = data;
        } else if (data instanceof ArrayBuffer) {
            bytes = new Uint8Array(data);
        } else if (typeof data === 'string') {
            bytes = new TextEncoder().encode(data);
        } else {
            throw new Error('Unsupported data type');
        }

        return SABFS.importFile(path, bytes);
    }

    /**
     * Pre-populate SABFS with container image layers
     * @param {Object} image - Image manifest
     * @param {Function} fetchLayer - Async function to fetch layer data
     * @returns {Promise<void>}
     */
    async function importImage(image, fetchLayer) {
        if (!initialized) {
            throw new Error('SABFSLoader not initialized');
        }

        console.log(`SABFSLoader: Importing image with ${image.layers.length} layers`);

        for (let i = 0; i < image.layers.length; i++) {
            const layer = image.layers[i];
            const layerPath = `/docker/overlay2/${layer.digest.replace('sha256:', '').substring(0, 12)}`;

            SABFS.mkdir(layerPath, 0o755);
            SABFS.mkdir(`${layerPath}/diff`, 0o755);

            console.log(`SABFSLoader: Fetching layer ${i + 1}/${image.layers.length}...`);
            const data = await fetchLayer(layer);

            // Store compressed layer
            importFile(`${layerPath}/layer.tar.gz`, data);

            console.log(`SABFSLoader: Layer ${layer.digest.substring(0, 19)}... imported (${data.length} bytes)`);
        }
    }

    /**
     * Get filesystem statistics
     * @returns {Object}
     */
    function getStats() {
        if (!initialized) {
            return { initialized: false };
        }

        // Read from superblock
        const buffer = SABFS.getBuffer();
        const view = new DataView(buffer);

        return {
            initialized: true,
            totalSize: buffer.byteLength,
            blockSize: view.getUint32(8, true),
            totalBlocks: view.getUint32(12, true),
            inodeCount: view.getUint32(16, true),
            freeBlockPtr: view.getUint32(20, true),
            freeInodePtr: view.getUint32(24, true),
        };
    }

    /**
     * Get the SharedArrayBuffer for passing to workers
     * @returns {SharedArrayBuffer|null}
     */
    function getBuffer() {
        return sabBuffer;
    }

    /**
     * Check if SABFS is initialized
     * @returns {boolean}
     */
    function isInitialized() {
        return initialized;
    }

    return {
        init,
        importFromMEMFS,
        importFile,
        importImage,
        getStats,
        getBuffer,
        isInitialized,
    };
})();

// Export for different environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SABFSLoader;
} else if (typeof globalThis !== 'undefined') {
    globalThis.SABFSLoader = SABFSLoader;
}
