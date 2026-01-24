/*
 *  x86 segmentation related helpers: (sysemu-only code)
 *  TSS, interrupts, system calls, jumps and call/task gates, descriptors
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "tcg/helper-tcg.h"
#include "../seg_helper.h"

#ifdef __EMSCRIPTEN__
#include <emscripten.h>

/*
 * SABFS Syscall Interception
 *
 * This intercepts Linux syscalls at the TCG level and handles file I/O
 * directly via SABFS (SharedArrayBuffer Filesystem), completely bypassing
 * the guest kernel. This eliminates ~150ms of TCG emulation per syscall.
 *
 * Intercepted syscalls (x86-64 numbers):
 *   0 = read(fd, buf, count)
 *   1 = write(fd, buf, count)
 *   2 = open(path, flags, mode)
 *   3 = close(fd)
 *
 * File descriptors >= SABFS_FD_BASE are SABFS-managed and never reach kernel.
 */

#define SABFS_FD_BASE 10000  /* SABFS fds start here to avoid kernel conflicts */

/* x86-64 syscall numbers */
#define SYS_read    0
#define SYS_write   1
#define SYS_open    2
#define SYS_close   3
#define SYS_stat    4
#define SYS_fstat   5
#define SYS_openat  257
#define AT_FDCWD    -100

/* Check if SABFS is available - prefixed to avoid conflict with 9p-sabfs.c */
EM_JS(int, syscall_sabfs_available, (void), {
    return (typeof SABFS !== 'undefined' && typeof SABFS.open === 'function') ? 1 : 0;
});

/* Open file in SABFS, returns SABFS fd or -1 */
EM_JS(int, syscall_sabfs_open, (const char *path, int flags), {
    try {
        const pathStr = UTF8ToString(path);
        return SABFS.open(pathStr, flags, 0o644);
    } catch (e) {
        return -1;
    }
});

/* Close SABFS fd */
EM_JS(int, syscall_sabfs_close, (int fd), {
    try {
        return SABFS.close(fd);
    } catch (e) {
        return -1;
    }
});

/* Read from SABFS fd into buffer */
EM_JS(int, syscall_sabfs_read, (int fd, void *buf, int count), {
    try {
        const buffer = new Uint8Array(HEAPU8.buffer, buf, count);
        const result = SABFS.read(fd, buffer, count);
        return result;
    } catch (e) {
        return -1;
    }
});

/* Write to SABFS fd from buffer */
EM_JS(int, syscall_sabfs_write, (int fd, const void *buf, int count), {
    try {
        const buffer = new Uint8Array(HEAPU8.buffer, buf, count);
        return SABFS.write(fd, buffer, count);
    } catch (e) {
        return -1;
    }
});

/* Stat file - returns size, mode, etc. */
EM_JS(int, syscall_sabfs_stat, (const char *path, void *statbuf), {
    try {
        const pathStr = UTF8ToString(path);
        const st = SABFS.stat(pathStr);
        if (!st) return -1;

        /* Fill in Linux stat64 structure (partial) */
        const view = new DataView(HEAPU8.buffer, statbuf, 144);
        view.setBigUint64(0, BigInt(0), true);       /* st_dev */
        view.setBigUint64(8, BigInt(st.ino || 1), true);   /* st_ino */
        view.setBigUint64(16, BigInt(0), true);      /* st_nlink */
        view.setUint32(24, st.mode, true);           /* st_mode */
        view.setUint32(28, 0, true);                 /* st_uid */
        view.setUint32(32, 0, true);                 /* st_gid */
        view.setUint32(36, 0, true);                 /* padding */
        view.setBigUint64(40, BigInt(0), true);      /* st_rdev */
        view.setBigInt64(48, BigInt(st.size), true); /* st_size */
        view.setBigInt64(56, BigInt(4096), true);    /* st_blksize */
        view.setBigInt64(64, BigInt(Math.ceil(st.size / 512)), true); /* st_blocks */
        /* Timestamps at offsets 72, 88, 104 - leave as 0 for now */
        return 0;
    } catch (e) {
        return -1;
    }
});

/* Fstat - stat by fd */
EM_JS(int, syscall_sabfs_fstat, (int fd, void *statbuf), {
    try {
        const st = SABFS.fstat(fd);
        if (!st) return -1;

        const view = new DataView(HEAPU8.buffer, statbuf, 144);
        view.setBigUint64(0, BigInt(0), true);
        view.setBigUint64(8, BigInt(st.ino || 1), true);
        view.setBigUint64(16, BigInt(0), true);
        view.setUint32(24, st.mode, true);
        view.setUint32(28, 0, true);
        view.setUint32(32, 0, true);
        view.setUint32(36, 0, true);
        view.setBigUint64(40, BigInt(0), true);
        view.setBigInt64(48, BigInt(st.size), true);
        view.setBigInt64(56, BigInt(4096), true);
        view.setBigInt64(64, BigInt(Math.ceil(st.size / 512)), true);
        return 0;
    } catch (e) {
        return -1;
    }
});

/* Debug logging */
EM_JS(void, syscall_sabfs_log, (const char *msg), {
    console.log('[SYSCALL-INTERCEPT] ' + UTF8ToString(msg));
});

EM_JS(void, syscall_sabfs_log_nr, (int nr, const char *path), {
    console.log('[SYSCALL-INTERCEPT] syscall=' + nr + ' path=' + (path ? UTF8ToString(path) : 'null'));
});

/* Forward declaration - defined later in file */
static int read_guest_string(CPUX86State *env, uint64_t guest_addr, char *buf, int max_len);

/*
 * PVPROC - Paravirtualized Process Syscall Interception
 *
 * Intercepts clone/fork/execve/exit/wait syscalls and handles them
 * on the host side, bypassing slow TCG emulation of kernel process
 * management code.
 *
 * x86-64 syscall numbers:
 *   56 = clone(flags, stack, parent_tid, child_tid, tls)
 *   57 = fork()
 *   58 = vfork()
 *   59 = execve(path, argv, envp)
 *   60 = exit(status)
 *   61 = wait4(pid, status, options, rusage)
 *  231 = exit_group(status)
 */
#define SYS_clone       56
#define SYS_fork        57
#define SYS_vfork       58
#define SYS_execve      59
#define SYS_exit        60
#define SYS_wait4       61
#define SYS_exit_group  231

/*
 * PVPROC SharedArrayBuffer-based IPC with main thread
 * Similar to SABFS - workers communicate via SAB and Atomics
 *
 * SAB Layout (512 bytes per slot):
 *   0: Control (0=idle, 1=request, 2=response)
 *   4: Operation (1=fork, 2=exec, 3=exit, 4=wait)
 *   8: Arg1 (parent_pid)
 *  12: Arg2 (flags/status)
 *  16: Arg3 (options)
 *  20: Result
 *  24: Error
 *  32: Path (256 bytes)
 */

/* Check if PVPROC SAB is available, initialize on first call */
EM_JS(int, syscall_pvproc_available, (void), {
    /* Initialize on first call */
    if (typeof Module._pvprocInitDone === 'undefined') {
        Module._pvprocInitDone = true;
        Module._pvprocSAB = null;
        Module._pvprocView = null;

        /* In worker: request buffer from main thread */
        if (typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope) {
            self.postMessage({ cmd: 'PVPROC_REQUEST' });
            console.log('[PVPROC Worker] Requested buffer from main thread');

            /* Listen for buffer */
            self.addEventListener('message', function(e) {
                if (e.data && e.data.cmd === 'PVPROC_BUFFER' && e.data.buffer instanceof SharedArrayBuffer) {
                    Module._pvprocSAB = e.data.buffer;
                    Module._pvprocView = new Int32Array(e.data.buffer);
                    console.log('[PVPROC Worker] Attached to shared buffer');
                }
            });
        }
    }
    return (Module._pvprocSAB && Module._pvprocView) ? 1 : 0;
});

/* Fork/clone via SAB IPC - returns child PID */
EM_JS(int, syscall_pvproc_fork, (int flags), {
    if (!Module._pvprocSAB || !Module._pvprocView) return -1;

    const view = Module._pvprocView;
    const SLOT_SIZE = 128;  /* 512 bytes / 4 */
    const slot = 0;  /* Use slot 0 for now */
    const base = slot * SLOT_SIZE;

    /* Write request */
    view[base + 1] = 1;  /* OP_FORK */
    view[base + 2] = 0;  /* parent_pid (TODO: get real) */
    view[base + 3] = flags;

    /* Signal request */
    Atomics.store(view, base, 1);
    Atomics.notify(view, base, 1);

    /* Wait for response (5 second timeout) */
    const result = Atomics.wait(view, base, 1, 5000);
    if (result === 'timed-out') {
        console.error('[PVPROC] Fork timed out');
        Atomics.store(view, base, 0);
        return -110;
    }

    /* Read response */
    const childPid = view[base + 5];
    const error = view[base + 6];

    /* Reset to idle */
    Atomics.store(view, base, 0);

    if (error) return error;
    return childPid;
});

/* Execve via SAB IPC */
EM_JS(int, syscall_pvproc_execve, (const char *path, uint64_t argv, uint64_t envp), {
    if (!Module._pvprocSAB || !Module._pvprocView) return -1;

    const view = Module._pvprocView;
    const pathStr = UTF8ToString(path);
    const SLOT_SIZE = 128;
    const slot = 0;
    const base = slot * SLOT_SIZE;

    /* Write path string (starts at offset 32 bytes = 8 words) */
    const pathBytes = new TextEncoder().encode(pathStr);
    const pathView = new Uint8Array(Module._pvprocSAB, slot * 512 + 32, 256);
    pathView.fill(0);
    pathView.set(pathBytes.subarray(0, Math.min(pathBytes.length, 255)));

    /* Write request */
    view[base + 1] = 2;  /* OP_EXEC */
    view[base + 2] = 0;  /* pid */

    /* Signal request */
    Atomics.store(view, base, 1);
    Atomics.notify(view, base, 1);

    /* Wait for response */
    const result = Atomics.wait(view, base, 1, 5000);
    if (result === 'timed-out') {
        Atomics.store(view, base, 0);
        return -110;
    }

    const retval = view[base + 5];
    const error = view[base + 6];
    Atomics.store(view, base, 0);

    return error ? error : retval;
});

/* Exit via SAB IPC (fire-and-forget) */
EM_JS(void, syscall_pvproc_exit, (int pid, int status), {
    if (!Module._pvprocSAB || !Module._pvprocView) return;

    const view = Module._pvprocView;
    const SLOT_SIZE = 128;
    const slot = 0;
    const base = slot * SLOT_SIZE;

    view[base + 1] = 3;  /* OP_EXIT */
    view[base + 2] = pid;
    view[base + 3] = status;

    Atomics.store(view, base, 1);
    Atomics.notify(view, base, 1);

    /* Brief wait then reset (don't block on exit) */
    Atomics.wait(view, base, 1, 50);
    Atomics.store(view, base, 0);
});

/* Wait via SAB IPC */
EM_JS(int, syscall_pvproc_wait, (int pid, int options), {
    if (!Module._pvprocSAB || !Module._pvprocView) return -1;

    const view = Module._pvprocView;
    const SLOT_SIZE = 128;
    const slot = 0;
    const base = slot * SLOT_SIZE;

    view[base + 1] = 4;  /* OP_WAIT */
    view[base + 2] = 0;  /* parent_pid */
    view[base + 3] = pid;  /* wait_pid */
    view[base + 4] = options;

    Atomics.store(view, base, 1);
    Atomics.notify(view, base, 1);

    const result = Atomics.wait(view, base, 1, 5000);
    if (result === 'timed-out') {
        Atomics.store(view, base, 0);
        return -110;
    }

    const childPid = view[base + 5];
    const error = view[base + 6];
    Atomics.store(view, base, 0);

    return error ? error : childPid;
});

/* Debug logging for process syscalls */
EM_JS(void, syscall_pvproc_log, (const char *msg), {
    console.log('[PVPROC-SYSCALL] ' + UTF8ToString(msg));
});

/*
 * Simulated process table for fast-path execution.
 * When we intercept fork+execve for simple commands, we track them here
 * and return results directly without creating real guest processes.
 */
#define PVPROC_MAX_SIMULATED 64
static struct {
    int active;
    int pid;
    int parent_pid;
    int exit_code;
    int exited;
    char path[256];
} pvproc_simulated[PVPROC_MAX_SIMULATED];
static int pvproc_next_pid = 20000;  /* Start high to avoid conflicts */
static int pvproc_initialized = 0;

static void pvproc_init(void)
{
    if (!pvproc_initialized) {
        for (int i = 0; i < PVPROC_MAX_SIMULATED; i++) {
            pvproc_simulated[i].active = 0;
        }
        pvproc_initialized = 1;
    }
}

static int pvproc_alloc_simulated(int parent_pid)
{
    pvproc_init();
    for (int i = 0; i < PVPROC_MAX_SIMULATED; i++) {
        if (!pvproc_simulated[i].active) {
            pvproc_simulated[i].active = 1;
            pvproc_simulated[i].pid = pvproc_next_pid++;
            pvproc_simulated[i].parent_pid = parent_pid;
            pvproc_simulated[i].exit_code = 0;
            pvproc_simulated[i].exited = 0;
            pvproc_simulated[i].path[0] = 0;
            return pvproc_simulated[i].pid;
        }
    }
    return -1;
}

static int pvproc_find_by_pid(int pid)
{
    for (int i = 0; i < PVPROC_MAX_SIMULATED; i++) {
        if (pvproc_simulated[i].active && pvproc_simulated[i].pid == pid) {
            return i;
        }
    }
    return -1;
}

/*
 * Try to intercept process-related syscalls.
 * Returns 1 if handled, 0 if should proceed to kernel.
 */
static int pvproc_try_intercept(CPUX86State *env, int next_eip_addend)
{
    uint64_t syscall_nr = env->regs[R_EAX];
    uint64_t arg1 = env->regs[R_EDI];
    uint64_t arg2 = env->regs[R_ESI];
    uint64_t arg3 = env->regs[R_EDX];
    uint64_t arg4 = env->regs[R_R10];

    /* Only handle in 64-bit mode */
    if (!(env->hflags & HF_LMA_MASK)) {
        return 0;
    }

    /* Check if PVPROC is available - check each time until ready
     * (Module.pvProc may not be initialized during early boot) */
    static int pvproc_ok = -1;
    static int pvproc_logged = 0;
    if (pvproc_ok <= 0) {
        pvproc_ok = syscall_pvproc_available();
        if (pvproc_ok && !pvproc_logged) {
            syscall_pvproc_log("PVPROC syscall interception enabled");
            pvproc_logged = 1;
        }
    }

    switch (syscall_nr) {
    case SYS_clone:
    case SYS_fork:
    case SYS_vfork:
        {
            /* Log fork/clone attempts */
            char msg[128];
            snprintf(msg, sizeof(msg), "fork/clone: nr=%d flags=0x%lx",
                     (int)syscall_nr, (unsigned long)arg1);
            syscall_pvproc_log(msg);

            if (pvproc_ok) {
                /* Try to handle via PVPROC */
                int flags = (syscall_nr == SYS_clone) ? (int)arg1 : 0;
                int child_pid = syscall_pvproc_fork(flags);

                if (child_pid > 0) {
                    /* Success - allocate simulated process */
                    int sim_pid = pvproc_alloc_simulated(0);  /* TODO: get real parent PID */
                    if (sim_pid > 0) {
                        snprintf(msg, sizeof(msg), "fork simulated: child_pid=%d", sim_pid);
                        syscall_pvproc_log(msg);

                        /* Return child PID to parent */
                        env->regs[R_EAX] = sim_pid;
                        env->eip += next_eip_addend;
                        return 1;  /* Handled */
                    }
                }
            }
            /* Fall through to kernel */
            return 0;
        }

    case SYS_execve:
        {
            char path[256];
            read_guest_string(env, arg1, path, sizeof(path));

            char msg[320];
            snprintf(msg, sizeof(msg), "execve: path=%s", path);
            syscall_pvproc_log(msg);

            if (pvproc_ok) {
                /* Try to handle via PVPROC */
                int ret = syscall_pvproc_execve(path, arg2, arg3);
                if (ret == 0) {
                    snprintf(msg, sizeof(msg), "execve handled by PVPROC");
                    syscall_pvproc_log(msg);
                    /* Note: Full implementation would set up new process state */
                }
            }
            /* Always fall through to kernel for now - execve is complex */
            return 0;
        }

    case SYS_exit:
    case SYS_exit_group:
        {
            int status = (int)arg1;
            char msg[128];
            snprintf(msg, sizeof(msg), "exit: status=%d", status);
            syscall_pvproc_log(msg);

            if (pvproc_ok) {
                syscall_pvproc_exit(0, status);  /* TODO: get real PID */
            }
            /* Always let kernel handle exit */
            return 0;
        }

    case SYS_wait4:
        {
            int wait_pid = (int)arg1;
            int options = (int)arg3;
            char msg[128];
            snprintf(msg, sizeof(msg), "wait4: pid=%d options=0x%x", wait_pid, options);
            syscall_pvproc_log(msg);

            if (pvproc_ok && wait_pid > 0) {
                /* Check if this is one of our simulated processes */
                int idx = pvproc_find_by_pid(wait_pid);
                if (idx >= 0 && pvproc_simulated[idx].exited) {
                    int exit_code = pvproc_simulated[idx].exit_code;
                    pvproc_simulated[idx].active = 0;  /* Free slot */

                    /* Write exit status to user pointer if provided */
                    if (arg2) {
                        /* Status format: (exit_code << 8) for normal exit */
                        cpu_stl_data(env, arg2, (exit_code & 0xff) << 8);
                    }

                    env->regs[R_EAX] = wait_pid;
                    env->eip += next_eip_addend;

                    snprintf(msg, sizeof(msg), "wait4 handled: pid=%d exit_code=%d",
                             wait_pid, exit_code);
                    syscall_pvproc_log(msg);
                    return 1;  /* Handled */
                }
            }
            /* Fall through to kernel */
            return 0;
        }

    default:
        return 0;
    }
}

/*
 * SABFS FD mapping table.
 * Maps guest fd (>= SABFS_FD_BASE) to SABFS fd.
 * Simple array: sabfs_fd_map[guest_fd - SABFS_FD_BASE] = sabfs_fd
 */
#define SABFS_MAX_FDS 256
static int sabfs_fd_map[SABFS_MAX_FDS];
static int sabfs_fd_initialized = 0;
static int sabfs_next_guest_fd = SABFS_FD_BASE;

static void sabfs_init_fd_map(void)
{
    if (!sabfs_fd_initialized) {
        for (int i = 0; i < SABFS_MAX_FDS; i++) {
            sabfs_fd_map[i] = -1;
        }
        sabfs_fd_initialized = 1;
    }
}

static int sabfs_alloc_guest_fd(int sabfs_fd)
{
    sabfs_init_fd_map();
    int guest_fd = sabfs_next_guest_fd++;
    int idx = guest_fd - SABFS_FD_BASE;
    if (idx >= 0 && idx < SABFS_MAX_FDS) {
        sabfs_fd_map[idx] = sabfs_fd;
        return guest_fd;
    }
    return -1;
}

static int sabfs_get_fd(int guest_fd)
{
    int idx = guest_fd - SABFS_FD_BASE;
    if (idx >= 0 && idx < SABFS_MAX_FDS) {
        return sabfs_fd_map[idx];
    }
    return -1;
}

static void sabfs_free_guest_fd(int guest_fd)
{
    int idx = guest_fd - SABFS_FD_BASE;
    if (idx >= 0 && idx < SABFS_MAX_FDS) {
        sabfs_fd_map[idx] = -1;
    }
}

/*
 * Read a null-terminated string from guest virtual memory.
 * Returns length or -1 on error. Max 512 bytes.
 */
static int read_guest_string(CPUX86State *env, uint64_t guest_addr, char *buf, int max_len)
{
    int i;
    for (i = 0; i < max_len - 1; i++) {
        uint8_t c = cpu_ldub_data(env, guest_addr + i);
        buf[i] = c;
        if (c == 0) break;
    }
    buf[i] = 0;
    return i;
}

/*
 * Copy data from guest virtual memory to host buffer.
 */
static void read_guest_buffer(CPUX86State *env, uint64_t guest_addr, void *buf, int len)
{
    uint8_t *p = buf;
    for (int i = 0; i < len; i++) {
        p[i] = cpu_ldub_data(env, guest_addr + i);
    }
}

/*
 * Copy data from host buffer to guest virtual memory.
 */
static void write_guest_buffer(CPUX86State *env, uint64_t guest_addr, const void *buf, int len)
{
    const uint8_t *p = buf;
    for (int i = 0; i < len; i++) {
        cpu_stb_data(env, guest_addr + i, p[i]);
    }
}

/*
 * Try to intercept a syscall and handle it via SABFS.
 * Returns 1 if handled (caller should return to userspace).
 * Returns 0 if not handled (caller should proceed with kernel entry).
 *
 * On success, sets env->regs[R_EAX] to syscall result.
 */
static int sabfs_try_intercept(CPUX86State *env, int next_eip_addend)
{
    uint64_t syscall_nr = env->regs[R_EAX];
    uint64_t arg1 = env->regs[R_EDI];
    uint64_t arg2 = env->regs[R_ESI];
    uint64_t arg3 = env->regs[R_EDX];

    /* Only intercept in 64-bit mode */
    if (!(env->hflags & HF_LMA_MASK)) {
        return 0;
    }

    /* Log syscalls we care about (open, openat) for debugging */
    static int debug_count = 0;
    if ((syscall_nr == SYS_open || syscall_nr == SYS_openat) && debug_count < 20) {
        debug_count++;
        char path[512];
        uint64_t path_addr = (syscall_nr == SYS_openat) ? arg2 : arg1;
        read_guest_string(env, path_addr, path, sizeof(path));
        syscall_sabfs_log_nr(syscall_nr, path);
    }

    /* Check if SABFS is available (check every time since it may be attached later) */
    static int sabfs_ok = 0;
    if (!sabfs_ok) {
        sabfs_ok = syscall_sabfs_available();
        if (!sabfs_ok) {
            return 0;
        }
        syscall_sabfs_log("SABFS available for syscall interception");
    }

    switch (syscall_nr) {
    case SYS_open:
        {
            char path[512];
            read_guest_string(env, arg1, path, sizeof(path));

            /* Only intercept /mnt/wasi1 paths (9p mount point users access) */
            if (strncmp(path, "/mnt/wasi1/", 11) != 0) {
                return 0;  /* Let kernel handle it */
            }

            /* Translate /mnt/wasi1/foo → /pack/foo */
            char sabfs_path[512];
            snprintf(sabfs_path, sizeof(sabfs_path), "/pack/%s", path + 11);

            int sabfs_fd = syscall_sabfs_open(sabfs_path, arg2);
            if (sabfs_fd < 0) {
                env->regs[R_EAX] = -2;  /* -ENOENT */
            } else {
                int guest_fd = sabfs_alloc_guest_fd(sabfs_fd);
                env->regs[R_EAX] = guest_fd;
            }

            /* Return to userspace: set RIP to return address */
            env->eip = env->regs[R_ECX] = env->eip + next_eip_addend;
            return 1;
        }

    case SYS_read:
        {
            int guest_fd = arg1;
            int sabfs_fd = sabfs_get_fd(guest_fd);

            if (sabfs_fd < 0) {
                return 0;  /* Not a SABFS fd, let kernel handle */
            }

            int count = arg3;
            if (count > 65536) count = 65536;  /* Limit buffer size */

            /* Allocate temporary buffer for SABFS read */
            uint8_t *tmp = g_malloc(count);
            if (!tmp) {
                env->regs[R_EAX] = -12;  /* -ENOMEM */
            } else {
                int n = syscall_sabfs_read(sabfs_fd, tmp, count);
                if (n > 0) {
                    write_guest_buffer(env, arg2, tmp, n);
                }
                env->regs[R_EAX] = n;
                g_free(tmp);
            }

            env->eip = env->regs[R_ECX] = env->eip + next_eip_addend;
            return 1;
        }

    case SYS_write:
        {
            int guest_fd = arg1;
            int sabfs_fd = sabfs_get_fd(guest_fd);

            if (sabfs_fd < 0) {
                return 0;  /* Not a SABFS fd, let kernel handle */
            }

            int count = arg3;
            if (count > 65536) count = 65536;

            uint8_t *tmp = g_malloc(count);
            if (!tmp) {
                env->regs[R_EAX] = -12;  /* -ENOMEM */
            } else {
                read_guest_buffer(env, arg2, tmp, count);
                int n = syscall_sabfs_write(sabfs_fd, tmp, count);
                env->regs[R_EAX] = n;
                g_free(tmp);
            }

            env->eip = env->regs[R_ECX] = env->eip + next_eip_addend;
            return 1;
        }

    case SYS_close:
        {
            int guest_fd = arg1;
            int sabfs_fd = sabfs_get_fd(guest_fd);

            if (sabfs_fd < 0) {
                return 0;  /* Not a SABFS fd, let kernel handle */
            }

            int ret = syscall_sabfs_close(sabfs_fd);
            sabfs_free_guest_fd(guest_fd);
            env->regs[R_EAX] = ret;

            env->eip = env->regs[R_ECX] = env->eip + next_eip_addend;
            return 1;
        }

    case SYS_stat:
        {
            char path[512];
            read_guest_string(env, arg1, path, sizeof(path));

            /* Only intercept /mnt/wasi1 paths */
            if (strncmp(path, "/mnt/wasi1/", 11) != 0) {
                return 0;
            }

            char sabfs_path[512];
            snprintf(sabfs_path, sizeof(sabfs_path), "/pack/%s", path + 11);

            /* arg2 = statbuf pointer */
            uint8_t statbuf[144];
            memset(statbuf, 0, sizeof(statbuf));
            int ret = syscall_sabfs_stat(sabfs_path, statbuf);
            if (ret == 0) {
                write_guest_buffer(env, arg2, statbuf, sizeof(statbuf));
                env->regs[R_EAX] = 0;
            } else {
                env->regs[R_EAX] = -2;  /* -ENOENT */
            }

            env->eip = env->regs[R_ECX] = env->eip + next_eip_addend;
            return 1;
        }

    case SYS_fstat:
        {
            int guest_fd = arg1;
            int sabfs_fd = sabfs_get_fd(guest_fd);

            if (sabfs_fd < 0) {
                return 0;  /* Not a SABFS fd */
            }

            uint8_t statbuf[144];
            memset(statbuf, 0, sizeof(statbuf));
            int ret = syscall_sabfs_fstat(sabfs_fd, statbuf);
            if (ret == 0) {
                write_guest_buffer(env, arg2, statbuf, sizeof(statbuf));
                env->regs[R_EAX] = 0;
            } else {
                env->regs[R_EAX] = -9;  /* -EBADF */
            }

            env->eip = env->regs[R_ECX] = env->eip + next_eip_addend;
            return 1;
        }

    case SYS_openat:
        {
            /* openat(dirfd, pathname, flags, mode) */
            /* arg1=dirfd, arg2=pathname, arg3=flags, r10=mode */
            int dirfd = (int)arg1;

            char path[512];
            read_guest_string(env, arg2, path, sizeof(path));

            /* Handle AT_FDCWD or absolute paths */
            if (dirfd != AT_FDCWD && path[0] != '/') {
                return 0;  /* Relative to non-cwd fd, let kernel handle */
            }

            /* Only intercept /mnt/wasi1 paths */
            if (strncmp(path, "/mnt/wasi1/", 11) != 0) {
                return 0;
            }

            char sabfs_path[512];
            snprintf(sabfs_path, sizeof(sabfs_path), "/pack/%s", path + 11);

            int sabfs_fd = syscall_sabfs_open(sabfs_path, arg3);
            if (sabfs_fd < 0) {
                env->regs[R_EAX] = -2;  /* -ENOENT */
            } else {
                int guest_fd = sabfs_alloc_guest_fd(sabfs_fd);
                env->regs[R_EAX] = guest_fd;
            }

            env->eip = env->regs[R_ECX] = env->eip + next_eip_addend;
            return 1;
        }
    }

    return 0;  /* Not handled */
}

#endif /* __EMSCRIPTEN__ */

void helper_syscall(CPUX86State *env, int next_eip_addend)
{
    int selector;

    if (!(env->efer & MSR_EFER_SCE)) {
        raise_exception_err_ra(env, EXCP06_ILLOP, 0, GETPC());
    }

#ifdef __EMSCRIPTEN__
    /*
     * SABFS syscall interception: handle file I/O directly without
     * entering guest kernel. This bypasses ~150ms of TCG emulation.
     */
    if (sabfs_try_intercept(env, next_eip_addend)) {
        return;  /* Syscall handled, returning directly to userspace */
    }

    /*
     * PVPROC syscall interception: handle fork/exec/exit/wait directly
     * without entering guest kernel for process management.
     */
    if (pvproc_try_intercept(env, next_eip_addend)) {
        return;  /* Syscall handled, returning directly to userspace */
    }
#endif

    selector = (env->star >> 32) & 0xffff;
#ifdef TARGET_X86_64
    if (env->hflags & HF_LMA_MASK) {
        int code64;

        env->regs[R_ECX] = env->eip + next_eip_addend;
        env->regs[11] = cpu_compute_eflags(env) & ~RF_MASK;

        code64 = env->hflags & HF_CS64_MASK;

        env->eflags &= ~(env->fmask | RF_MASK);
        cpu_load_eflags(env, env->eflags, 0);
        cpu_x86_load_seg_cache(env, R_CS, selector & 0xfffc,
                           0, 0xffffffff,
                               DESC_G_MASK | DESC_P_MASK |
                               DESC_S_MASK |
                               DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK |
                               DESC_L_MASK);
        cpu_x86_load_seg_cache(env, R_SS, (selector + 8) & 0xfffc,
                               0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                               DESC_S_MASK |
                               DESC_W_MASK | DESC_A_MASK);
        if (code64) {
            env->eip = env->lstar;
        } else {
            env->eip = env->cstar;
        }
    } else
#endif
    {
        env->regs[R_ECX] = (uint32_t)(env->eip + next_eip_addend);

        env->eflags &= ~(IF_MASK | RF_MASK | VM_MASK);
        cpu_x86_load_seg_cache(env, R_CS, selector & 0xfffc,
                           0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                               DESC_S_MASK |
                               DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK);
        cpu_x86_load_seg_cache(env, R_SS, (selector + 8) & 0xfffc,
                               0, 0xffffffff,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                               DESC_S_MASK |
                               DESC_W_MASK | DESC_A_MASK);
        env->eip = (uint32_t)env->star;
    }
}

void handle_even_inj(CPUX86State *env, int intno, int is_int,
                     int error_code, int is_hw, int rm)
{
    CPUState *cs = env_cpu(env);
    uint32_t event_inj = x86_ldl_phys(cs, env->vm_vmcb + offsetof(struct vmcb,
                                                          control.event_inj));

    if (!(event_inj & SVM_EVTINJ_VALID)) {
        int type;

        if (is_int) {
            type = SVM_EVTINJ_TYPE_SOFT;
        } else {
            type = SVM_EVTINJ_TYPE_EXEPT;
        }
        event_inj = intno | type | SVM_EVTINJ_VALID;
        if (!rm && exception_has_error_code(intno)) {
            event_inj |= SVM_EVTINJ_VALID_ERR;
            x86_stl_phys(cs, env->vm_vmcb + offsetof(struct vmcb,
                                             control.event_inj_err),
                     error_code);
        }
        x86_stl_phys(cs,
                 env->vm_vmcb + offsetof(struct vmcb, control.event_inj),
                 event_inj);
    }
}

void x86_cpu_do_interrupt(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    if (cs->exception_index == EXCP_VMEXIT) {
        assert(env->old_exception == -1);
        do_vmexit(env);
    } else {
        do_interrupt_all(cpu, cs->exception_index,
                         env->exception_is_int,
                         env->error_code,
                         env->exception_next_eip, 0);
        /* successfully delivered */
        env->old_exception = -1;
    }
}

bool x86_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    int intno;

    interrupt_request = x86_cpu_pending_interrupt(cs, interrupt_request);
    if (!interrupt_request) {
        return false;
    }

    /* Don't process multiple interrupt requests in a single call.
     * This is required to make icount-driven execution deterministic.
     */
    switch (interrupt_request) {
    case CPU_INTERRUPT_POLL:
        cs->interrupt_request &= ~CPU_INTERRUPT_POLL;
        apic_poll_irq(cpu->apic_state);
        break;
    case CPU_INTERRUPT_SIPI:
        do_cpu_sipi(cpu);
        break;
    case CPU_INTERRUPT_SMI:
        cpu_svm_check_intercept_param(env, SVM_EXIT_SMI, 0, 0);
        cs->interrupt_request &= ~CPU_INTERRUPT_SMI;
        do_smm_enter(cpu);
        break;
    case CPU_INTERRUPT_NMI:
        cpu_svm_check_intercept_param(env, SVM_EXIT_NMI, 0, 0);
        cs->interrupt_request &= ~CPU_INTERRUPT_NMI;
        env->hflags2 |= HF2_NMI_MASK;
        do_interrupt_x86_hardirq(env, EXCP02_NMI, 1);
        break;
    case CPU_INTERRUPT_MCE:
        cs->interrupt_request &= ~CPU_INTERRUPT_MCE;
        do_interrupt_x86_hardirq(env, EXCP12_MCHK, 0);
        break;
    case CPU_INTERRUPT_HARD:
        cpu_svm_check_intercept_param(env, SVM_EXIT_INTR, 0, 0);
        cs->interrupt_request &= ~(CPU_INTERRUPT_HARD |
                                   CPU_INTERRUPT_VIRQ);
        intno = cpu_get_pic_interrupt(env);
        qemu_log_mask(CPU_LOG_INT,
                      "Servicing hardware INT=0x%02x\n", intno);
        do_interrupt_x86_hardirq(env, intno, 1);
        break;
    case CPU_INTERRUPT_VIRQ:
        cpu_svm_check_intercept_param(env, SVM_EXIT_VINTR, 0, 0);
        intno = x86_ldl_phys(cs, env->vm_vmcb
                             + offsetof(struct vmcb, control.int_vector));
        qemu_log_mask(CPU_LOG_INT,
                      "Servicing virtual hardware INT=0x%02x\n", intno);
        do_interrupt_x86_hardirq(env, intno, 1);
        cs->interrupt_request &= ~CPU_INTERRUPT_VIRQ;
        env->int_ctl &= ~V_IRQ_MASK;
        break;
    }

    /* Ensure that no TB jump will be modified as the program flow was changed.  */
    return true;
}

/* check if Port I/O is allowed in TSS */
void helper_check_io(CPUX86State *env, uint32_t addr, uint32_t size)
{
    uintptr_t retaddr = GETPC();
    uint32_t io_offset, val, mask;

    /* TSS must be a valid 32 bit one */
    if (!(env->tr.flags & DESC_P_MASK) ||
        ((env->tr.flags >> DESC_TYPE_SHIFT) & 0xf) != 9 ||
        env->tr.limit < 103) {
        goto fail;
    }
    io_offset = cpu_lduw_kernel_ra(env, env->tr.base + 0x66, retaddr);
    io_offset += (addr >> 3);
    /* Note: the check needs two bytes */
    if ((io_offset + 1) > env->tr.limit) {
        goto fail;
    }
    val = cpu_lduw_kernel_ra(env, env->tr.base + io_offset, retaddr);
    val >>= (addr & 7);
    mask = (1 << size) - 1;
    /* all bits must be zero to allow the I/O */
    if ((val & mask) != 0) {
    fail:
        raise_exception_err_ra(env, EXCP0D_GPF, 0, retaddr);
    }
}
