/** @file proc-util.c */
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>

#include "log.h"
#include "proc-util.h"
#include "util.h"

#if defined(__OpenBSD__)

#include <kvm.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

static kvm_t *safe_kvm_close(kvm_t *kd)
{
        if (kd)
                kvm_close(kd);

        return NULL;
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(kvm_t, safe_kvm_close)

int df_proc_is_alive(pid_t pid)
{
        g_autoptr(kvm_t) kd = NULL;
        struct kinfo_proc *kp;
        int cnt;

        g_assert(pid > 0);

        /* kill(pid, 0) is a portable liveness check - use it as the primary
         * mechanism here as well, and fall back to kvm only when we need to
         * check if the process is in the middle of exiting. */
        if (kill(pid, 0) < 0) {
                if (errno == ESRCH)
                        return 0;
                /* EPERM means that the process is still alive but we can't signal
                 * it (i.e. a different UID) */
                if (errno != EPERM)
                        return -1;
        }

        /* Try to detect if the process is in the middle of exiting via kvm. We
         * can't really check if the process is in the middle of a core dump as
         * we do when procfs is available, so this is the next best thing we
         * can do. If kvm fails for any reason, just trust the kill() result
         * above. */
        kd = kvm_open(/* execfile= */ NULL, /* corefile= */ NULL, /* swapfile= */ NULL, KVM_NO_FILES, /* errstr= */ NULL);
        if (!kd)
                return 1;

        kp = kvm_getprocs(kd, KERN_PROC_PID, pid, sizeof(*kp), &cnt);
        if (kp && cnt > 0) {
                /* P_WEXIT indicates the process is in the middle of exiting */
                if (kp->p_flag & P_WEXIT)
                        return 0;
        }

        return 1;
}

int df_proc_get_name(pid_t pid, char *buf, size_t bufsz)
{
        g_autoptr(kvm_t) kd = NULL;
        struct kinfo_proc *kp;
        char **argv;
        int cnt;

        g_assert(pid > 0);
        g_assert(buf);
        g_assert(bufsz > 0);

        kd = kvm_open(/* execfile= */ NULL, /* corefile= */ NULL, /* swapfile= */ NULL, KVM_NO_FILES, /* errstr= */ NULL);
        if (!kd)
                return -1;

        kp = kvm_getprocs(kd, KERN_PROC_PID, pid, sizeof(*kp), &cnt);
        if (!kp || cnt == 0)
                return -1;

        /* Try to get the full command line first */
        argv = kvm_getargv(kd, kp, 0);
        if (argv && argv[0]) {
                strncpy(buf, argv[0], bufsz - 1);
                buf[bufsz - 1] = '\0';
                return 0;
        }

        /* Otherwise fall back to the short process name */
        strncpy(buf, kp->p_comm, bufsz - 1);
        buf[bufsz - 1] = '\0';
        return 0;
}

int df_check_proc_available(void)
{
        /* There's no procfs since OpenBSD 5.7 and kvm/kill don't require any special filesystem */
        return 0;
}

#else /* Linux, FreeBSD, NetBSD, ... */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int df_proc_is_alive(pid_t pid)
{
        g_autoptr(FILE) f = NULL;
        g_autoptr(char) line = NULL;
        char proc_path[14 + DECIMAL_STR_MAX(pid_t)]; /* /proc/(pid_t)/status */
        size_t len = 0;
        int dumping;

        g_assert(pid > 0);

        sprintf(proc_path, "/proc/%d/status", pid);

        f = fopen(proc_path, "r");
        if (!f) {
                if (errno == ENOENT || errno == ENOTDIR || errno == ESRCH)
                        return 0;

                return -1;
        }

        /* Check if the process is not currently dumping a core */
        while (getline(&line, &len, f) > 0) {
                if (sscanf(line, "CoreDumping: %d", &dumping) == 1) {
                        if (dumping > 0)
                                return 0;

                        break;
                }
        }

        /* Assume the process exited if we fail while reading the stat file */
        if (ferror(f))
                return 0;

        return 1;
}

int df_proc_get_name(pid_t pid, char *buf, size_t bufsz)
{
        g_auto(fd_t) fd = -1;
        char proc_path[15 + DECIMAL_STR_MAX(pid_t)]; /* /proc/(pid_t)/[exe|cmdline] */
        int ret;

        g_assert(pid > 0);
        g_assert(buf);
        g_assert(bufsz > 0);

        /* Try readlink on /proc/PID/exe first */
        sprintf(proc_path, "/proc/%d/exe", pid);
        ret = readlink(proc_path, buf, bufsz - 1);
        if (ret > 0) {
                buf[ret] = '\0';

                /* If the executable is an interpreter, fall through to
                 * /proc/PID/cmdline to get the actual script name. */
                if (!strstr(buf, "python") && !strstr(buf, "perl"))
                        return 0;
        }

        /* Fall back to /proc/PID/cmdline */
        sprintf(proc_path, "/proc/%d/cmdline", pid);
        fd = open(proc_path, O_RDONLY);
        if (fd < 0)
                return -1;

        for (size_t i = 0; ; i++) {
                if (i >= bufsz - 1) {
                        buf[bufsz - 1] = '\0';
                        break;
                }

                ret = read(fd, buf + i, 1);
                if (ret < 0)
                        return -1;
                if (ret == 0) {
                        buf[i] = '\0';
                        break;
                }
                if (buf[i] == '\0')
                        break;
        }

        return 0;
}

int df_check_proc_available(void)
{
        struct stat sb;

        if (stat("/proc/1/status", &sb) < 0) {
                df_fail("Cannot access /proc/1/status: %s\n", strerror(errno));
                return -1;
        }

        return 0;
}

#endif
