/** @file util.c */

#include <errno.h>
#include <fcntl.h>
#include <gio/gio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "util.h"
#include "log.h"

char *strjoin_real(const char *x, ...) {
        va_list ap;
        size_t l = 1;
        char *r, *p;

        va_start(ap, x);
        for (const char *t = x; t; t = va_arg(ap, const char *)) {
                size_t n;

                n = strlen(t);
                if (n > SIZE_MAX - l) {
                        va_end(ap);
                        return NULL;
                }
                l += n;
        }
        va_end(ap);

        p = r = malloc(l * sizeof(*p));
        if (!r)
                return NULL;

        va_start(ap, x);
        for (const char *t = x; t; t = va_arg(ap, const char *))
                p = stpcpy(p, t);
        va_end(ap);

        *p = 0;

        return r;
}

int safe_strtoull(const gchar *p, guint64 *ret)
{
        gchar *e = NULL;
        guint32 l;

        g_assert(ret);

        errno = 0;
        l = g_ascii_strtoull(p, &e, 10);
        if (errno > 0)
                return -errno;
        if (!e || e == p || *e != 0)
                return -EINVAL;
        if (*p == '-')
                return -ERANGE;

        *ret = l;

        return 0;
}

int df_execute_external_command(const char *command, gboolean show_output)
{
        pid_t pid;

        g_assert(command);

        pid = fork();

        if (pid < 0)
                return df_fail_ret(-1, "Failed to fork: %m\n");
        if (pid > 0) {
                /* Parent process */
                siginfo_t status;

                for (;;) {
                        if (waitid(P_PID, pid, &status, WEXITED) < 0) {
                                if (errno == EINTR)
                                        continue;

                                return df_fail_ret(-1, "Error when waiting for a child: %m\n");
                        }

                        break;
                }

                return status.si_status;
        }

        /* Child process */
        g_auto(fd_t) null_fd = -1;

        /* Redirect stdin/stdout/stderr to /dev/null */
        null_fd = open("/dev/null", O_RDWR);
        if (null_fd < 0)
                return df_fail_ret(-1, "Failed to open /dev/null: %m\n");

        for (guint8 i = 0; i < 3; i++) {
                if (i > 0 && show_output)
                        break;
                if (dup2(null_fd, i) < 0)
                        return df_fail_ret(-1, "Failed to replace fd %d with /dev/null: %m\n", i);
        }

        if (execl("/bin/sh", "sh", "-c", command, (char*) NULL) < 0)
                return df_fail_ret(-1, "Failed to execl(): %m\n");

        return 0;
}
