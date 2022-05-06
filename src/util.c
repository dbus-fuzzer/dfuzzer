/** @file util.c */

#include <assert.h>
#include <errno.h>
#include <gio/gio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

        assert(ret);

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
