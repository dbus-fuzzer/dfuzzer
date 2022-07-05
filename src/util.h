/** @file util.h */
#pragma once

#include <gio/gio.h>
#include <stdlib.h>
#include <unistd.h>

#define USEC_PER_SEC ((useconds_t) 1000000ULL)

typedef int fd_t;

static inline int safe_close(fd_t fd) {
        if (fd >= 0)
                close(fd);

        return -1;
}

static inline FILE *safe_fclose(FILE *f) {
        if (f)
                fclose(f);

        return NULL;
}

static inline GVariant *safe_g_variant_unref(GVariant *p) {
        if (p)
                g_variant_unref(p);

        return NULL;
}

static inline GVariantIter *safe_g_variant_iter_free(GVariantIter *p) {
        if (p)
                g_variant_iter_free(p);

        return NULL;
}

static inline GDBusProxy *safe_g_dbus_proxy_unref(GDBusProxy *p) {
        if (p)
                g_object_unref(p);

        return NULL;
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(FILE, safe_fclose)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(char, free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC(gchar, g_free)

G_DEFINE_AUTO_CLEANUP_FREE_FUNC(fd_t, safe_close, -1)

static inline int isempty(const char *s) {
        return !s || s[0] == '\0';
}

#define mfree(memory)                           \
        ({                                      \
                free(memory);                   \
                (typeof(memory)) NULL;          \
        })

/* Returns the number of chars needed to format variables of the
 * specified type as a decimal string. Adds in extra space for a
 * negative '-' prefix (hence works correctly on signed
 * types). Includes space for the trailing NUL. */
#define DECIMAL_STR_MAX(type)                                           \
        (2U+(sizeof(type) <= 1 ? 3U :                                   \
             sizeof(type) <= 2 ? 5U :                                   \
             sizeof(type) <= 4 ? 10U :                                  \
             sizeof(type) <= 8 ? 20U : sizeof(int[-2*(sizeof(type) > 8)])))

#define ELEMENTSOF(x)                                                   \
        (__builtin_choose_expr(                                         \
                !__builtin_types_compatible_p(typeof(x), typeof(&*(x))), \
                sizeof(x)/sizeof((x)[0]),                               \
                (void*)0))

#define STRV_FOREACH(i, strv) for (typeof(*(strv)) *_i = (strv), i; (i = *_i) && i; _i++)
#define STRV_FOREACH_COND(i, strv, cond) for (typeof(*(strv)) *_i = (strv), i; (cond) && (i = *_i) && i; _i++)

int safe_strtoull(const gchar *p, guint64 *ret);
char *strjoin_real(const char *x, ...) __attribute__((__sentinel__));
#define strjoin(a, ...) strjoin_real((a), __VA_ARGS__, NULL)

#define strjoina(a, ...)                                                \
        ({                                                              \
                const char *_appendees_[] = { a, __VA_ARGS__ };         \
                char *_d_, *_p_;                                        \
                size_t _len_ = 0;                                       \
                size_t _i_;                                             \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _len_ += strlen(_appendees_[_i_]);              \
                _p_ = _d_ = alloca(_len_ + 1);                          \
                for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) \
                        _p_ = stpcpy(_p_, _appendees_[_i_]);            \
                *_p_ = 0;                                               \
                _d_;                                                    \
        })

#define ANSI_RED        "\x1B[0;31m"
#define ANSI_GREEN      "\x1B[0;32m"
#define ANSI_YELLOW     "\x1B[0;33m"
#define ANSI_BLUE       "\x1B[0;34m"
#define ANSI_MAGENTA    "\x1B[0;35m"
#define ANSI_CYAN       "\x1B[0;36m"

#define ANSI_NORMAL     "\x1B[0m"
#define ANSI_BOLD       "\x1B[1m"

#define ANSI_CR         "\r"

static inline int df_isatty(void) {
        return isatty(STDOUT_FILENO) && isatty(STDERR_FILENO);
}

#define DEFINE_ANSI_FUNC(name, NAME)                       \
        static inline const char *ansi_##name(void) {      \
                return df_isatty() ? ANSI_##NAME : "";     \
        }

DEFINE_ANSI_FUNC(red,        RED);
DEFINE_ANSI_FUNC(green,      GREEN);
DEFINE_ANSI_FUNC(yellow,     YELLOW);
DEFINE_ANSI_FUNC(blue,       BLUE);
DEFINE_ANSI_FUNC(magenta,    MAGENTA);
DEFINE_ANSI_FUNC(cyan,       CYAN);
DEFINE_ANSI_FUNC(normal,     NORMAL);
DEFINE_ANSI_FUNC(bold,       BOLD);
DEFINE_ANSI_FUNC(cr,         CR);

int df_execute_external_command(const char *command, gboolean show_output);
