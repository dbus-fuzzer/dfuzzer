/** @file util.h */
#pragma once

static inline void g_object_unrefp(gpointer *gobj) {
        if (!*gobj)
                return;

        g_object_unref(*gobj);
}

static inline void closep(int *fd) {
        if (*fd < 0)
                return;

        close(*fd);
}

#define _cleanup_(x) __attribute__((__cleanup__(x)))
#define _cleanup_close_ _cleanup_(closep)

static inline int isempty(const char *s) {
        return !s || s[0] == '\0';
}

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


