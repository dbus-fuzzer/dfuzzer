#pragma once

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

enum {
        DF_LOG_LEVEL_INFO = 0,
        DF_LOG_LEVEL_VERBOSE,
        DF_LOG_LEVEL_DEBUG,
        _DF_LOG_LEVEL_MAX
};

void df_set_log_level(guint8 log_level);
guint8 df_get_log_level(void);
int df_log_open_log_file(const char *file_name);
gboolean df_log_file_is_open(void);

/* Normal logging */
void df_log_file(const char *format, ...) __attribute__((__format__(printf, 1, 2)));
void df_log_full(gint8 log_level, FILE *target, const char *format, ...) __attribute__((__format__(printf, 3, 4)));

#define df_log(...)         df_log_full(DF_LOG_LEVEL_INFO, stdout, __VA_ARGS__)
#define df_fail(...)        df_log_full(DF_LOG_LEVEL_INFO, stderr,  __VA_ARGS__)
#define df_verbose(...)     df_log_full(DF_LOG_LEVEL_VERBOSE, stdout, __VA_ARGS__)
#define df_debug(...)       df_log_full(DF_LOG_LEVEL_DEBUG, stdout, __VA_ARGS__)

void df_error(const char *message, GError *error);

/* Logging functions which return a value (i.e. can be used as part of a return statement) */
#define df_log_ret_internal(ret, fun, ...)          \
        ({                                          \
                fun(__VA_ARGS__);                   \
                ret;                                \
        })

#define df_oom(void)            df_log_ret_internal(-ENOMEM, df_fail, "Allocation error: %m\n")
#define df_fail_ret(ret, ...)   df_log_ret_internal(ret, df_fail, __VA_ARGS__)
#define df_debug_ret(ret, ...)  df_log_ret_internal(ret, df_debug, __VA_ARGS__)
