#include <stdio.h>
#include <sys/stat.h>

#include "log.h"

static guint8 log_level_max = DF_LOG_LEVEL_INFO;
static FILE *log_file;

void df_set_log_level(guint8 log_level)
{
        g_assert(log_level < _DF_LOG_LEVEL_MAX);

        log_level_max = log_level;
}

guint8 df_get_log_level(void)
{
        return log_level_max;
}

int df_log_open_log_file(const char *file_name)
{
        g_assert(!log_file);

        (void) umask(0022);

        log_file = fopen(file_name, "a+");
        if (!log_file)
                return df_fail_ret(-1, "Failed to open file %s: %s\n", file_name, strerror(errno));

        return 0;
}

gboolean df_log_file_is_open(void)
{
        return !!log_file;
}

void df_log_file(const char *format, ...)
{
        if (log_file) {
                va_list args;

                va_start(args, format);
                vfprintf(log_file, format, args);
                va_end(args);
        }
}

void df_log_full(gint8 log_level, FILE *target, const char *format, ...)
{
        if (log_level > log_level_max)
                return;

        va_list args;

        va_start(args, format);
        vfprintf(target, format, args);
        va_end(args);
        fflush(target);
}

void df_error(const char *message, GError *error)
{
        if (log_level_max < DF_LOG_LEVEL_DEBUG)
                return;

        fprintf(stderr, "%s: %s\n", message, error->message ?: "n/a");
}
