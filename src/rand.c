/** @file rand.c */
/*
 * dfuzzer - tool for fuzz testing processes communicating through D-Bus.
 *
 * Copyright(C) 2013, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <assert.h>
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <stdint.h>

#include "rand.h"
#include "dfuzzer.h"
#include "util.h"


/** Maximum buffer size for generated strings (in Bytes) */
static size_t df_buf_size;
static struct external_dictionary df_external_dictionary;

/**
 * @function Initializes global flag variables and seeds pseudo-random
 * numbers generators.
 * @param buf_size Maximum buffer size for generated strings (in Bytes)
 */
void df_rand_init(const long buf_size)
{
        srand(time(NULL));  // for int rand()
        srandom(time(NULL));    // for long int random()

        if (buf_size < MINLEN)
                df_buf_size = MAX_BUF_LEN;
        else
                df_buf_size = buf_size;
}

int df_rand_load_external_dictionary(const char *filename)
{
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *line = NULL;
        char **array = NULL;
        size_t allocated = 0, len = 0, i = 0;
        ssize_t n;

        assert(filename);

        f = fopen(filename, "r");
        if (!f)
                return df_fail_ret(-errno, "Failed to open file '%s': %m\n", filename);

        while ((n = getline(&line, &len, f)) > 0) {
                /* Extend the array if we're out of space */
                if (i >= allocated) {
                        allocated += 10;
                        array = realloc(array, sizeof(array) * allocated);
                        if (!array)
                                return df_oom();
                }

                /* Drop the newline */
                if (line[n - 1] == '\n')
                        line[n - 1] = 0;

                array[i++] = TAKE_PTR(line);
        }

        df_external_dictionary.strings = TAKE_PTR(array);
        df_external_dictionary.size = i;

        return 0;
}
/**
 * @return Generated pseudo-random 8-bit unsigned integer value
 */
guint8 df_rand_guint8(guint64 iteration)
{
        switch (iteration) {
        case 0:
                return 0;
        case 1:
                return G_MAXUINT8;
        case 2:
                return G_MAXUINT8 / 2;
        default:
                return rand() % G_MAXUINT8;
        }
}

/**
 * @return Generated pseudo-random boolean value
 */
gboolean df_rand_gboolean(guint64 iteration)
{
        return ((gboolean) (iteration % 2));
}

/**
 * @return Generated pseudo-random 16-bit integer value
 */
gint16 df_rand_gint16(guint64 iteration)
{
        gint16 gi16;

        switch (iteration) {
        case 0:
                return G_MININT16;
        case 1:
                return G_MAXINT16;
        case 2:
                return 0;
        case 3:
                return G_MAXINT16 / 2;
        default:
                gi16 = rand() % G_MAXINT16;
                if (rand() % 2 == 0)
                        return (gi16 * -1) - 1;

                return gi16;
        }
}

/**
 * @return Generated pseudo-random 16-bit unsigned integer value
 */
guint16 df_rand_guint16(guint64 iteration)
{
        switch (iteration) {
        case 0:
                return 0;
        case 1:
                return G_MAXUINT16;
        case 2:
                return G_MAXUINT16 / 2;
        default:
                return rand() % G_MAXUINT16;
        }
}

/**
 * @return Generated pseudo-random 32-bit integer value
 */
gint32 df_rand_gint32(guint64 iteration)
{
        gint32 gi32;

        switch (iteration) {
        case 0:
                return G_MININT32;
        case 1:
                return G_MAXINT32;
        case 2:
                return 0;
        case 3:
                return G_MAXINT32 / 2;
        default:
                gi32 = rand() % G_MAXINT32;
                if (rand() % 2 == 0)
                        return (gi32 * -1) - 1;

                return gi32;
        }
}

/**
 * @return Generated pseudo-random 32-bit unsigned integer value
 */
guint32 df_rand_guint32(guint64 iteration)
{
        switch (iteration) {
        case 0:
                return 0;
        case 1:
                return G_MAXUINT32;
        case 2:
                return G_MAXUINT32 / 2;
        default:
                return rand() % G_MAXUINT32;
        }
}

/**
 * @return Generated pseudo-random 64-bit (long) integer value
 */
gint64 df_rand_gint64(guint64 iteration)
{
        gint64 gi64;

        switch (iteration) {
        case 0:
                return G_MININT64;
        case 1:
                return G_MAXINT64;
        case 2:
                return 0;
        case 3:
                return G_MAXINT64 / 2;
        default:
                gi64 = rand() % G_MAXINT64;
                if (rand() % 2 == 0)
                        return (gi64 * -1) - 1;

                return gi64;
        }
}

/**
 * @return Generated pseudo-random 64-bit (long) unsigned integer value
 */
guint64 df_rand_guint64(guint64 iteration)
{
        switch (iteration) {
        case 0:
                return 0;
        case 1:
                return G_MAXUINT64;
        case 2:
                return G_MAXUINT64 / 2;
        default:
                return rand() % G_MAXUINT64;
        }
}

/**
 * @return Generated pseudo-random double precision floating point number
 */
gdouble df_rand_gdouble(guint64 iteration)
{
        gdouble gdbl;

        switch (iteration) {
        case 0:
                return G_MAXDOUBLE;
        case 1:
                return G_MINDOUBLE;
        case 2:
                return 0;
        case 3:
                return G_MAXDOUBLE / 2.0;
        default:
                gdbl = (gdouble) random();
                gdbl += ((gdouble) rand() / RAND_MAX);

                if (rand() % 2 == 0)
                        return gdbl * -1.0;

                return gdbl;
        }
}

/**
 * @function Generates pseudo-random string of size size.
 * @param buf Pointer on buffer where generated string will be stored
 * @param size Size of buffer
 */
static void df_rand_random_string(char *buf, const long size)
{
        if (size < 1)
                return;

        long i;
        long n = size - 1;  // number of generated characters

        for (i = 0; i < n; ++i)
                buf[i] = rand() % (127 - 32) + 32;  // only printable characters
        buf[i] = '\0';
}

/**
 * @function Allocates memory for pseudo-random string of size counted
 * by adding generated pseudo-random number from interval <0, CHAR_MAX>
 * to df_str_len (this mechanism is responsible for generating bigger strings
 * by every call of df_rand_string()). Then pseudo-random string is generated
 * and stored in buf. At the beginning strings from global array df_str_def
 * are used. Warning: buf should be freed outside this module by callee
 * of this function.
 * @param buf Address of pointer on buffer where generated string
 * will be stored
 * @return 0 on success, -1 on error
 */
int df_rand_string(gchar **buf, guint64 iteration)
{
        /* List of strings that are used before we start generating random stuff */
        static const char *test_strings[] = {
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "%s%s%s%s%s%s%s%s%s%n%s%n%n%n%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n" \
                "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n",
                "bomb(){ bomb|bomb & }; bomb",
                ":1.285",
                "org.freedesktop.foo",
                "/org/freedesktop/foo",
                "",
                "\0",
                "systemd-localed.service",
                "/tmp/test",
                "verify-active",
                "IPAddressDeny",
                "Description",
                "127.0.0.1",
        };
        _cleanup_(g_freep) gchar *ret = NULL;
        size_t len;

        /* If -f/--string-file= was used, use the loaded strings instead of the
         * pre-defined ones, before generating random ones. */
        if (df_external_dictionary.size > 0) {
                if (iteration < df_external_dictionary.size) {
                        ret = strdup(df_external_dictionary.strings[iteration]);
                        if (!ret)
                                return df_fail_ret(-1, "Could not allocate memory for the random string\n");
                }
        } else if (iteration < G_N_ELEMENTS(test_strings)) {
                ret = strdup(test_strings[iteration]);
                if (!ret)
                        return df_fail_ret(-1, "Could not allocate memory for the random string\n");
        }

        if (!ret) {
                /* Genearate a pseudo-random string length in interval <0, df_buf_size) */
                len = (rand() * iteration) % df_buf_size;
                len = CLAMP(len, 1, df_buf_size);
                ret = g_try_new(gchar, len);
                if (!ret)
                        return df_fail_ret(-1, "Could not allocate memory for the random string\n");
                df_rand_random_string(ret, len);
        }

        *buf = TAKE_PTR(ret);

        return 0;
}

/**
 * @function Allocates memory for pseudo-random object path string of size
 * counted by adding 1 to size variable on every call of function to maximum
 * size of MAXLEN. On every call pseudo-random object path string is generated
 * into buf buffer.
 * Warning: buf should be freed outside this module by callee of this
 * function.
 * @param buf Address of pointer on buffer where generated object path string
 * will be stored
 * @return 0 on success, -1 on error
 */
int df_rand_dbus_objpath_string(gchar **buf, guint64 iteration)
{
        /* List of object paths that are used before we start generating random stuff */
        static const char *test_object_paths[] = {
                "/",
                "/a",
                "/0",
                "/_",
                "/\0/\0\0",
                "/a/a/a",
                "/0/0/0",
                "/_/_/_",
        };
        _cleanup_(g_freep) gchar *ret = NULL;
        guint16 size;
        int i, j, beg;

        if (iteration < G_N_ELEMENTS(test_object_paths)) {
                ret = strdup(test_object_paths[iteration]);
                if (!ret)
                        return df_fail_ret(-1, "Could not allocate memory for the random string\n");
        } else {
                size = (iteration % MAXLEN) + 9;

                // TODO: simplify
                ret = g_try_new(gchar, size + 1);
                if (!ret)
                        return df_fail_ret(-1, "Could not allocate memory for the random string\n");

                i = (size - 3) / 3;
                ret[0] = '/';
                beg = 1;
                for (j = 1; j <= i; j++) {
                        if (j == beg)   // objpath can begin only with character
                                ret[j] = rand() % (91 - 65) + 65;
                        else
                                ret[j] = rand() % (123 - 97) + 97;
                }
                ret[j++] = '/';
                beg = j;
                for (; j <= (i * 2); j++) {
                        if (j == beg)   // objpath can begin only with character
                                ret[j] = rand() % (91 - 65) + 65;
                        else
                                ret[j] = rand() % (123 - 97) + 97;
                }
                ret[j++] = '/';
                beg = j;
                for (; j <= (i * 3); j++) {
                        if (j == beg)   // objpath can begin only with character
                                ret[j] = rand() % (91 - 97) + 97;
                        else
                                ret[j] = rand() % (123 - 97) + 97;
                }
                ret[j] = '\0';
        }

        *buf = TAKE_PTR(ret);

        return 0;
}

/**
 * @function Allocates memory for pseudo-random signature string of size
 * counted by adding 1 to size variable on every call of function to maximum
 * size of MAXSIG. On every call pseudo-random signature string is generated
 * by random access into global variable df_sig_def which contains all D-Bus
 * signatures and copying signature into buf buffer.
 * Warning: buf should be freed outside this module by callee of this
 * function.
 * @param buf Address of pointer on buffer where generated signature string
 * will be stored
 * @return 0 on success, -1 on error
 */
int df_rand_dbus_signature_string(gchar **buf, guint64 iteration)
{
        /* TODO: support arrays ('a') and other complex types */
        static const char valid_signature_chars[] = "ybnqiuxtdsogvh";
        _cleanup_(g_freep) gchar *ret = NULL;
        uint16_t size, i = 0;

        size = (iteration % MAXSIG) + 1;

        ret = g_try_new(gchar, size + 1);
        if (!ret)
                return df_fail_ret(-1, "Could not allocate memory for the random string\n");

        for (i = 0; i < size; i++)
                ret[i] = valid_signature_chars[rand() % G_N_ELEMENTS(valid_signature_chars)];

        ret[i] = '\0';
        *buf = TAKE_PTR(ret);

        return 0;
}

/**
 * @function Creates Gvariant containing pseudo-random string. At the beginning
 * strings from global array df_str_def are used.
 * @param var Address of pointer on GVariant where new Gvariant value
 * will be stored
 * @return 0 on success, -1 on error
 */
int df_rand_GVariant(GVariant **var, guint64 iteration)
{
        _cleanup_(g_freep) gchar *str = NULL;
        int r;

        r = df_rand_string(&str, iteration);
        if (r < 0)
                return r;

        *var = g_variant_new("s", str);

        return 0;
}

/**
 * @return Generated pseudo-random FD number from interval <-1, INT_MAX)
 */
int df_rand_unixFD(guint64 iteration)
{
        int fd;

        switch (iteration) {
        case 0:
        case 1:
        case 2:
                return (int) iteration;
        case 3:
                return -1;
        default:
                fd = rand () % INT_MAX;
                if (rand () % 10 == 0)
                        fd *= -1;

                return fd;
        }
}
