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
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <stdint.h>

#include "rand.h"


/** Maximum buffer size for generated strings (in Bytes) */
static long df_buf_size;

/** Counter for fuzzing methods which have only numbers as their parameters.
  * Every call for some number generation increments this counter.
  * See function df_rand_continue() how this counter is used. */
static unsigned int df_num_fuzz_counter;

/* Flag variables for controlling pseudo-random numbers generation */
static unsigned short df_gu8f;
static unsigned short df_gi16f;
static unsigned short df_gu16f;
static unsigned short df_gi32f;
static unsigned short df_gu32f;
static unsigned short df_gi64f;
static unsigned short df_gu64f;
static unsigned short df_gdouf;

/** Length of  pseudo-random strings */
static long df_str_len;

/**
  * Array of strings, which will be send to tested process if it has any string
  * parameters. Feel free to include any strings here (only valid UTF-8).
  * Array must be terminated by NULL string.
  */
static const char *df_str_def[] = {
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "%s%s%s%s%s%s%s%s%s%n%s%n%n%n%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
        "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n" \
        "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n",
        "bomb(){ bomb|bomb & }; bomb",
        ":1.285",
        "org.freedesktop.foo",
        "/org/freedesktop/foo",
        NULL
};

/** Index into df_str_def array for function df_rand_string() */
static unsigned df_index_str;
/** Index into df_str_def array for function df_rand_GVariant() */
static unsigned df_index_var;

/**
  * Array of signature definitions, which will be send to tested process if it
  * has any signature parameters.
  */
static const char df_sig_def[16] = "ybnqiuxtdsogavh";


/* Module static functions */
static void df_rand_random_string(char *buf, const long size);


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

        df_gu8f = 0;
        df_gi16f = 0;
        df_gu16f = 0;
        df_gi32f = 0;
        df_gu32f = 0;
        df_gi64f = 0;
        df_gu64f = 0;
        df_gdouf = 0;

        df_num_fuzz_counter = 0;
        df_str_len = 0;
        df_index_str = 0;
        df_index_var = 0;
}

/**
 * @return Generated pseudo-random 8-bit unsigned integer value
 */
guint8 df_rand_guint8(void)
{
        guint8 gu8;

        if (df_gu8f < 100)
                gu8 = G_MAXUINT8;
        else if (df_gu8f < 200)
                gu8 = G_MAXUINT8 / 2;
        else if (df_gu8f < 250)
                gu8 = 0;
        else {
                gu8 = rand() % G_MAXUINT8;
                if ((rand() % 2) == 0)
                        gu8++;
        }

        if (df_gu8f < USHRT_MAX)
                df_gu8f++;
        else
                df_gu8f = 0;

        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
        return gu8;
}

/**
 * @return Generated pseudo-random boolean value
 */
gboolean df_rand_gboolean(void)
{
        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
        return ((gboolean) (rand() % 2));
}

/**
 * @return Generated pseudo-random 16-bit integer value
 */
gint16 df_rand_gint16(void)
{
        gint16 gi16;

        if (df_gi16f < 100)
                gi16 = G_MAXINT16;
        else if (df_gi16f < 200)
                gi16 = G_MAXINT16 / 2;
        else if (df_gi16f < 250)
                gi16 = 0;
        else {
                gi16 = rand() % G_MAXINT16;
                if ((rand() % 2) == 0)
                        gi16++;
        }

        // makes sure to test negative numbers
        if ((rand() % 2) == 0)
                gi16 = (gi16 * -1) - 1;

        if (df_gi16f < USHRT_MAX)
                df_gi16f++;
        else
                df_gi16f = 0;

        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
        return gi16;
}

/**
 * @return Generated pseudo-random 16-bit unsigned integer value
 */
guint16 df_rand_guint16(void)
{
        guint16 gu16;

        if (df_gu16f < 100)
                gu16 = G_MAXUINT16;
        else if (df_gu16f < 200)
                gu16 = G_MAXUINT16 / 2;
        else if (df_gu16f < 250)
                gu16 = 0;
        else {
                gu16 = rand() % G_MAXUINT16;
                if ((rand() % 2) == 0)
                        gu16++;
        }

        if (df_gu16f < USHRT_MAX)
                df_gu16f++;
        else
                df_gu16f = 0;

        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
        return gu16;
}

/**
 * @return Generated pseudo-random 32-bit integer value
 */
gint32 df_rand_gint32(void)
{
        gint32 gi32;

        if (df_gi32f < 100)
                gi32 = G_MAXINT32;
        else if (df_gi32f < 200)
                gi32 = G_MAXINT32 / 2;
        else if (df_gi32f < 250)
                gi32 = 0;
        else {
                gi32 = rand() % G_MAXINT32;
                if ((rand() % 2) == 0)
                        gi32++;
        }

        // makes sure to test negative numbers
        if ((rand() % 2) == 0)
                gi32 = (gi32 * -1) - 1;

        if (df_gi32f < USHRT_MAX)
                df_gi32f++;
        else
                df_gi32f = 0;

        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
        return gi32;
}

/**
 * @return Generated pseudo-random 32-bit unsigned integer value
 */
guint32 df_rand_guint32(void)
{
        guint32 gu32;

        if (df_gu32f < 100)
                gu32 = G_MAXUINT32;
        else if (df_gu32f < 200)
                gu32 = G_MAXUINT32 / 2;
        else if (df_gu32f < 250)
                gu32 = 0;
        else {
                gu32 = random() % G_MAXUINT32;
                if ((rand() % 2) == 0)
                        gu32++;
        }

        if (df_gu32f < USHRT_MAX)
                df_gu32f++;
        else
                df_gu32f = 0;

        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
        return gu32;
}

/**
 * @return Generated pseudo-random 64-bit (long) integer value
 */
gint64 df_rand_gint64(void)
{
        gint64 gi64;

        if (df_gi64f < 100)
                gi64 = G_MAXINT64;
        else if (df_gi64f < 200)
                gi64 = G_MAXINT64 / 2;
        else if (df_gi64f < 250)
                gi64 = 0;
        else {
                gi64 = random() % G_MAXINT64;
                if ((rand() % 2) == 0)
                        gi64++;
        }

        // makes sure to test negative numbers
        if ((rand() % 2) == 0)
                gi64 = (gi64 * -1) - 1;

        if (df_gi64f < USHRT_MAX)
                df_gi64f++;
        else
                df_gi64f = 0;

        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
        return gi64;
}

/**
 * @return Generated pseudo-random 64-bit (long) unsigned integer value
 */
guint64 df_rand_guint64(void)
{
        guint64 gu64;

        if (df_gu64f < 100)
                gu64 = G_MAXUINT64;
        else if (df_gu64f < 200)
                gu64 = G_MAXUINT64 / 2;
        else if (df_gu64f < 250)
                gu64 = 0;
        else {
                gu64 = random() % G_MAXUINT64;
                if ((rand() % 2) == 0)
                        gu64++;
        }

        if (df_gu64f < USHRT_MAX)
                df_gu64f++;
        else
                df_gu64f = 0;

        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
        return gu64;
}

/**
 * @return Generated pseudo-random double precision floating point number
 */
gdouble df_rand_gdouble(void)
{
        gdouble gdou;

        if (df_gdouf < 100)
                gdou = G_MAXDOUBLE;
        else if (df_gdouf < 200)
                gdou = G_MAXDOUBLE / 2.0;
        else if (df_gdouf < 250)
                gdou = 0.0;
        else if (df_gdouf < 350)
                gdou = G_MINDOUBLE;
        else {
                gdou = (double)random();
                gdou += drand();
                if ((rand() % 2) == 0)
                        gdou++;
        }

        if (gdou != 0.0 && (rand() % 2) == 0)
                gdou *= -1.0;

        if (df_gdouf < USHRT_MAX)
                df_gdouf++;
        else
                df_gdouf = 0;

        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
        return gdou;
}

/**
 * @function Tells callee whether to continue testing according to current size
 * of generated strings not to exceed df_buf_size length.
 * @param fuzz_on_str_len If 1, fuzzing will be controlled by generated random
 * strings lengths
 * @return 1 when callee should continue, 0 otherwise
 */
int df_rand_continue(const int fuzz_on_str_len, const int nargs)
{
        static int counter = 0; // makes sure to test biggest strings more times

       if (nargs == 0) {
               if (df_num_fuzz_counter == 10) {
                       df_num_fuzz_counter = 0;
                       return 0;
               }
               df_num_fuzz_counter++;
               return 1;
       }

        if (fuzz_on_str_len) {
                if (df_str_len >= df_buf_size) {
                        if (counter >= 10) {
                                counter = 0;
                                return 0;
                        }
                        counter++;
                }
        } else {
                if (df_num_fuzz_counter == MAX_FUZZ_COUNTER) {
                        df_num_fuzz_counter = 0;
                        return 0;
                }
        }

        return 1;
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
int df_rand_string(gchar **buf)
{
        df_str_len += (rand() % CHAR_MAX) + 1;
        if (df_str_len > df_buf_size)
                df_str_len = df_buf_size;

        if (df_str_def[df_index_str] != NULL)
                df_str_len = strlen(df_str_def[df_index_str]) + 1;

        *buf = malloc(sizeof(gchar) * df_str_len);
        if (*buf == NULL) {
                fprintf(stderr, "Error: Could not allocate memory for rand. string.\n");
                return -1;
        }

        if (df_str_def[df_index_str] != NULL) {
                strcpy(*buf, df_str_def[df_index_str]);
                df_index_str++;
                return 0;
        }

        df_rand_random_string(*buf, df_str_len);
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
int df_rand_dbus_objpath_string(gchar **buf)
{
        static short size = 9;
        size++;
        int i, j, beg;

        if (size > MAXLEN)
                size = MAXLEN;

        *buf = malloc(sizeof(gchar) * size + 1);
        if (*buf == NULL) {
                fprintf(stderr, "Error: Could not allocate memory for random D-Bus object path.\n");
                return -1;
        }

        i = (size - 3) / 3;
        (*buf)[0] = '/';
        beg = 1;
        for (j = 1; j <= i; j++) {
                if (j == beg)   // objpath can begin only with character
                        (*buf)[j] = rand() % (91 - 65) + 65;
                else
                        (*buf)[j] = rand() % (123 - 97) + 97;
        }
        (*buf)[j++] = '/';
        beg = j;
        for (; j <= (i * 2); j++) {
                if (j == beg)   // objpath can begin only with character
                        (*buf)[j] = rand() % (91 - 65) + 65;
                else
                        (*buf)[j] = rand() % (123 - 97) + 97;
        }
        (*buf)[j++] = '/';
        beg = j;
        for (; j <= (i * 3); j++) {
                if (j == beg)   // objpath can begin only with character
                        (*buf)[j] = rand() % (91 - 97) + 97;
                else
                        (*buf)[j] = rand() % (123 - 97) + 97;
        }
        (*buf)[j] = '\0';

        if (size == MAXLEN)
                size = 9;

        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
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
int df_rand_dbus_signature_string(gchar **buf)
{
        static uint16_t size = 1;
        size++;
        int i, j;

        if (size > MAXSIG)
                size = MAXSIG;

        *buf = malloc(sizeof(gchar) * size + 1);
        if (*buf == NULL) {
                fprintf(stderr, "Error: Could not allocate memory for random signature.\n");
                return -1;
        }

        for (j = 0; j < size; j++) {
                i = rand() % 15;
                (*buf)[j] = df_sig_def[i];
        }
        (*buf)[j] = '\0';

        if (size == MAXSIG)
                size = 1;

        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
        return 0;
}

/**
 * @function Creates Gvariant containing pseudo-random string. At the beginning
 * strings from global array df_str_def are used.
 * @param var Address of pointer on GVariant where new Gvariant value
 * will be stored
 * @return 0 on success, -1 on error
 */
int df_rand_GVariant(GVariant **var)
{
        gchar *buf;

        df_str_len += (rand() % CHAR_MAX) + 1;
        if (df_str_len > df_buf_size)
                df_str_len = df_buf_size;

        if (df_str_def[df_index_var] != NULL)
                df_str_len = strlen(df_str_def[df_index_var]) + 1;

        buf = malloc(sizeof(gchar) * df_str_len);
        if (buf == NULL) {
                fprintf(stderr, "Error: Could not allocate memory for random GVariant.\n");
                return -1;
        }

        if (df_str_def[df_index_var] != NULL) {
                strcpy(buf, df_str_def[df_index_var]);
                df_index_var++;
                *var = g_variant_new("s", buf);
                free(buf);
                return 0;
        }

        df_rand_random_string(buf, df_str_len);
        *var = g_variant_new("s", buf);
        free(buf);
        return 0;
}

/**
 * @return Generated pseudo-random FD number from interval <-1, INT_MAX)
 */
int df_rand_unixFD(void)
{
        if ((rand() % 10) == 0)
                return -1;

        int fd = rand() % INT_MAX;
        if (fd < 0)
                fd *= -1;

        if (df_num_fuzz_counter < MAX_FUZZ_COUNTER)
                df_num_fuzz_counter++;
        return fd;
}
