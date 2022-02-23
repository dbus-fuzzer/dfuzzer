/** @file rand.h */
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
#ifndef RAND_H
#define RAND_H

/** Minimal buffer size for generated strings */
#define MINLEN 512

/** Maximum buffer size for generated strings, default is cca 50 kB */
#define MAX_BUF_LEN 50000

/** Maximum length of strings containing D-Bus object path */
#define MAXLEN 256

/** Maximum length of D-Bus signature string */
#define MAXSIG 255

/** Maximum number of generations of non-string values (for functions
  * without string arguments) */
#define MAX_FUZZ_COUNTER 1000


/**
 * @function Initializes global flag variables and seeds pseudo-random
 * numbers generators.
 * @param buf_size Maximum buffer size for generated strings (in Bytes)
 */
void df_rand_init(const long buf_size);

/**
 * @return Generated pseudo-random 8-bit unsigned integer value
 */
guint8 df_rand_guint8(void);

/**
 * @return Generated pseudo-random boolean value
 */
gboolean df_rand_gboolean(void);

/**
 * @return Generated pseudo-random 16-bit integer value
 */
gint16 df_rand_gint16(void);

/**
 * @return Generated pseudo-random 16-bit unsigned integer value
 */
guint16 df_rand_guint16(void);

/**
 * @return Generated pseudo-random 32-bit integer value
 */
gint32 df_rand_gint32(void);

/**
 * @return Generated pseudo-random 32-bit unsigned integer value
 */
guint32 df_rand_guint32(void);

/**
 * @return Generated pseudo-random 64-bit (long) integer value
 */
gint64 df_rand_gint64(void);

/**
 * @return Generated pseudo-random 64-bit (long) unsigned integer value
 */
guint64 df_rand_guint64(void);

/**
 * @return Generated pseudo-random double precision floating point number
 * from interval <0, 1>
 */
inline double drand(void);

/**
 * @return Generated pseudo-random double precision floating point number
 */
gdouble df_rand_gdouble(void);

/**
 * @function Tells callee whether to continue testing according to current size
 * of generated strings not to exceed df_buf_size length.
 * @param fuzz_on_str_len If 1, fuzzing will be controlled by generated random
 * strings lengths
 * @return 1 when callee should continue, 0 otherwise
 */
int df_rand_continue(const int fuzz_on_str_len);

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
int df_rand_string(gchar **buf);

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
int df_rand_dbus_objpath_string(gchar **buf);

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
int df_rand_dbus_signature_string(gchar **buf);

/**
 * @function Creates Gvariant containing pseudo-random string. At the beginning
 * strings from global array df_str_def are used.
 * @param var Address of pointer on GVariant where new Gvariant value
 * will be stored
 * @return 0 on success, -1 on error
 */
int df_rand_GVariant(GVariant **var);

/**
 * @return Generated pseudo-random FD number from interval <-1, INT_MAX)
 */
int df_rand_unixFD(void);

#endif
