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
#pragma once

#include "fuzz.h"

#define OBJECT_PATH_VALID_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                                "abcdefghijklmnopqrstuvwxyz" \
                                "0123456789_"

struct external_dictionary {
        size_t size;
        char **strings;
};

/**
 * @function Initializes global flag variables and seeds pseudo-random
 * numbers generators.
 */
void df_rand_init();
int df_rand_load_external_dictionary(const char *filename);

GVariant *df_generate_random_basic(const GVariantType *type, guint64 iteration);
GVariant *df_generate_random_from_signature(const char *signature, guint64 iteration);

size_t df_rand_array_size(guint64 iteration);

/**
 * @return Generated pseudo-random 8-bit unsigned integer value
 */
guint8 df_rand_guint8(guint64 iteration);

/**
 * @return Generated pseudo-random boolean value
 */
gboolean df_rand_gboolean(guint64 iteration);

/**
 * @return Generated pseudo-random 16-bit integer value
 */
gint16 df_rand_gint16(guint64 iteration);

/**
 * @return Generated pseudo-random 16-bit unsigned integer value
 */
guint16 df_rand_guint16(guint64 iteration);

/**
 * @return Generated pseudo-random 32-bit integer value
 */
gint32 df_rand_gint32(guint64 iteration);

/**
 * @return Generated pseudo-random 32-bit unsigned integer value
 */
guint32 df_rand_guint32(guint64 iteration);

/**
 * @return Generated pseudo-random 64-bit (long) integer value
 */
gint64 df_rand_gint64(guint64 iteration);

/**
 * @return Generated pseudo-random 64-bit (long) unsigned integer value
 */
guint64 df_rand_guint64(guint64 iteration);

/**
 * @return Generated pseudo-random double precision floating point number
 */
gdouble df_rand_gdouble(guint64 iteration);

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
int df_rand_string(gchar **buf, guint64 iteration);

/**
 * @function Allocates memory for pseudo-random object path string of size
 * counted by adding 1 to size variable on every call of function to maximum
 * size of MAX_OBJECT_PATH_LENGTH. On every call pseudo-random object path string is generated
 * into buf buffer.
 * Warning: buf should be freed outside this module by callee of this
 * function.
 * @param buf Address of pointer on buffer where generated object path string
 * will be stored
 * @return 0 on success, -1 on error
 */
int df_rand_dbus_objpath_string(gchar **buf, guint64 iteration);

/**
 * @function Allocates memory for pseudo-random signature string of size
 * counted by adding 1 to size variable on every call of function to maximum
 * size of MAX_SIGNATURE_LENGTH. On every call pseudo-random signature string is generated
 * by random access into global variable df_sig_def which contains all D-Bus
 * signatures and copying signature into buf buffer.
 * Warning: buf should be freed outside this module by callee of this
 * function.
 * @param buf Address of pointer on buffer where generated signature string
 * will be stored
 * @return 0 on success, -1 on error
 */
int df_rand_dbus_signature_string(gchar **buf, guint64 iteration);

/**
 * @function Creates Gvariant containing pseudo-random string. At the beginning
 * strings from global array df_str_def are used.
 * @param var Address of pointer on GVariant where new Gvariant value
 * will be stored
 * @return 0 on success, -1 on error
 */
int df_rand_GVariant(GVariant **var, guint64 iteration);

/**
 * @return Generated pseudo-random FD number from interval <-1, INT_MAX)
 */
int df_rand_unixFD(guint64 iteration);
