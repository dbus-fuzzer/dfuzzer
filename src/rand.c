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
#include <glib.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "rand.h"
#include "dfuzzer.h"
#include "util.h"

static struct external_dictionary df_external_dictionary;

/**
 * @function Initializes global flag variables and seeds pseudo-random
 * numbers generators.
 * @param buf_size Maximum buffer size for generated strings (in Bytes)
 */
void df_rand_init()
{
        srand(time(NULL));  // for int rand()
        srandom(time(NULL));    // for long int random()
}

int df_rand_load_external_dictionary(const char *filename)
{
        g_autoptr(FILE) f = NULL;
        g_autoptr(char) line = NULL;
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
                        array = realloc(array, sizeof(*array) * allocated);
                        if (!array)
                                return df_oom();
                }

                /* Drop the newline */
                if (line[n - 1] == '\n')
                        line[n - 1] = 0;

                array[i++] = g_steal_pointer(&line);
        }

        df_external_dictionary.strings = g_steal_pointer(&array);
        df_external_dictionary.size = i;

        return 0;
}

/* Generate a GVariant with random data for a basic (non-compound) type
 *
 * Note: variant itself is treated as a basic type, since it's a bit special and
 *       cannot be iterated on
 */
GVariant *df_generate_random_basic(const GVariantType *type, guint64 iteration)
{
        g_autoptr(char) ssig = NULL;

        if (!type) {
                g_assert_not_reached();
                return NULL;
        }

        ssig = g_variant_type_dup_string(type);

        if (g_variant_type_equal(type, G_VARIANT_TYPE_BOOLEAN))
                return g_variant_new(ssig, df_rand_gboolean(iteration));
        else if (g_variant_type_equal(type, G_VARIANT_TYPE_BYTE))
                return g_variant_new(ssig, df_rand_guint8(iteration));
        else if (g_variant_type_equal(type, G_VARIANT_TYPE_INT16))
                return g_variant_new(ssig, df_rand_gint16(iteration));
        else if (g_variant_type_equal(type, G_VARIANT_TYPE_UINT16))
                return g_variant_new(ssig, df_rand_guint16(iteration));
        else if (g_variant_type_equal(type, G_VARIANT_TYPE_INT32))
                return g_variant_new(ssig, df_rand_gint32(iteration));
        else if (g_variant_type_equal(type, G_VARIANT_TYPE_UINT32))
                return g_variant_new(ssig, df_rand_guint32(iteration));
        else if (g_variant_type_equal(type, G_VARIANT_TYPE_INT64))
                return g_variant_new(ssig, df_rand_gint64(iteration));
        else if (g_variant_type_equal(type, G_VARIANT_TYPE_UINT64))
                return g_variant_new(ssig, df_rand_guint64(iteration));
        else if (g_variant_type_equal(type, G_VARIANT_TYPE_HANDLE))
                return g_variant_new(ssig, df_rand_unixFD(iteration));
        else if (g_variant_type_equal(type, G_VARIANT_TYPE_DOUBLE))
                return g_variant_new(ssig, df_rand_gdouble(iteration));
        else if (g_variant_type_equal(type, G_VARIANT_TYPE_STRING)) {
                g_autoptr(char) str = NULL;

                if (df_rand_string(&str, iteration) < 0) {
                        df_fail("Failed to generate a random string\n");
                        return NULL;
                }

                return g_variant_new(ssig, str);
        } else if (g_variant_type_equal(type, G_VARIANT_TYPE_OBJECT_PATH)) {
                g_autoptr(char) obj_path = NULL;

                if (df_rand_dbus_objpath_string(&obj_path, iteration) < 0) {
                        df_fail("Failed to generate a random object path\n");
                        return NULL;
                }

                return g_variant_new(ssig, obj_path);
        } else if (g_variant_type_equal(type, G_VARIANT_TYPE_SIGNATURE)) {
                g_autoptr(char) sig_str = NULL;

                if (df_rand_dbus_signature_string(&sig_str, iteration) < 0) {
                        df_fail("Failed to generate a random signature string\n");
                        return NULL;
                }

                return g_variant_new(ssig, sig_str);
        } else if (g_variant_type_equal(type, G_VARIANT_TYPE_VARIANT)) {
                GVariant *variant = NULL;

                if (df_rand_GVariant(&variant, iteration) < 0) {
                        df_fail("Failed to generate a random GVariant\n");
                        return NULL;
                }

                return g_variant_new(ssig, variant);
        } else {
                df_fail("Invalid basic type: %s\n", ssig);
                g_assert_not_reached();
        }

        return NULL;
}

GVariant *df_generate_random_from_signature(const char *signature, guint64 iteration)
{
        g_autoptr(GVariantType) type = NULL;
        g_autoptr(GVariantBuilder) builder = NULL;

        if (!signature ||
            !g_variant_is_signature(signature) ||
            !g_variant_type_string_is_valid(signature)) {
                df_fail("Invalid signature: %s\n", signature);
                return NULL;
        }

        type = g_variant_type_new(signature);
        /* Leaf nodes */
        if (g_variant_type_is_basic(type) || g_variant_type_is_variant(type))
                return df_generate_random_basic(type, iteration);

        builder = g_variant_builder_new(type);

        for (const GVariantType *iter = g_variant_type_first(type);
             iter;
             iter = g_variant_type_next(iter)) {

                g_autoptr(char) ssig = NULL;

                ssig = g_variant_type_dup_string(iter);

                if (g_variant_type_is_basic(iter) || g_variant_type_is_variant(iter)) {
                        /* Basic type, generate a random value
                         * Note: treat 'variant' as a basic type, since it can't
                         *       be iterated on by g_variant_type_{first,next}()
                         */
                        GVariant *basic;

                        basic = df_generate_random_basic(iter, iteration);
                        if (!basic)
                                return NULL;

                        g_variant_builder_add_value(builder, basic);
                } else if (g_variant_type_is_tuple(iter)) {
                        /* Tuple */
                        GVariant *tuple = NULL;

                        tuple = df_generate_random_from_signature(ssig, iteration);
                        if (!tuple)
                                return NULL;

                        g_variant_builder_add_value(builder, tuple);
                } else if (g_variant_type_is_array(iter)) {
                        /* Array */
                        g_autoptr(char) array_signature = NULL;
                        const GVariantType *array_type = NULL;
                        int nest_level = 0;

                        /* Open the "main" array container */
                        g_variant_builder_open(builder, iter);

                        /* Resolve all levels of arrays (e.g. aaaai) */
                        for (array_type = g_variant_type_element(iter);
                             g_variant_type_is_array(array_type);
                             array_type = g_variant_type_element(array_type)) {

                                /* Open an container for each nested array */
                                g_variant_builder_open(builder, array_type);
                                nest_level++;
                        }

                        array_signature = g_variant_type_dup_string(array_type);

                        /* Create a pseudo-randomly sized array */
                        for (size_t i = 0; i < df_rand_array_size(iteration); i++) {
                                GVariant *array_item = NULL;

                                array_item = df_generate_random_from_signature(array_signature, iteration);
                                if (!array_item)
                                        return NULL;

                                g_variant_builder_add_value(builder, array_item);
                        }

                        /* Close container of each array level */
                        for (int i = 0; i < nest_level; i++)
                                g_variant_builder_close(builder);

                        /* Close the "main" array container */
                        g_variant_builder_close(builder);
                } else {
                        /* TODO: maybe */
                        df_fail("Not implemented: %s\n", ssig);
                        return NULL;
                }
        }

        return g_variant_builder_end(builder);
}


size_t df_rand_array_size(guint64 iteration)
{
        /* Generate an empty array on the first iteration */
        if (iteration == 0)
                return 0;

        return rand() % 10;
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

static gunichar df_rand_unichar(guint16 *width)
{
        gunichar uc = 0;

        /* If width is set to 0, generate a random width in the UTF-8 interval
         * (i.e. 1 - 4 bytes) and set the result as the value */
        if (*width == 0)
                *width = (rand() % 4) + 1;

        g_assert(*width > 0 && *width < 5);

        /* Not all characters in the UTF-8 range are valid, so we must try again
         * if we hit an invalid character */
        do
                switch (*width) {
                        case 1:
                                /* 1-byte wide character: [0x20, 0x7F], i.e. [32, 127]
                                 *
                                 * Skip the bottom 32, i.e. [0x0, 0x20) control characters.
                                 */
                                uc = rand() % (0x80 - 0x20) + 0x20;
                                break;
                        case 2:
                                /* 2-byte wide character: [0x80, 0x7FF], i.e. [128, 2047] */
                                uc = rand() % (0x800 - 0x80) + 0x80;
                                break;
                        case 3:
                                /* 3-byte wide character: [0x800, 0xFFFF], i.e. [2048, 65535] */
                                uc = rand() % (0x10000 - 0x800) + 0x800;
                                break;
                        case 4:
                                /* 4-byte wide character: [0x10000, 0x10FFFF], i.e. [65536 - 1114111] */
                                uc = rand() % (0x110000 - 0x10000) + 0x10000;
                                break;
                        default:
                                g_assert_not_reached();
                }
        while (!g_unichar_validate(uc));

        return uc;
}

/**
 * @function Generates pseudo-random string of size size.
 * @param buf Pointer on buffer where generated string will be stored
 * @param size Size of buffer
 */
static char *df_rand_random_string(size_t size)
{
        if (size == 0)
                return NULL;

        g_autoptr(GString) str = NULL;
        size_t str_size;

        str_size = size - 1;
        str = g_string_sized_new(size);

        for (size_t i = 0; i < str_size;) {
                /* If we have enough space, let df_rand_unichar() decide the
                 * width of the random character, otherwise specify it ourselves
                 * to fit into the remaining space */
                guint16 width = str_size - i > 4 ? 0 : str_size - i;
                gunichar uc;

                uc = df_rand_unichar(&width);
                str = g_string_append_unichar(str, uc);
                i += width;
        }

        /* "Steal" the internal C-string from the GString class to avoid another
         * unnecessary allocation */
        return g_steal_pointer(&str->str);
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
        g_autoptr(gchar) ret = NULL;
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
                /* Genearate a pseudo-random string length in interval <0, df_fuzz_get_buffer_length()) */
                len = (rand() * iteration) % df_fuzz_get_buffer_length();
                len = CLAMP(len, 1, df_fuzz_get_buffer_length());
                ret = df_rand_random_string(len);
        }

        *buf = g_steal_pointer(&ret);

        return 0;
}

/* Generate a pseudo-random object path */
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
        g_autoptr(gchar) ret = NULL;

        if (iteration < G_N_ELEMENTS(test_object_paths)) {
                ret = strdup(test_object_paths[iteration]);
                if (!ret)
                        return df_fail_ret(-1, "Could not allocate memory for the random string\n");
        } else {
                gint64 size, nelem, idx = 0;

                /* Rules for an object path:
                 *
                 * - it can be of any length
                 * - it must begin with a '/' and consist of elements separated by '/'
                 * - each element must only contain [A-Z][a-z][0-9]_
                 * - no element may be an empty string
                 *
                 * See: https://dbus.freedesktop.org/doc/dbus-specification.html
                 *      section 'Valid object paths;
                 */

                /* We need at least 2 characters for the shortest object path
                 * (e.g. "/a"), not counting the root object path ("/") */
                size = (iteration % (df_fuzz_get_buffer_length() - 2)) + 2;
                /* Calculate number of 'elements', i.e. the "/abc" parts in the object path.
                 * For that, lets calculate the maximum number of elements for given size
                 * (each element needs at least two characters, hence size/2) and
                 * we need at least one element (hence +-1). With that, generate
                 * a pseudo-random number of elements in interval <1, size/2> */
                nelem = (rand() % (size / 2 - 1)) + 1;

                ret = g_try_new(gchar, size + 1);
                if (!ret)
                        return df_fail_ret(-1, "Could not allocate memory for the random string\n");

                /* Now let's generate each element */
                for (gint64 i = 0; i < nelem; i++) {
                        /* Each element needs at least 2 characters, e.g. "/a", so let's reserve
                         * enough space for all following elements */
                        gint64 reserve = (nelem - i - 1) * 2;
                        /* Generate a pseudo-random size for the current element, taking the reserved
                         * space into consideration (i.e. the current element can take up to
                         * "remaining size - reserved size" bytes, but at least 2 bytes.
                         *
                         * Additionally, if we're the last element, use the remaining size in full */
                        gint64 elem_size = i + 1 == nelem ? size : (rand() % (size - reserve - 2)) + 2;
                        size -= elem_size;

                        ret[idx++] = '/';
                        /* Fill each element with pseudo-random characters from the list of allowed
                         * characters (as defined by the D-Bus spec) */
                        for (gint64 j = 0; j < elem_size - 1; j++)
                                ret[idx++] = OBJECT_PATH_VALID_CHARS[rand() % strlen(OBJECT_PATH_VALID_CHARS)];
                }

                ret[idx] = 0;
        }

        *buf = g_steal_pointer(&ret);

        return 0;
}

static inline char df_generate_random_signature_basic(void)
{
    return SIGNATURE_BASIC_TYPES[rand() % strlen(SIGNATURE_BASIC_TYPES)];
}

static void df_generate_random_signature(GString *str, gint16 size, guint16 nest_level, gboolean complete_type)
{
    const char *all_types = SIGNATURE_BASIC_TYPES "av({";
    size_t type_idx;

    g_assert(str);
    g_assert(size > 0 && size <= MAX_SIGNATURE_LENGTH);
    g_assert(nest_level <= MAX_SIGNATURE_NEST_LEVEL);

    for (gint16 i = 0; i < size;) {
        type_idx = rand() % strlen(all_types);

        if (type_idx < strlen(SIGNATURE_BASIC_TYPES) || all_types[type_idx] == 'v') {
            g_string_append_c(str, df_generate_random_signature_basic());
            i++;
        } else if (all_types[type_idx] == 'a') {
            /* Check if we have a room for the shortest array, i.e. "ax" */
            if (size - i - 2 < 0)
                continue;

            g_string_append_c(str, 'a');
            i++;

            /* As right now we're not a complete type, let's start the loop from
             * the beginning to fix that */
            continue;
        } else if (all_types[type_idx] == '(') {
            if (nest_level >= MAX_SIGNATURE_NEST_LEVEL)
                continue;

            /* Check if we have enough space for the shortest struct, i.e. "(x)" */
            gint16 max_struct_size = size - i - 2;
            gint16 struct_size, orig_str_length;

            if (max_struct_size < 1)
                continue;

            /* Generate a pseudo-random length for the struct. If we have a room for
             * only 1 element, use that length directly instead.
             *
             * Also, since we recursively call the df_generate_signature() function
             * to generate the struct, which itself might do the same, we need to know
             * how long the resulting struct is - do that by saving the current signature
             * string length and subtract it from the string length after we return from
             * df_generate_signature().
             */
            struct_size = max_struct_size == 1 ? max_struct_size : (rand() % (max_struct_size - 1)) + 1;
            orig_str_length = str->len;

            g_string_append_c(str, '(');
            /* Don't 'request' a single complete type, since we want to utilize the full length
             * of the possible struct and we ourselves ensure the type will be complete */
            df_generate_random_signature(str, struct_size, nest_level++, /* complete= */ FALSE);
            g_string_append_c(str, ')');
            i += (str->len - orig_str_length);
        } else if (all_types[type_idx] == '{') {
            if (nest_level >= MAX_SIGNATURE_NEST_LEVEL)
                continue;
            /* For dictionaries we need to meet a couple of conditions:
             *  - dictionaries may appear only as an array element type - to increase the likelihood
             *    of having a dictionary in the final signature, let's add the array element ourselves
             *    if it's not already the last element of the signature
             *  - the "key" of the dictionary must be a basic type
             *  - the "value" of the dictionary must be a single complete type
             */
            gboolean prev_is_array = str->str[str->len] == 'a';
            gint16 max_value_size = size - i - (prev_is_array ? 3 : 4);
            gint16 value_size, orig_str_length;

            if (max_value_size < 1)
                continue;

            /* Similarly to structs, generate a random size of the dict "value", and
             * store the current signature string length, so we can later determine
             * how many bytes were added in total */
            value_size = max_value_size == 1 ? max_value_size : (rand() % (max_value_size - 1)) + 1;
            orig_str_length = str->len;

            /* If the last element of the signature is not an array, add it ourselves */
            if (!prev_is_array)
                g_string_append_c(str, 'a');
            g_string_append_c(str, '{');
            /* The dictionary "key" must be a basic type */
            g_string_append_c(str, df_generate_random_signature_basic());
            /* The dictionary "value" must be a single complete type */
            df_generate_random_signature(str, value_size, nest_level++, /* complete= */ TRUE);
            g_string_append_c(str, '}');
            i += (str->len - orig_str_length);
        } else
            g_assert_not_reached();

        /* If a single complete type was requested, break out of the loop, since
         * at this point we should have just that, once the stack unwinds */
        if (complete_type)
            break;
    }
}

int df_rand_dbus_signature_string(gchar **buf, guint64 iteration)
{
        g_autoptr(GString) signature = NULL;
        guint16 size;

        size = (iteration % MAX_SIGNATURE_LENGTH) + 1;
        signature = g_string_sized_new(size + 1);

        df_generate_random_signature(signature, size, 0, /* complete= */ FALSE);
        g_assert(g_variant_is_signature(signature->str));

        *buf = g_steal_pointer(&signature->str);

        return 0;
}

int df_rand_GVariant(GVariant **var, guint64 iteration)
{
        g_autoptr(GString) signature = NULL;
        guint16 size;

        size = (iteration % MAX_SIGNATURE_LENGTH) + 1;
        signature = g_string_sized_new(size + 3);

        /* Variant must be a single complete type */
        g_string_append_c(signature, '(');
        df_generate_random_signature(signature, size, 0, /* complete= */ TRUE);
        g_string_append_c(signature, ')');

        g_assert(g_variant_is_signature(signature->str) && g_variant_type_string_is_valid(signature->str));

        *var = df_generate_random_from_signature(signature->str, iteration);
        if (!*var)
                return -1;

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
