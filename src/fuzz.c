/** @file fuzz.c */
/*
 * dfuzzer - tool for fuzz testing processes communicating through D-Bus.
 *
 * Copyright(C) 2013, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>
 *                                   Miroslav Vadkerti <mvadkert@redhat.com>
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fuzz.h"
#include "dfuzzer.h"
#include "rand.h"
#include "util.h"


/** Pointer on D-Bus interface proxy for calling methods. */
static GDBusProxy *df_dproxy;
/** Exceptions counter; if MAX_EXCEPTIONS is reached testing continues
  * with a next method */
static char df_except_counter = 0;


/* Module static functions */
static void df_fuzz_write_log(const struct df_dbus_method *method, GVariant *value);
static int df_exec_cmd_check(const char *cmd);
static int df_fuzz_call_method(const struct df_dbus_method *method, GVariant *value);

guint64 df_get_number_of_iterations(const char *signature) {
        guint64 iterations = 0;
        guint32 multiplier = 1, current_nest_level = 0;

        for (size_t i = 0; i < strlen(signature); i++) {
                switch (signature[i]) {
                case 'y':
                        /* BYTE */
                        iterations = MAX(iterations, 8);
                        break;
                case 'b':
                        /* BOOLEAN */
                        iterations = MAX(iterations, 2);
                        break;
                case 'n':
                case 'q':
                        /* INT/UINT 16 */
                        iterations = MAX(iterations, 16);
                        break;
                case 'i':
                case 'u':
                case 'h':
                        /* INT/UINT 32, UNIX_FD */
                        iterations = MAX(iterations, 24);
                        break;
                case 'x':
                case 't':
                case 'd':
                        /* INT/UINT 64, DOUBLE */
                        iterations = MAX(iterations, 32);
                        break;
                case 's':
                case 'o':
                case 'g':
                        /* STRING, OBJECT_PATH, SIGNATURE */
                        iterations = MAX(iterations, 64);
                        break;
                case 'v':
                        /* VARIANT */
                        iterations = MAX(iterations, 64);
                        break;
                case 'a':
                        /* ARRAY */
                        current_nest_level++;
                        continue;
                case '(':
                case ')':
                case '{':
                case '}':
                        /* Ignore container-specific characters */
                        break;
                default:
                        df_fail("Unexpected character '%c' in signature '%s'\n", signature[i], signature);
                        g_assert_not_reached();
                }

                multiplier = MAX(multiplier, current_nest_level);
                current_nest_level = 0;
        }

        iterations *= multiplier;

        /* Do at least 10 iterations to cover void methods as well */
        return CLAMP(iterations, 10, G_MAXUINT64);
}

/* Generate a GVariant with random data for a basic (non-compound) type
 *
 * Note: variant itself is treated as a basic type, since it's a bit special and
 *       cannot be iterated on
 */
GVariant *df_generate_random_basic(const GVariantType *type, guint64 iteration) {
        _cleanup_free_ char *ssig = NULL;

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
                _cleanup_free_ char *str = NULL;

                if (df_rand_string(&str, iteration) < 0) {
                        df_fail("Failed to generate a random string\n");
                        return NULL;
                }

                return g_variant_new(ssig, str);
        } else if (g_variant_type_equal(type, G_VARIANT_TYPE_OBJECT_PATH)) {
                _cleanup_free_ char *obj_path = NULL;

                if (df_rand_dbus_objpath_string(&obj_path, iteration) < 0) {
                        df_fail("Failed to generate a random object path\n");
                        return NULL;
                }

                return g_variant_new(ssig, obj_path);
        } else if (g_variant_type_equal(type, G_VARIANT_TYPE_SIGNATURE)) {
                _cleanup_free_ char *sig_str = NULL;

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
        _cleanup_(g_variant_type_freep) GVariantType *type = NULL;
        _cleanup_(g_variant_builder_unrefp) GVariantBuilder *builder = NULL;

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

                _cleanup_free_ char *ssig = NULL;

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
                        _cleanup_free_ char *array_signature = NULL;
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
                        for (int i = 0; i < rand() % 10; i++) {
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

/**
 * @function Saves pointer on D-Bus interface proxy for this module to be
 * able to call methods through this proxy during fuzz testing.
 * @param dproxy Pointer on D-Bus interface proxy
 * @return 0 on success, -1 on error
 */

int df_fuzz_init(GDBusProxy *dproxy)
{
        if (dproxy == NULL) {
                df_debug("Passing NULL argument to function.\n");
                return -1;
        }
        df_dproxy = dproxy;

        return 0;
}

/**
 * @function Prints all method signatures and their values on the output.
 * @return 0 on success, -1 on error
 */
static void df_fuzz_write_log(const struct df_dbus_method *method, GVariant *value)
{
        _cleanup_free_ char *variant_value = NULL;

        assert(method);
        assert(value);

        if (!method->signature) {
                df_fail("No method signature\n");
                return;
        }

        df_fail("   -- Signature: %s\n", method->signature);
        FULL_LOG("%s;", method->signature);

        variant_value = g_variant_print(value, TRUE);
        if (variant_value) {
                df_fail("   -- Value: %s\n", variant_value);
                FULL_LOG("%s;", variant_value);
        }
}

/**
 * @function Executes command/script cmd.
 * @param cmd Command/Script to execute
 * @return 0 on successful completition of cmd or when cmd is NULL, value
 * higher than 0 on unsuccessful completition of cmd or -1 on error
 */
static int df_exec_cmd_check(const char *cmd)
{
        if (cmd == NULL)
                return 0;

        const char *fn = "/dev/null";
        _cleanup_(closep) int stdoutcpy = -1, stderrcpy = -1, fd = -1;
        int status = 0;

        fd = open(fn, O_RDWR, S_IRUSR | S_IWUSR);
        if (fd == -1) {
                perror("open");
                return -1;
        }

        // backup std descriptors
        stdoutcpy = dup(1);
        if (stdoutcpy < 0)
                return -1;
        stderrcpy = dup(2);
        if (stderrcpy < 0)
                return -1;

        // make stdout and stderr go to fd
        if (dup2(fd, 1) < 0)
                return -1;
        if (dup2(fd, 2) < 0)
                return -1;
        fd = safe_close(fd);      // fd no longer needed

        // execute cmd
        status = system(cmd);

        // restore std descriptors
        if (dup2(stdoutcpy, 1) < 0)
                return -1;
        stdoutcpy = safe_close(stdoutcpy);
        if (dup2(stderrcpy, 2) < 0)
                return -1;
        stderrcpy = safe_close(stderrcpy);


        if (status == -1)
                return status;
        return WEXITSTATUS(status);
}

static int df_check_if_exited(const int pid) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *line = NULL;
        char proc_pid[14 + DECIMAL_STR_MAX(pid)];
        size_t len = 0;
        int dumping;

        assert(pid > 0);

        sprintf(proc_pid, "/proc/%d/status", pid);

        f = fopen(proc_pid, "r");
        if (!f) {
                if (errno == ENOENT || errno == ENOTDIR || errno == ESRCH)
                        return 0;

                return -1;
        }

        /* Check if the process is not currently dumping a core */
        while (getline(&line, &len, f) > 0) {
                if (sscanf(line, "CoreDumping: %d", &dumping) == 1) {
                        if (dumping > 0)
                                return 0;

                        break;
                }
        }

        /* Assume the process exited if we fail while reading the stat file */
        if (ferror(f))
                return 0;

        return 1;
}

/**
 * @function Function is testing a method in a cycle, each cycle generates
 * data for function arguments, calls method and waits for result.
 * @param statfd FD of process status file
 * @param buf_size Maximum buffer size for generated strings
 * by rand module (in Bytes)
 * @param name D-Bus name
 * @param obj D-Bus object path
 * @param intf D-Bus interface
 * @param pid PID of tested process
 * @param void_method If method has out args 1, 0 otherwise
 * @param execute_cmd Command/Script to execute after each method call.
 * @return 0 on success, -1 on error, 1 on tested process crash, 2 on void
 * function returning non-void value, 3 on warnings and 4 when executed
 * command finished unsuccessfuly
 */
int df_fuzz_test_method(
                const struct df_dbus_method *method, long buf_size, const char *name,
                const char *obj, const char *intf, const int pid, const char *execute_cmd,
                guint64 min_iterations, guint64 max_iterations)
{
        _cleanup_(g_variant_unrefp) GVariant *value = NULL;
        guint64 iterations;
        int ret = 0;            // return value from df_fuzz_call_method()
        int execr = 0;          // return value from execution of execute_cmd
        int buf_size_flg = 0;

        if (buf_size != 0)
                buf_size_flg = 1;
        if (buf_size < MINLEN)
                buf_size = MAX_BUF_LEN;
        // initialization of random module
        df_rand_init(buf_size);
        iterations = df_get_number_of_iterations(method->signature);
        iterations = CLAMP(iterations, min_iterations, max_iterations);

        df_debug("  Method: %s%s %s => %"G_GUINT64_FORMAT" iterations%s\n", ansi_bold(),
                 method->name, method->signature, iterations, ansi_normal());

        df_verbose("  %s...", method->name);

        for (guint64 i = 0; i < iterations; i++) {
                int r;

                value = safe_g_variant_unref(value);

                // creates variant containing all (fuzzed) method arguments
                value = df_generate_random_from_signature(method->signature, i);
                if (!value) {
                        return df_debug_ret(-1, "Failed to generate a variant for signature '%s'\n", method->signature);
                }

                /* Convert the floating variant reference into a full one */
                value = g_variant_ref_sink(value);
                ret = df_fuzz_call_method(method, value);
                execr = df_exec_cmd_check(execute_cmd);

                if (execr < 0)
                        return df_fail_ret(-1, "df_exec_cmd_check() failed: %m");
                else if (execr > 0) {
                        df_fail("%s  %sFAIL%s %s - '%s' returned %s%d%s\n",
                                ansi_cr(), ansi_red(), ansi_normal(), method->name,
                                execute_cmd, ansi_red(), execr, ansi_normal());
                        break;
                }

                r = df_check_if_exited(pid);
                if (r < 0)
                        return df_fail_ret(-1, "Error while reading process' stat file: %m\n");
                else if (r == 0) {
                        ret = -1;
                        df_fail("%s  %sFAIL%s %s - process %d exited\n",
                                ansi_cr(), ansi_red(), ansi_normal(), method->name, pid);
                        break;
                }

                /* Ignore exceptions returned by the test method */
                if (ret == 2)
                        return 0;
                else if (ret > 0)
                        break;

                FULL_LOG("%s;%s;", intf, obj);

                if (logfile)
                        df_fuzz_write_log(method, value);
                FULL_LOG("Success\n");
                if (df_except_counter == MAX_EXCEPTIONS) {
                        df_except_counter = 0;
                        break;
                }
        }

        if (ret != 0 || execr != 0)
                goto fail_label;

        df_verbose("%s  %sPASS%s %s\n",
                   ansi_cr(), ansi_green(), ansi_normal(), method->name);
        return 0;


fail_label:
        if (ret != 1) {
                df_fail("   on input:\n");
                FULL_LOG("%s;%s;", intf, obj);
                df_fuzz_write_log(method, value);
        }

        df_fail("   reproducer: %sdfuzzer -v -n %s -o %s -i %s -t %s",
                ansi_yellow(), name, obj, intf, method->name);
        if (buf_size_flg)
                df_fail(" -b %ld", buf_size);
        if (execute_cmd != NULL)
                df_fail(" -e '%s'", execute_cmd);
        df_fail("%s\n", ansi_normal());

        if (ret == 1){  // method returning void is returning illegal value
                return 2;
        }
        if (execr > 0){ // command/script execution ended with error
                FULL_LOG("Command execution error\n");
                return 4;
        }
        FULL_LOG("Crash\n");

        return 1;
}

/**
 * @function Calls method from df_list (using its name) with its arguments.
 * @param value GVariant tuple containing all method arguments signatures and
 * their values
 * @param void_method If method has out args 1, 0 otherwise
 * @return 0 on success, -1 on error, 1 if void method returned non-void
 * value or 2 when tested method raised exception (so it should be skipped)
 */
static int df_fuzz_call_method(const struct df_dbus_method *method, GVariant *value)
{
        _cleanup_(g_error_freep) GError *error = NULL;
        _cleanup_(g_variant_unrefp) GVariant *response = NULL;
        _cleanup_(g_freep) gchar *dbus_error = NULL;
        const gchar *fmt;

        // Synchronously invokes method with arguments stored in value (GVariant *)
        // on df_dproxy.
        response = g_dbus_proxy_call_sync(
                        df_dproxy,
                        method->name,
                        value,
                        G_DBUS_CALL_FLAGS_NONE,
                        -1,
                        NULL,
                        &error);
        if (!response) {
                // D-Bus exceptions are accepted
                dbus_error = g_dbus_error_get_remote_error(error);
                if (dbus_error) {
                        // if process does not respond
                        if (strcmp(dbus_error, "org.freedesktop.DBus.Error.NoReply") == 0)
                                return -1;
                        else if (strcmp(dbus_error, "org.freedesktop.DBus.Error.Timeout") == 0) {
                                sleep(10);      // wait for tested process; processing
                                // of longer inputs may take a longer time
                                return -1;
                        } else if ((strcmp(dbus_error, "org.freedesktop.DBus.Error.AccessDenied") == 0) ||
                                   (strcmp(dbus_error, "org.freedesktop.DBus.Error.AuthFailed") == 0)) {
                                df_verbose("%s  %sSKIP%s %s - raised exception '%s'\n",
                                           ansi_cr(), ansi_blue(), ansi_normal(),
                                           method->name, dbus_error);
                                return 2;
                        }
                }

                g_dbus_error_strip_remote_error(error);
                if (strstr(error->message, "Timeout")) {
                        df_verbose("%s  %sSKIP%s %s - timeout reached\n",
                                   ansi_cr(), ansi_blue(), ansi_normal(), method->name);
                        return 2;
                }

                df_debug("%s  EXCE %s - D-Bus exception thrown: %.60s\n",
                         ansi_cr(), method->name, error->message);
                df_except_counter++;
                return 0;
        } else {
                if (!method->returns_value) {
                        // fmt points to GVariant, do not free it
                        fmt = g_variant_get_type_string(response);
                        // void function can only return empty tuple
                        if (strcmp(fmt, "()") != 0) {
                                df_fail("%s  %sFAIL%s %s - void method returns '%s' instead of '()'\n",
                                        ansi_cr(), ansi_red(), ansi_normal(), method->name, fmt);
                                return 1;
                        }
                }
        }

        return 0;
}
