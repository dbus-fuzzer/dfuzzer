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
#include <ctype.h>
#include <errno.h>
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fuzz.h"
#include "bus.h"
#include "log.h"
#include "rand.h"
#include "util.h"

static guint64 fuzz_buffer_length = MAX_BUFFER_LENGTH;
static gboolean show_command_output = FALSE;
/** Pointer on D-Bus interface proxy for calling methods. */
static GDBusProxy *df_dproxy;
/** Exceptions counter; if MAX_EXCEPTIONS is reached testing continues
  * with a next method */
static char df_except_counter = 0;

void df_fuzz_set_buffer_length(const guint64 length)
{
        g_assert(length <= MAX_BUFFER_LENGTH);

        fuzz_buffer_length = length;
}

guint64 df_fuzz_get_buffer_length(void)
{
        return fuzz_buffer_length;
}

void df_fuzz_set_show_command_output(gboolean value)
{
        show_command_output = value;
}

guint64 df_get_number_of_iterations(const char *signature)
{
        guint64 iterations = 0;
        guint32 multiplier = 1, current_nest_level = 0;

        g_assert(signature);

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

/**
 * @function Saves pointer on D-Bus interface proxy for this module to be
 * able to call methods through this proxy during fuzz testing.
 * @param dproxy Pointer on D-Bus interface proxy
 * @return 0 on success, -1 on error
 */

int df_fuzz_init(GDBusProxy *dproxy)
{
        g_assert(dproxy);

        df_dproxy = dproxy;

        return 0;
}

/**
 * @function Prints all method signatures and their values on the output.
 * @return 0 on success, -1 on error
 */
static void df_fuzz_write_log(const struct df_dbus_method *method, GVariant *value)
{
        g_autoptr(char) variant_value = NULL;

        g_assert(method);
        g_assert(value);

        df_log_file("%s;", method->name);

        if (!method->signature) {
                df_fail("No method signature\n");
                return;
        }

        df_fail("   -- Signature: %s\n", method->signature);
        df_log_file("%s;", method->signature);

        variant_value = g_variant_print(value, TRUE);
        if (variant_value) {
                df_fail("   -- Value: %s\n", variant_value);
                df_log_file("%s;", variant_value);
        }
}

static int df_check_if_exited(const int pid) {
        g_autoptr(FILE) f = NULL;
        g_autoptr(char) line = NULL;
        char proc_pid[14 + DECIMAL_STR_MAX(pid)];
        size_t len = 0;
        int dumping;

        g_assert(pid > 0);

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
 * @function Calls method from df_list (using its name) with its arguments.
 * @param value GVariant tuple containing all method arguments signatures and
 * their values
 * @param void_method If method has out args 1, 0 otherwise
 * @return 0 on success, -1 on error, 1 if void method returned non-void
 * value or 2 when tested method raised exception (so it should be skipped)
 */
static int df_fuzz_call_method(const struct df_dbus_method *method, GVariant *value)
{
        g_autoptr(GError) error = NULL;
        g_autoptr(GVariant) response = NULL;
        g_autoptr(gchar) dbus_error = NULL;
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
                if (g_dbus_connection_is_closed(g_dbus_proxy_get_connection(df_dproxy)))
                        return df_fail_ret(2, "%s  %sFAIL%s [M] %s - the connection is closed (this is most likely a bug in dfuzzer, "
                                          "please report it at https://github.com/dbus-fuzzer/dfuzzer together with dbus-daemon/dbus-broker logs)\n",
                                           ansi_cr(), ansi_red(), ansi_normal(), method->name);

                // D-Bus exceptions are accepted
                dbus_error = g_dbus_error_get_remote_error(error);
                if (dbus_error) {
                        if (g_str_equal(dbus_error, "org.freedesktop.DBus.Error.NoReply"))
                                /* If the method is annotated as "NoReply", don't consider
                                 * not replying as an error */
                                return method->expect_reply ? -1 : 0;
                        else if (g_str_equal(dbus_error, "org.freedesktop.DBus.Error.Timeout")) {
                                sleep(10);
                                return -1;
                        } else if (g_str_equal(dbus_error, "org.freedesktop.DBus.Error.AccessDenied") ||
                                   g_str_equal(dbus_error, "org.freedesktop.DBus.Error.AuthFailed"))
                                return df_verbose_ret(2, "%s  %sSKIP%s [M] %s - raised exception '%s'\n",
                                                      ansi_cr(), ansi_blue(), ansi_normal(),
                                                      method->name, dbus_error);
                }

                g_dbus_error_strip_remote_error(error);
                if (strstr(error->message, "Timeout"))
                        return df_verbose_ret(2, "%s  %sSKIP%s [M] %s - timeout reached\n",
                                              ansi_cr(), ansi_blue(), ansi_normal(), method->name);

                df_debug("%s  EXCE %s - D-Bus exception thrown: %s\n",
                         ansi_cr(), method->name, error->message);
                df_except_counter++;
                return 0;
        } else {
                /* Check if a method without return value returns void */
                if (!method->returns_value) {
                        fmt = g_variant_get_type_string(response);
                        if (!g_str_equal(fmt, "()"))
                                return df_fail_ret(1, "%s  %sFAIL%s [M] %s - void method returns '%s' instead of '()'\n",
                                                   ansi_cr(), ansi_red(), ansi_normal(), method->name, fmt);
                }
        }

        return 0;
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
                const struct df_dbus_method *method, const char *name,
                const char *obj, const char *intf, const int pid, const char *execute_cmd,
                guint64 iterations)
{
        g_autoptr(GVariant) value = NULL;
        int ret = 0;            // return value from df_fuzz_call_method()
        int execr = 0;          // return value from execution of execute_cmd

        df_debug("  Method: %s%s %s => %"G_GUINT64_FORMAT" iterations%s\n", ansi_bold(),
                 method->name, method->signature, iterations, ansi_normal());

        df_verbose("  [M] %s...", method->name);

        df_except_counter = 0;

        for (guint64 i = 0; i < iterations; i++) {
                int r;

                value = safe_g_variant_unref(value);

                /* Create a random GVariant based on method's signature */
                value = df_generate_random_from_signature(method->signature, i);
                if (!value)
                        return df_debug_ret(-1, "Failed to generate a variant for signature '%s'\n", method->signature);

                /* Convert the floating variant reference into a full one */
                value = g_variant_ref_sink(value);
                ret = df_fuzz_call_method(method, value);
                execr = execute_cmd ? df_execute_external_command(execute_cmd, show_command_output) : 0;

                if (ret < 0) {
                        df_fail("%s  %sFAIL%s [M] %s - unexpected response\n",
                                ansi_cr(), ansi_red(), ansi_normal(), method->name);
                        break;
                }

                if (execr < 0)
                        return df_fail_ret(-1, "df_execute_external_command() failed: %s", strerror(errno));
                else if (execr > 0) {
                        df_fail("%s  %sFAIL%s [M] %s - '%s' returned %s%d%s\n",
                                ansi_cr(), ansi_red(), ansi_normal(), method->name,
                                execute_cmd, ansi_red(), execr, ansi_normal());
                        break;
                }

                r = df_check_if_exited(pid);
                if (r < 0)
                        return df_fail_ret(-1, "Error while reading process' stat file: %s\n", strerror(errno));
                else if (r == 0) {
                        ret = -1;
                        df_fail("%s  %sFAIL%s [M] %s - process %d exited\n",
                                ansi_cr(), ansi_red(), ansi_normal(), method->name, pid);
                        break;
                }

                /* Ignore exceptions returned by the test method */
                if (ret == 2)
                        return 0;
                else if (ret > 0)
                        break;

                df_log_file("%s;%s;", intf, obj);

                if (df_log_file_is_open())
                        df_fuzz_write_log(method, value);
                df_log_file("Success\n");

                if (df_except_counter == MAX_EXCEPTIONS)
                        break;
        }

        if (ret != 0 || execr != 0)
                goto fail_label;

        df_verbose("%s  %sPASS%s [M] %s\n",
                   ansi_cr(), ansi_green(), ansi_normal(), method->name);
        return 0;


fail_label:
        if (ret != 1) {
                df_fail("   on input:\n");
                df_log_file("%s;%s;", intf, obj);
                df_fuzz_write_log(method, value);
        }

        df_fail("   reproducer: %sdfuzzer -v -n %s -o %s -i %s -t %s",
                ansi_yellow(), name, obj, intf, method->name);
        df_fail(" -b %"G_GUINT64_FORMAT, fuzz_buffer_length);
        if (execute_cmd != NULL)
                df_fail(" -e '%s'", execute_cmd);
        df_fail("%s\n", ansi_normal());

        /* Method with a void return type returned a non-void value */
        if (ret == 1)
                return 2;
        /* Command specified via -e/--command returned a non-zero exit code */
        if (execr > 0) {
                df_log_file("Command execution error\n");
                return 4;
        }
        df_log_file("Crash\n");

        return 1;
}

static int df_fuzz_get_property(GDBusProxy *pproxy, const char *interface,
                                const struct df_dbus_property *property)
{
        g_autoptr(GVariant) response = NULL;

        response = df_bus_call(pproxy, "Get",
                               g_variant_new("(ss)", interface, property->name),
                               G_DBUS_CALL_FLAGS_NONE);
        if (!response)
                return -1;

        if (df_get_log_level() >= DF_LOG_LEVEL_DEBUG) {
                g_autoptr(gchar) value_str = NULL;
                value_str = g_variant_print(response, TRUE);
                df_debug("Got value for property %s.%s: %s\n", interface, property->name, value_str);
        }

        return 0;
}

static int df_fuzz_set_property(GDBusProxy *pproxy, const char *interface,
                                const struct df_dbus_property *property, GVariant *value)
{
        g_autoptr(GVariant) val = NULL, response = NULL;
        g_autoptr(GError) error = NULL;
        g_autoptr(gchar) dbus_error = NULL;

        /* Unwrap the variant, since our generator automagically wraps it in a tuple
         * to make generating method signatures easier. Property signatures should
         * consist of a single complete type, hence getting the first child from
         * the tuple should achieve just that. */
        val = g_variant_get_child_value(value, 0);
        response = g_dbus_proxy_call_sync(
                        pproxy,
                        "Set",
                        g_variant_new("(ssv)", interface, property->name, val),
                        G_DBUS_CALL_FLAGS_NONE,
                        -1,
                        NULL,
                        &error);
        if (!response) {
                if (g_dbus_connection_is_closed(g_dbus_proxy_get_connection(pproxy)))
                        return df_fail_ret(2, "%s  %sFAIL%s [P] %s - the connection is closed (this is most likely a bug in dfuzzer, "
                                          "please report it at https://github.com/dbus-fuzzer/dfuzzer together with dbus-daemon/dbus-broker logs)\n",
                                           ansi_cr(), ansi_red(), ansi_normal(), property->name);

                dbus_error = g_dbus_error_get_remote_error(error);
                if (dbus_error) {
                        if (g_str_equal(dbus_error, "org.freedesktop.DBus.Error.NoReply"))
                                /* If the property is annotated as "NoReply", don't consider
                                 * not replying as an error */
                                return property->expect_reply ? -1 : 0;
                        else if (g_str_equal(dbus_error, "org.freedesktop.DBus.Error.Timeout")) {
                                sleep(10);
                                return -1;
                        } else if (g_str_equal(dbus_error, "org.freedesktop.DBus.Error.AccessDenied") ||
                                   g_str_equal(dbus_error, "org.freedesktop.DBus.Error.AuthFailed"))
                                return df_verbose_ret(2, "%s  %sSKIP%s [P] %s - raised exception '%s'\n",
                                                      ansi_cr(), ansi_blue(), ansi_normal(),
                                                      property->name, dbus_error);
                }

                g_dbus_error_strip_remote_error(error);
                if (strstr(error->message, "Timeout"))
                        return df_verbose_ret(2, "%s  %sSKIP%s [P] %s - timeout reached\n",
                                              ansi_cr(), ansi_blue(), ansi_normal(), property->name);

                df_debug("%s  EXCE [P] %s - D-Bus exception thrown: %s\n",
                         ansi_cr(), property->name, error->message);
                df_except_counter++;
                return 0;
        }

        if (df_get_log_level() >= DF_LOG_LEVEL_DEBUG) {
                g_autoptr(gchar) value_str = NULL;
                value_str = g_variant_print(value, TRUE);
                df_debug("Set value for property %s.%s: %s\n", interface, property->name, value_str);
        }

        return 0;
}

int df_fuzz_test_property(GDBusConnection *dcon, const struct df_dbus_property *property,
                          const char *bus, const char *object, const char *interface,
                          const int pid, guint64 iterations)
{
        g_autoptr(GDBusProxy) pproxy = NULL;
        int r;

        /* Create a "property proxy"
         * See: https://dbus.freedesktop.org/doc/dbus-specification.html#standard-interfaces-properties
         */
        pproxy = df_bus_new(dcon, bus, object, "org.freedesktop.DBus.Properties",
                            G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS);
        if (!pproxy)
                return df_fail_ret(-1, "Failed to create a property proxy for object '%s'\n", object);

        /* Try to read the property if it's readable.
         *
         * For performance reasons read readable property only twice, since that
         * should be enough to trigger most of the issues.
         */
        iterations = 2;
        if (property->is_readable) {
                df_debug("  Property: %s%s %s (read) => %"G_GUINT64_FORMAT" iterations%s\n", ansi_bold(),
                         property->name, property->signature, iterations, ansi_normal());

                df_verbose("  [P] %s (read)...", property->name);

                for (guint8 i = 0; i < iterations; i++) {
                        r = df_fuzz_get_property(pproxy, interface, property);
                        if (r < 0)
                                return df_fail_ret(1, "%s  %sFAIL%s [P] %s - unexpected response while reading a property\n",
                                                   ansi_cr(), ansi_red(), ansi_normal(), property->name);
                }

                /* Check if the remote side is still alive */
                r = df_check_if_exited(pid);
                if (r < 0)
                        return df_fail_ret(-1, "Error while reading process' stat file: %s\n", strerror(errno));
                else if (r == 0) {
                        df_fail("%s  %sFAIL%s [P] %s (read) - process %d exited\n",
                                ansi_cr(), ansi_red(), ansi_normal(), property->name, pid);
                        return 1;
                }

                df_verbose("%s  %sPASS%s [P] %s (read)\n",
                           ansi_cr(), ansi_green(), ansi_normal(), property->name);
        }

        /* Try to write a random value to the property if it's writable
         *
         * Cap the iterations for writable properties to 16 for now, since without
         * dictionaries doing the "full" loop is mostly a waste of time.
         */
        iterations = CLAMP(iterations, 1, 16);
        if (property->is_writable) {
                df_debug("  Property: %s%s %s (write) => %"G_GUINT64_FORMAT" iterations%s\n", ansi_bold(),
                         property->name, property->signature, iterations, ansi_normal());

                df_verbose("  [P] %s (write)...", property->name);

                for (guint64 i = 0; i < iterations; i++) {
                        g_autoptr(GVariant) value = NULL;

                        /* Create a random GVariant based on method's signature */
                        value = df_generate_random_from_signature(property->signature, i);
                        if (!value)
                                return df_debug_ret(-1, "Failed to generate a variant for signature '%s'\n", property->signature);

                        /* Convert the floating variant reference into a full one */
                        value = g_variant_ref_sink(value);
                        r = df_fuzz_set_property(pproxy, interface, property, value);
                        if (r < 0)
                                return df_fail_ret(1, "%s  %sFAIL%s [P] %s (write) - unexpected response while writing to a property\n",
                                                   ansi_cr(), ansi_red(), ansi_normal(), property->name);
                }

                /* Check if the remote side is still alive */
                r = df_check_if_exited(pid);
                if (r < 0)
                        return df_fail_ret(-1, "Error while reading process' stat file: %s\n", strerror(errno));
                else if (r == 0)
                        return df_fail_ret(1, "%s  %sFAIL%s [P] %s (write) - process %d exited\n",
                                           ansi_cr(), ansi_red(), ansi_normal(), property->name, pid);

                df_verbose("%s  %sPASS%s [P] %s (write)\n",
                           ansi_cr(), ansi_green(), ansi_normal(), property->name);
        }

        return 0;
}
