/** @file dfuzzer.c */
/*
 * dfuzzer - tool for fuzz testing processes communicating through D-Bus.
 *
 * Copyright(C) 2013,2014,2015, Red Hat, Inc.
 *     Matus Marhefka <mmarhefk@redhat.com>
 *     Miroslav Vadkerti <mvadkert@redhat.com>
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
#include <fcntl.h>
#include <getopt.h>
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bus.h"
#include "fuzz.h"
#include "introspection.h"
#include "log.h"
#include "rand.h"
#include "suppression.h"
#include "util.h"

#define DF_BUS_ROOT_NODE "/"

enum {
        DF_BUS_OK = 0,
        DF_BUS_SKIP,
        DF_BUS_NO_PID,
        DF_BUS_WARNING,
        DF_BUS_FAIL,
        DF_BUS_ERROR
};

/** Structure containing D-Bus name, object path and interface of process. */
struct fuzzing_target {
        /* names on D-Bus have the most MAX_OBJECT_PATH_LENGTH characters */
        /** Bus name */
        char *name;
        /** Object path */
        char *obj_path;
        /** Interface */
        char *interface;
};

gboolean df_skip_methods;
gboolean df_skip_properties;
static char *df_test_method;
static char *df_test_property;
/** Structure containing D-Bus name, object path and interface of process */
static struct fuzzing_target target_proc = { "", "", "" };
/** Option for listing names on the bus */
static int df_list_names;
/** Tested process PID */
static int df_pid = -1;
GList *suppressions;
/** If -s option is passed 1, otherwise 0 */
static int df_supflg;
/** Command/Script to execute by dfuzzer after each method call.
  * If command/script returns >0, dfuzzer prints fail message,
  * if 0 it continues */
static char *df_execute_cmd;
/** Path to directory containing output logs */
static char *df_log_dir_name;
static guint64 df_max_iterations = G_MAXUINT32;
static guint64 df_min_iterations = 10;

/**
 * @function Checks if name is valid D-Bus name, obj is valid
 * D-Bus object path and intf is valid D-Bus interface.
 * @param name D-Bus name
 * @param obj D-Bus object path
 * @param intf D-Bus interface
 * @return 1 if name, obj and intf are valid, 0 otherwise
 */
static int df_is_valid_dbus(const char *name, const char *obj, const char *intf)
{
        if (!g_dbus_is_name(name)) {
                df_fail("Error: Unknown bus name '%s'.\n", name);
                return 0;
        }
        if (!g_variant_is_object_path(obj)) {
                df_fail("Error: Unknown object path '%s'.\n", obj);
                return 0;
        }
        if (!g_dbus_is_interface_name(intf)) {
                df_fail("Error: Unknown interface '%s'.\n", intf);
                return 0;
        }
        return 1;
}

/**
 * @function Calls method ListNames to get all available connection names
 * on the bus and prints them on the program output.
 * @param dcon D-Bus connection structure
 * @return 0 on success, -1 on error
 */
static int df_list_bus_names(GDBusConnection *dcon)
{
        g_autoptr(GDBusProxy) proxy = NULL;
        g_autoptr(GVariantIter) iter = NULL;
        g_autoptr(GVariant) response = NULL;
        char *str;

        proxy = df_bus_new(dcon,
                           "org.freedesktop.DBus",
                           "/org/freedesktop/DBus",
                           "org.freedesktop.DBus",
                           G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS);
        if (!proxy)
                return -1;

        response = df_bus_call(proxy, "ListNames", NULL, G_DBUS_CALL_FLAGS_NONE);
        if (!response)
                return -1;

        g_variant_get(response, "(as)", &iter);
        while (g_variant_iter_loop(iter, "s", &str)) {
                if (str[0] != ':')
                        printf("%s\n", str);
        }

        response = safe_g_variant_unref(response);
        iter = safe_g_variant_iter_free(iter);

        response = df_bus_call(proxy, "ListActivatableNames", NULL, G_DBUS_CALL_FLAGS_NONE);
        if (!response)
                return -1;

        g_variant_get(response, "(as)", &iter);
        while (g_variant_iter_loop(iter, "s", &str)) {
                if (str[0] != ':')
                        printf("%s (activatable)\n", str);
        }

        return 0;
}

/**
 * @function Calls method GetConnectionUnixProcessID on the interface
 * org.freedesktop.DBus to get process pid.
 * @param dcon D-Bus connection structure
 * @return Process PID on success, -1 on error
 */
static int df_get_pid(GDBusConnection *dcon, gboolean activate)
{
        g_autoptr(GDBusProxy) pproxy = NULL;
        g_autoptr(GVariant) variant_pid = NULL;
        int pid = -1;

        pproxy = df_bus_new(dcon,
                            "org.freedesktop.DBus",
                            "/org/freedesktop/DBus",
                            "org.freedesktop.DBus",
                            G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS);
        if (!pproxy)
                return -1;

        /* Attempt to activate the remote side. Since we can't use any well-known
         * remote method for auto-activation, fall back to calling
         * the org.freedesktop.DBus.StartServiceByName method.
         *
         * See:
         *  - https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-start-service-by-name
         *  - https://dbus.freedesktop.org/doc/system-activation.txt
         */
        if (activate) {
                g_autoptr(GError) act_error = NULL;
                g_autoptr(GVariant) act_res = NULL;

                act_res = df_bus_call_full(pproxy,
                                           "StartServiceByName",
                                           g_variant_new("(su)", target_proc.name, 0),
                                           G_DBUS_CALL_FLAGS_NONE,
                                           &act_error);
                if (!act_res) {
                        g_dbus_error_strip_remote_error(act_error);
                        df_verbose("Error while activating '%s': %s.\n", target_proc.name, act_error->message);
                        df_error("Failed to activate the target", act_error);
                        /* Don't make this a hard fail */
                }
        }

        variant_pid = df_bus_call(pproxy,
                                  "GetConnectionUnixProcessID",
                                  g_variant_new("(s)", target_proc.name),
                                  G_DBUS_CALL_FLAGS_NONE);
        if (!variant_pid)
                return -1;

        g_variant_get(variant_pid, "(u)", &pid);

        return pid;
}

/**
 * @function Controls fuzz testing of all methods of specified interface (intf)
 * and reports results.
 * @param dcon D-Bus connection structure
 * @param name D-Bus name
 * @param obj D-Bus object path
 * @param intf D-Bus interface
 * @return 0 on success, 1 on error, 2 when testing detected any failures,
 * 3 on warnings
 */
static int df_fuzz(GDBusConnection *dcon, const char *name, const char *object, const char *interface)
{
        g_autoptr(GDBusProxy) dproxy = NULL;
        g_autoptr(GDBusNodeInfo) node_info = NULL;
        GDBusInterfaceInfo *interface_info = NULL;
        guint64 iterations;
        int method_found = 0, property_found = 0, ret;
        int rv = DF_BUS_OK;

        // initialization of random module
        df_rand_init(time(NULL));

        // Sanity check fuzzing target
        if (isempty(name) || isempty(object) || isempty(interface)) {
                df_fail("Error in target specification.\n");
                return DF_BUS_ERROR;
        }

        if (!df_is_valid_dbus(name, object, interface))
                return DF_BUS_ERROR;

        dproxy = df_bus_new(dcon, name, object, interface,
                            G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS);
        if (!dproxy)
                return DF_BUS_ERROR;

        node_info = df_get_interface_info(dproxy, interface, &interface_info);
        if (!node_info)
                return DF_BUS_ERROR;

        if (df_fuzz_init(dproxy) == -1) {
                df_debug("Error in df_fuzz_add_proxy()\n");
                return DF_BUS_ERROR;
        }

        /* Test properties */
        STRV_FOREACH_COND(p, interface_info->properties, !df_skip_properties) {
                g_auto(df_dbus_property_t) dbus_property = {0,};

                /* Test only a specific property if set */
                if (df_test_property && !g_str_equal(df_test_property, p->name))
                        continue;

                property_found = 1;

                dbus_property.name = strdup(p->name);
                dbus_property.signature = strjoin("(", p->signature, ")");
                dbus_property.is_readable = p->flags & G_DBUS_PROPERTY_INFO_FLAGS_READABLE;
                dbus_property.is_writable = p->flags & G_DBUS_PROPERTY_INFO_FLAGS_WRITABLE;
                dbus_property.expect_reply = df_object_returns_reply(p->annotations);

                iterations = df_get_number_of_iterations(dbus_property.signature);
                iterations = CLAMP(iterations, df_min_iterations, df_max_iterations);
                ret = df_fuzz_test_property(
                                dcon,
                                &dbus_property,
                                name,
                                object,
                                interface,
                                df_pid,
                                iterations);
                if (ret < 0) {
                        // error during testing method
                        df_debug("Error in df_fuzz_test_property()\n");
                        return DF_BUS_ERROR;
                } else if (ret == 1 && !df_test_property) {
                        // launch process again after crash
                        rv = DF_BUS_FAIL;
                        dproxy = safe_g_dbus_proxy_unref(dproxy);

                        if (!df_is_valid_dbus(name, object, interface))
                                return DF_BUS_ERROR;

                        dproxy = df_bus_new(dcon, name, object, interface,
                                            G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS);
                        if (!dproxy)
                                return DF_BUS_ERROR;

                        sleep(5);

                        // gets pid of tested process
                        df_pid = df_get_pid(dcon, FALSE);
                        if (df_pid < 0) {
                                df_debug("Error in df_get_pid() on getting pid of process\n");
                                return DF_BUS_ERROR;
                        }
                        fprintf(stderr, "%s%s[RE-CONNECTED TO PID: %d]%s\n",
                                        ansi_cr(), ansi_cyan(), df_pid, ansi_blue());

                        if (df_fuzz_init(dproxy) < 0) {
                                df_debug("Error in df_fuzz_add_proxy()\n");
                                return DF_BUS_ERROR;
                        }
                } else if (ret == 1 && df_test_property)
                        rv = DF_BUS_FAIL;
        }

        /* Test methods */
        STRV_FOREACH_COND(m, interface_info->methods, !df_skip_methods) {
                g_auto(df_dbus_method_t) dbus_method = {0,};
                char *description;

                /* Test only a specific method if set */
                if (df_test_method && !g_str_equal(df_test_method, m->name))
                        continue;

                method_found = 1;

                if (df_suppression_check(suppressions, object, interface, m->name, &description) != 0) {
                        df_verbose("%s  %sSKIP%s [M] %s - %s\n", ansi_cr(), ansi_blue(), ansi_normal(),
                                   m->name, description ?: "suppressed method");
                        continue;
                }

                dbus_method.name = strdup(m->name);
                dbus_method.signature = df_method_get_full_signature(m);
                dbus_method.returns_value = !!*(m->out_args);
                dbus_method.expect_reply = df_object_returns_reply(m->annotations);

                iterations = df_get_number_of_iterations(dbus_method.signature);
                iterations = CLAMP(iterations, df_min_iterations, df_max_iterations);

                // tests for method
                ret = df_fuzz_test_method(
                                &dbus_method,
                                name,
                                object,
                                interface,
                                df_pid,
                                df_execute_cmd,
                                iterations);
                if (ret < 0) {
                        // error during testing method
                        df_debug("Error in df_fuzz_test_method()\n");
                        return DF_BUS_ERROR;
                } else if (ret == 1 && !df_test_method) {
                        // launch process again after crash
                        rv = DF_BUS_FAIL;
                        dproxy = safe_g_dbus_proxy_unref(dproxy);

                        if (!df_is_valid_dbus(name, object, interface))
                                return DF_BUS_ERROR;

                        dproxy = df_bus_new(dcon, name, object, interface,
                                            G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS);
                        if (!dproxy)
                                return DF_BUS_ERROR;

                        sleep(5);

                        // gets pid of tested process
                        df_pid = df_get_pid(dcon, FALSE);
                        if (df_pid < 0) {
                                df_debug("Error in df_get_pid() on getting pid of process\n");
                                return DF_BUS_ERROR;
                        }
                        fprintf(stderr, "%s%s[RE-CONNECTED TO PID: %d]%s\n",
                                        ansi_cr(), ansi_cyan(), df_pid, ansi_blue());

                        if (df_fuzz_init(dproxy) < 0) {
                                df_debug("Error in df_fuzz_add_proxy()\n");
                                return DF_BUS_ERROR;
                        }
                } else if (ret == 1 && df_test_method) {
                        // for one method, testing ends with failure
                        rv = DF_BUS_FAIL;
                } else if (ret == 2) {
                        // method returning void is returning illegal value
                        rv = DF_BUS_FAIL;
                } else if (ret == 3) {
                        // warnings
                        if (rv != 2)
                                rv = DF_BUS_WARNING;
                } else if (ret == 4) {
                        // executed command finished unsuccessfuly
                        rv = DF_BUS_FAIL;
                }
        }

        if (!df_skip_methods && df_test_method && method_found == 0) {
                df_fail("Error: Method '%s' is not in the interface '%s'.\n", df_test_method, interface);
                return DF_BUS_ERROR;
        }

        if (!df_skip_properties && df_test_property && property_found == 0) {
                df_fail("Error: Property '%s' is not in the interface '%s'.\n", df_test_property, interface);
                return DF_BUS_ERROR;
        }

        return rv;
}

/**
 * @function Traverses through all interfaces and objects of bus
 * name target_proc.name and for each interface it calls df_fuzz()
 * to fuzz test all its methods.
 * @param dcon D-Bus connection structure
 * @param root_node Starting object path (all nodes from this object path
 * will be traversed)
 * @return 0 on success, 1 on error, 2 when testing detected any failures
 * or warnings, 3 on warnings
 */
static int df_traverse_node(GDBusConnection *dcon, const char *root_node)
{
        char *intro_iface = "org.freedesktop.DBus.Introspectable";
        char *intro_method = "Introspect";
        g_autoptr(GVariant) response = NULL;
        g_autoptr(GDBusProxy) dproxy = NULL;
        g_autoptr(gchar) introspection_xml = NULL;
        g_autoptr(GError) error = NULL;
        /** Information about nodes in a remote object hierarchy. */
        g_autoptr(GDBusNodeInfo) node_data = NULL;
        /** Return values */
        int rd = 0;          // return value from df_fuzz()
        int rt = 0;          // return value from recursive transition
        int ret = DF_BUS_OK; // return value of this function


        if (!df_is_valid_dbus(target_proc.name, root_node, intro_iface))
                return DF_BUS_ERROR;

        dproxy = df_bus_new(dcon, target_proc.name, root_node, intro_iface,
                            G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS);
        if (!dproxy)
                return DF_BUS_ERROR;

        response = df_bus_call(dproxy, intro_method, NULL, G_DBUS_CALL_FLAGS_NONE);
        if (!response)
                return DF_BUS_ERROR;

        g_variant_get(response, "(s)", &introspection_xml);
        if (!introspection_xml) {
                df_fail("Error: Unable to get introspection data from GVariant.\n");
                return DF_BUS_ERROR;
        }

        // Parses introspection_xml and returns a GDBusNodeInfo representing
        // the data.
        node_data = g_dbus_node_info_new_for_xml(introspection_xml, &error);
        if (!node_data) {
                df_fail("Error: Unable to get introspection data.\n");
                df_error("Error in g_dbus_node_info_new_for_xml()", error);
                return DF_BUS_ERROR;
        }

        // go through all interfaces
        STRV_FOREACH(interface, node_data->interfaces) {
                fprintf(stderr, " Interface: %s%s%s\n",
                        ansi_bold(), interface->name, ansi_normal());
                // start fuzzing on the target_proc.name
                rd = df_fuzz(dcon, target_proc.name, root_node, interface->name);
                if (rd == DF_BUS_ERROR)
                        return DF_BUS_ERROR;
                else if (ret != DF_BUS_FAIL) {
                        if (rd != DF_BUS_OK)
                                ret = rd;
                }
        }

        // if object path was set as dfuzzer option, do not traverse
        // through all objects
        if (strlen(target_proc.obj_path) != 0)
                return ret;

        // go through all nodes
        STRV_FOREACH(node, node_data->nodes) {
                g_autoptr(char) object = NULL;
                // create next object path
                object = strjoin(root_node, strlen(root_node) == 1 ? "" : "/", node->path);
                if (object == NULL) {
                        df_fail("Error: Could not allocate memory for root_node string.\n");
                        return DF_BUS_ERROR;
                }
                fprintf(stderr, "Object: %s%s%s\n", ansi_bold(), object, ansi_normal());
                rt = df_traverse_node(dcon, object);
                if (rt == DF_BUS_ERROR)
                        return DF_BUS_ERROR;
                else if (ret != DF_BUS_FAIL) {
                        if (rt != DF_BUS_OK)
                                ret = rt;
                }
        }

        return ret;
}

static void df_print_process_info(int pid)
{
        char proc_path[15 + DECIMAL_STR_MAX(int)]; // "/proc/(int)/[exe|cmdline]"
        char name[PATH_MAX + 1];
        g_auto(fd_t) fd = -1;
        int ret;

        sprintf(proc_path, "/proc/%d/exe", pid);
        ret = readlink(proc_path, name, PATH_MAX);
        if (ret > 0) {
                name[ret] = '\0';

                if (ret == PATH_MAX)
                        df_verbose("The process name was truncated\n");

                if (!strstr(name, "python") && !strstr(name, "perl")) {
                        fprintf(stderr, "%s%s[PROCESS: %s]%s\n",
                                ansi_cr(), ansi_cyan(), name, ansi_normal());
                        return;
                }
        }

        // if readlink failed or executable was interpret (and our target is
        // interpreted script), try to read cmdline
        sprintf(proc_path, "/proc/%d/cmdline", pid);
        fd = open(proc_path, O_RDONLY);
        if (fd <= 0) {
                perror("open");
                return;
        }

        for (int i = 0;; i++) {
                if (i >= PATH_MAX) {
                        df_verbose("The process name was truncated\n");
                        name[PATH_MAX] = '\0';
                        break;
                }

                ret = read(fd, (name + i), 1);
                if (ret < 0) {
                        perror("read");
                        return;
                }

                if (name[i] == '\0')
                        break;
        }

        fprintf(stderr, "%s%s[PROCESS: %s]%s\n",
                ansi_cr(), ansi_cyan(), name, ansi_normal());
}

static void df_print_help(const char *name)
{
        printf(
         "Usage: %1$s -n BUS_NAME [OTHER_OPTIONS]\n\n"
         "Tool for fuzz testing processes communicating through D-Bus.\n"
         "The fuzzer traverses through all the methods on the given bus name.\n"
         "By default only failures and warnings are printed."
         " Use -v for verbose mode.\n\n"
         "REQUIRED OPTIONS:\n"
         "  -n --bus=BUS_NAME           D-Bus service name.\n\n"
         "OTHER OPTIONS:\n"
         "  -V --version                Show dfuzzer version and exit.\n"
         "  -h --help                   Show this help text.\n"
         "  -l --list                   List all available services on both buses.\n"
         "  -v --verbose                Be more verbose.\n"
         "  -d --debug                  Enable debug logging; implies -v.\n"
         "  -L --log-dir=DIRNAME        Write full, parseable log into DIRNAME/BUS_NAME.\n"
         "                              The directory must already exist.\n"
         "  -s --no-suppressions        Don't load suppression file(s).\n"
         "  -o --object=OBJECT_PATH     Optional object path to test. All children objects are traversed.\n"
         "  -i --interface=INTERFACE    Interface to test. Requires -o to be set as well.\n"
         "  -t --method=METHOD_NAME     Test only given method, all other methods are skipped.\n"
         "                              Requires -o and -i to be set as well. Can't be used together\n"
         "                              with --property=. Implies --skip-properties.\n"
         "  -p --property=PROPERTY_NAME Test only given property, all other properties are skipped.\n"
         "                              Requires -o and -i to be set as well, can't be used togetgher\n"
         "                              with --method=. Implies --skip-methods.\n"
         "     --skip-methods           Skip all methods.\n"
         "     --skip-properties        Skip all properties.\n"
         "  -b --buffer-limit=SIZE      Maximum buffer size for generated strings in bytes.\n"
         "                              Default: 50K, minimum: 256B.\n"
         "  -x --max-iterations=ITER    Maximum number of iterations done for each method.\n"
         "                              By default this value is dynamically calculated from each\n"
         "                              method's signature; minimum is 1 iteration.\n"
         "  -y --min-iterations=ITER    Minimum number of iterations done for each method.\n"
         "                              Default: 10 iterations; minimum: 1 iteration.\n"
         "  -I --iterations=ITER        Set both the minimum and maximum number of iterations to ITER\n"
         "                              See --max-iterations= and --min-iterations= above\n"
         "  -e --command=COMMAND        Command/script to execute after each method call.\n"
         "     --show-command-output    Don't suppress stdout/stderr of a COMMAND.\n"
         "  -f --dictionary=FILENAME    Name of a file with custom dictionary which is used as input\n"
         "                              for fuzzed methods before generating random data.\n"
         "\nExamples:\n\n"
         "Test all methods of GNOME Shell. Be verbose.\n"
         "# %1$s -v -n org.gnome.Shell\n\n"
         "Test only method of the given bus name, object path and interface.\n"
         "# %1$s -n org.freedesktop.Avahi -o / -i org.freedesktop.Avahi.Server -t GetAlternativeServiceName\n\n"
         "Test all methods of Avahi and be verbose. Redirect all log messages including failures\n"
         "and warnings into avahi.log:\n"
         "# %1$s -v -n org.freedesktop.Avahi 2>&1 | tee avahi.log\n\n"
         "Test name org.freedesktop.Avahi, be verbose and do not use any suppression file:\n"
         "# %1$s -v -s -n org.freedesktop.Avahi\n",
         name);
}

static void df_parse_parameters(int argc, char **argv)
{
        int c = 0;
        int r;

        enum {
                /* 0x100: make geopt() return values >256 for options without
                 * short variant */
                ARG_SKIP_METHODS = 0x100,
                ARG_SKIP_PROPERTIES,
                ARG_SHOW_COMMAND_OUTPUT
        };

        static const struct option options[] = {
                { "buffer-limit",        required_argument,  NULL,   'b'                     },
                { "debug",               no_argument,        NULL,   'd'                     },
                { "command",             required_argument,  NULL,   'e'                     },
                { "string-file",         required_argument,  NULL,   'f'                     },
                { "help",                no_argument,        NULL,   'h'                     },
                { "interface",           required_argument,  NULL,   'i'                     },
                { "list",                no_argument,        NULL,   'l'                     },
                { "mem-limit",           required_argument,  NULL,   'm'                     },
                { "bus",                 required_argument,  NULL,   'n'                     },
                { "object",              required_argument,  NULL,   'o'                     },
                { "property",            required_argument,  NULL,   'p'                     },
                { "no-suppressions",     no_argument,        NULL,   's'                     },
                { "method",              required_argument,  NULL,   't'                     },
                { "verbose",             no_argument,        NULL,   'v'                     },
                { "log-dir",             required_argument,  NULL,   'L'                     },
                { "version",             no_argument,        NULL,   'V'                     },
                { "max-iterations",      required_argument,  NULL,   'x'                     },
                { "min-iterations",      required_argument,  NULL,   'y'                     },
                { "iterations",          required_argument,  NULL,   'I'                     },
                { "skip-methods",        no_argument,        NULL,   ARG_SKIP_METHODS        },
                { "skip-properties",     no_argument,        NULL,   ARG_SKIP_PROPERTIES     },
                { "show-command-output", no_argument,        NULL,   ARG_SHOW_COMMAND_OUTPUT },
                {}
        };

        while ((c = getopt_long(argc, argv, "n:o:i:m:b:t:e:L:x:y:f:I:p:sdvlhV", options, NULL)) >= 0) {
                switch (c) {
                        case 'n':
                                if (strlen(optarg) >= MAX_OBJECT_PATH_LENGTH) {
                                        df_fail("%s: maximum %d characters for option --"
                                                " 'n'\n", argv[0], MAX_OBJECT_PATH_LENGTH - 1);
                                        exit(1);
                                }
                                target_proc.name = optarg;
                                break;
                        case 'o':
                                if (strlen(optarg) >= MAX_OBJECT_PATH_LENGTH) {
                                        df_fail("%s: maximum %d characters for option --"
                                                " 'o'\n", argv[0], MAX_OBJECT_PATH_LENGTH - 1);
                                        exit(1);
                                }
                                target_proc.obj_path = optarg;
                                break;
                        case 'i':
                                if (strlen(optarg) >= MAX_OBJECT_PATH_LENGTH) {
                                        df_fail("%s: maximum %d characters for option --"
                                                " 'i'\n", argv[0], MAX_OBJECT_PATH_LENGTH - 1);
                                        exit(1);
                                }
                                target_proc.interface = optarg;
                                break;
                        case 'm':
                                df_verbose("Option -m has no effect anymore");
                                break;
                        case 'b': {
                                guint64 buf_length;

                                r = safe_strtoull(optarg, &buf_length);
                                if (r < 0) {
                                        df_fail("Error: invalid value for option -%c: %s\n", c, strerror(-r));
                                        exit(1);
                                }

                                if (buf_length < MIN_BUFFER_LENGTH || buf_length > MAX_BUFFER_LENGTH) {
                                        df_fail("Error: buffer length must be in range [%d, %d]\n", MIN_BUFFER_LENGTH, MAX_BUFFER_LENGTH);
                                        exit(1);
                                }

                                df_fuzz_set_buffer_length(buf_length);
                                break;
                        }
                        case 't':
                                df_test_method = optarg;
                                /* Skip properties when we test a specific method */
                                df_skip_properties = TRUE;
                                break;
                        case 'p':
                                df_test_property = optarg;
                                /* Skip methods when we test a specific property */
                                df_skip_methods = TRUE;
                                break;
                        case 'e':
                                df_execute_cmd = optarg;
                                break;
                        case 's':
                                df_supflg = 1;
                                break;
                        case 'd':
                                df_set_log_level(DF_LOG_LEVEL_DEBUG);
                                break;
                        case 'v':
                                df_set_log_level(DF_LOG_LEVEL_VERBOSE);
                                break;
                        case 'l':
                                df_list_names = 1;
                                break;
                        case 'V':
                                printf("dfuzzer %s\n", G_STRINGIFY(DFUZZER_VERSION));
                                exit(0);
                                break;
                        case 'h':
                                df_print_help(argv[0]);
                                exit(0);
                                break;
                        case 'L':
                                //we need at least 1 more char than usual for directory separator
                                if (strlen(optarg) >= MAX_OBJECT_PATH_LENGTH -1) {
                                        df_fail("%s: maximum %d characters for option --"
                                                " 'L'\n", argv[0], MAX_OBJECT_PATH_LENGTH - 1);
                                        exit(1);
                                }
                                df_log_dir_name = optarg;
                                break;
                        case 'x':
                                r = safe_strtoull(optarg, &df_max_iterations);
                                if (r < 0) {
                                        df_fail("Error: invalid value for option -%c: %s\n", c, strerror(-r));
                                        exit(1);
                                }

                                if (df_max_iterations <= 0) {
                                        df_fail("Error: -%c: at least 1 iteration required\n", c);
                                        exit(1);
                                }

                                if (df_min_iterations > df_max_iterations)
                                        df_min_iterations = df_max_iterations;

                                break;
                        case 'y':
                                r = safe_strtoull(optarg, &df_min_iterations);
                                if (r < 0) {
                                        df_fail("Error: invalid value for option -%c: %s\n", c, strerror(-r));
                                        exit(1);
                                }

                                if (df_min_iterations <= 0) {
                                        df_fail("Error: -%c: at least 1 iteration required\n", c);
                                        exit(1);
                                }

                                break;
                        case 'I':
                                r = safe_strtoull(optarg, &df_min_iterations);
                                if (r < 0) {
                                        df_fail("Error: invalid value for option -%c: %s\n", c, strerror(-r));
                                        exit(1);
                                }

                                if (df_min_iterations <= 0) {
                                        df_fail("Error: -%c: at least 1 iteration required\n", c);
                                        exit(1);
                                }

                                df_max_iterations = df_min_iterations;

                                break;
                        case 'f':
                                r = df_rand_load_external_dictionary(optarg);
                                if (r < 0) {
                                        df_fail("Error: failed to load dictionary from file '%s'\n", optarg);
                                        exit(1);
                                }

                                break;
                        case ARG_SKIP_METHODS:
                                df_skip_methods = TRUE;
                                break;
                        case ARG_SKIP_PROPERTIES:
                                df_skip_properties = TRUE;
                                break;
                        case ARG_SHOW_COMMAND_OUTPUT:
                                df_fuzz_set_show_command_output(TRUE);
                                break;
                        default:    // '?'
                                exit(1);
                                break;
                }
        }

        if (isempty(target_proc.name) && !df_list_names) {
                df_fail("Error: Connection name is required!\nSee -h for help.\n");
                exit(1);
        }

        if (!isempty(target_proc.interface) && isempty(target_proc.obj_path)) {
                df_fail("Error: Object path is required if interface specified!\nSee -h for help.\n");
                exit(1);
        }

        if (df_min_iterations > df_max_iterations) {
                df_fail("Error: minimal # of iterations can't be larger that the max one.\n");
                exit(1);
        }

        if (df_test_method && df_test_property) {
                df_fail("Error: -t/--method= and -p/--property= are mutually exclusive.\n");
                exit(1);
        }
}

static int df_process_bus(GBusType bus_type)
{
        g_autoptr(GDBusConnection) dcon = NULL;
        g_autoptr(GError) error = NULL;

        switch (bus_type) {
        case G_BUS_TYPE_SESSION:
                fprintf(stderr, "%s%s[SESSION BUS]%s\n", ansi_cr(), ansi_cyan(), ansi_normal());
                break;
        case G_BUS_TYPE_SYSTEM:
                fprintf(stderr, "%s%s[SYSTEM BUS]%s\n", ansi_cr(), ansi_cyan(), ansi_normal());
                break;
        default:
                df_fail("Invalid bus type\n");
                return DF_BUS_ERROR;
        }

        dcon = g_bus_get_sync(bus_type, NULL, &error);
        if (!dcon) {
                df_fail("Bus not found.\n");
                df_error("Error in g_bus_get_sync()", error);
                return DF_BUS_SKIP;
        }

        if (df_list_names) {
                // list names on the bus
                if (df_list_bus_names(dcon) == -1) {
                        df_debug("Error in df_list_bus_names() for session bus\n");
                        return DF_BUS_ERROR;
                }
        } else {
                // gets pid of tested process
                df_pid = df_get_pid(dcon, TRUE);
                if (df_pid > 0) {
                        df_print_process_info(df_pid);
                        fprintf(stderr, "%s%s[CONNECTED TO PID: %d]%s\n", ansi_cr(), ansi_cyan(), df_pid, ansi_normal());
                        if (!isempty(target_proc.interface)) {
                                fprintf(stderr, "Object: %s%s%s\n", ansi_bold(), target_proc.obj_path, ansi_normal());
                                fprintf(stderr, " Interface: %s%s%s\n", ansi_bold(), target_proc.interface, ansi_normal());
                                return df_fuzz(dcon, target_proc.name, target_proc.obj_path, target_proc.interface);
                        } else if (!isempty(target_proc.obj_path)) {
                                fprintf(stderr, "Object: %s%s%s\n", ansi_bold(), target_proc.obj_path, ansi_normal());
                                return df_traverse_node(dcon, target_proc.obj_path);
                        } else {
                                fprintf(stderr, "Object: %s/%s\n", ansi_bold(), ansi_normal());
                                return df_traverse_node(dcon, DF_BUS_ROOT_NODE);
                        }
                } else {
                        df_fail("Couldn't get the PID of the tested process\n");
                        return DF_BUS_NO_PID;
                }
        }

        return DF_BUS_OK;
}

static int df_check_proc_mounted(void)
{
        struct stat sb;

        /* Since checking for procfs is different between Linux, FreeBSD, and possibly other platforms let's
         * just check if /proc/1/status exists. This should achieve pretty much the same thing but without any
         * ifdefs. */
         if (stat("/proc/1/status", &sb) < 0) {
                df_fail("Cannot access /proc/1/status: %s\n", strerror(errno));
                return -1;
        }

        return 0;
}

int main(int argc, char **argv)
{
        const char *log_file_name;
        int rses = 0;               // return value from session bus testing
        int rsys = 0;               // return value from system bus testing
        int ret = 0;

        df_parse_parameters(argc, argv);

        if (df_check_proc_mounted() != 0) {
                df_fail("dfuzzer requires procfs to be mounted at /proc/ for process tracking\n");
                return 1;
        }

        if (df_log_dir_name) {
                log_file_name = strjoina(df_log_dir_name, "/", target_proc.name);
                if (df_log_open_log_file(log_file_name) < 0) {
                        ret = 1;
                        goto cleanup;
                }
        }
        if (!df_supflg) {
                if (df_suppression_load(&suppressions, target_proc.name) < 0) {
                        printf("%sExit status: 1%s\n", ansi_bold(), ansi_normal());
                        ret = 1;
                        goto cleanup;
                }
        }

        rses = df_process_bus(G_BUS_TYPE_SESSION);
        rsys = df_process_bus(G_BUS_TYPE_SYSTEM);

        // both tests ended with error
        if (rses == DF_BUS_ERROR || rsys == DF_BUS_ERROR)
                ret = 1;
        else if (rses == DF_BUS_FAIL || rsys == DF_BUS_FAIL)
                // at least one test found failures
                ret = 2;
        else if (rses == DF_BUS_WARNING || rsys == DF_BUS_WARNING)
                // at least one test found warnings
                ret = 3;
        else if (rses == DF_BUS_OK || rsys == DF_BUS_OK)
                // at least one of the tests passed (and the other one is not in
                // a fail state)
                ret = 0;
        else
                // all remaining combinations, like both results missing
                ret = 4;

        fprintf(stderr, "%sExit status: %d%s\n", ansi_bold(), ret, ansi_normal());

cleanup:
        df_suppression_free(&suppressions);

        return ret;
}
