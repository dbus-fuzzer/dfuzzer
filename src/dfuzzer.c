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
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>

#include "dfuzzer.h"
#include "introspection.h"
#include "fuzz.h"
#include "util.h"


/** Structure containing D-Bus name, object path and interface of process */
static struct fuzzing_target target_proc = { "", "", "" };
/** Debug flag */
static int df_verbose_flag;
/** Verbose flag */
static int df_debug_flag;
/** Option for listing names on the bus */
static int df_list_names;
/** Memory limit for tested process in kB */
static long df_mem_limit;
/** Maximum buffer size for generated strings by rand module (in Bytes) */
static long df_buf_size;
/** Contains method name or NULL. When not NULL, only method with this name
  * will be tested (do not free - points to argv) */
static char *df_test_method;
/** Tested process PID */
static int df_pid = -1;
/** NULL terminated array of method names which will be skipped from testing */
static char *df_suppression[MAXLEN];
/** NULL terminated array of suppressed method descriptions */
static char *df_supp_description[MAXLEN];
/** If -s option is passed 1, otherwise 0 */
static int df_supflg;
/** Suppression file #1 */
#define SF1 "./dfuzzer.conf"
/** Suppression file #2 (home dir) */
#define SF2 ".dfuzzer.conf"
/** Suppression file #3 (mandatory) */
#define SF3 "/etc/dfuzzer.conf"
/** Command/Script to execute by dfuzzer after each method call.
  * If command/script returns >0, dfuzzer prints fail message,
  * if 0 it continues */
static char *df_execute_cmd;
/** If -L is passed, full log of method calls and their return values will be
  * written to a [BUS_NAME.log] file */
static int df_full_log_flag;
/** Path to directory containing output logs */
static char *log_dir_name;
/** Pointer to a file for full logging  */
FILE* logfile;


/**
 * @function Main function controls fuzzing.
 * @param argc Number of program arguments
 * @param argv Pointer on string with program arguments
 * @return 0 on success, 1 on error, 2 when testing detected any failures
 * and/or warnings, 3 when testing detected only warnings
 */
int main(int argc, char **argv)
{
        const char *log_file_name;
        int rses = 0;               // return value from session bus testing
        int rsys = 0;               // return value from system bus testing
        int ret = 0;
        df_parse_parameters(argc, argv);

        if (df_full_log_flag) {
                log_file_name = strjoina(log_dir_name, "/", target_proc.name);
                logfile = fopen(log_file_name, "a+");
                if(!logfile) {
                        df_fail("Error opening file %s; detailed logs will not be written\n", log_file_name);
                        df_full_log_flag = 0;
                }
        }
        if (!df_supflg) {       // if -s option was not passed
                if (df_load_suppressions() == -1) {
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
        // free all suppressions and their descriptions
        for (int i = 0; df_suppression[i]; i++)
                free(df_suppression[i]);

        for (int i = 0; df_supp_description[i]; i++)
                free(df_supp_description[i]);

        return ret;
}

int df_process_bus(GBusType bus_type)
{
        _cleanup_(g_dbus_connection_unrefp) GDBusConnection *dcon = NULL;
        _cleanup_(g_error_freep) GError *error = NULL;

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
                df_pid = df_get_pid(dcon);
                if (df_pid > 0) {
                        df_print_process_info(df_pid);
                        fprintf(stderr, "%s%s[CONNECTED TO PID: %d]%s\n", ansi_cr(), ansi_cyan(), df_pid, ansi_normal());
                        if (!isempty(target_proc.interface)) {
                                fprintf(stderr, "Object: %s%s%s\n", ansi_bold(), target_proc.obj_path, ansi_normal());
                                fprintf(stderr, " Interface: %s%s%s\n", ansi_bold(), target_proc.interface, ansi_normal());
                                if (!df_is_object_on_bus(dcon, DF_BUS_ROOT_NODE)) {
                                        df_fail("Error: Unknown object path '%s'.\n", target_proc.obj_path);
                                        return DF_BUS_ERROR;
                                } else
                                        return df_fuzz(dcon, target_proc.name, target_proc.obj_path, target_proc.interface);
                        } else if (!isempty(target_proc.obj_path)) {
                                fprintf(stderr, "Object: %s%s%s\n", ansi_bold(), target_proc.obj_path, ansi_normal());
                                if (!df_is_object_on_bus(dcon, DF_BUS_ROOT_NODE)) {
                                        df_fail("Error: Unknown object path '%s'.\n", target_proc.obj_path);
                                        return DF_BUS_ERROR;
                                } else
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

/**
 * @function Calls method ListNames to get all available connection names
 * on the bus and prints them on the program output.
 * @param dcon D-Bus connection structure
 * @return 0 on success, -1 on error
 */
int df_list_bus_names(GDBusConnection *dcon)
{
        _cleanup_(g_dbus_proxy_unrefp) GDBusProxy *proxy = NULL;    // proxy for getting bus names
        _cleanup_(g_variant_iter_freep) GVariantIter *iter = NULL;
        _cleanup_(g_variant_unrefp) GVariant *response = NULL;  // response from method ListNames
        _cleanup_(g_error_freep) GError *error = NULL;          // must be set to NULL
        char *str;

        // Uses dcon (GDBusConnection *) to create proxy for accessing
        // org.freedesktop.DBus (for calling its method ListNames)
        proxy = g_dbus_proxy_new_sync(
                        dcon,
                        G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
                        NULL,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        NULL,
                        &error);
        if (!proxy) {
                df_fail("Error: Unable to create proxy for getting bus names.\n");
                df_error("Error in g_dbus_proxy_new_sync()", error);
                return -1;
        }

        // Synchronously invokes method ListNames
        response = g_dbus_proxy_call_sync(
                        proxy,
                        "ListNames",
                        NULL,
                        G_DBUS_CALL_FLAGS_NONE,
                        -1,
                        NULL,
                        &error);
        if (!response) {
                g_dbus_error_strip_remote_error(error);
                df_fail("Error: %s.\n", error->message);
                df_error("Error in g_dbus_proxy_call_sync()", error);
                return -1;
        }

        g_variant_get(response, "(as)", &iter);
        while (g_variant_iter_loop(iter, "s", &str)) {
                if (str[0] != ':')
                        printf("%s\n", str);
        }

        return 0;
}

/**
 * @function Traverses through all objects of bus name target_proc.name
 * and is looking for object path target_proc.obj_path
 * @param dcon D-Bus connection structure
 * @param root_node Starting object path (all nodes from this object path
 * will be traversed)
 * @return 1 when obj. path target_proc.obj_path is found on bus, 0 otherwise
 */
int df_is_object_on_bus(GDBusConnection *dcon, const char *root_node)
{
        char *intro_iface = "org.freedesktop.DBus.Introspectable";
        char *intro_method = "Introspect";
        _cleanup_(g_variant_unrefp) GVariant *response = NULL;
        _cleanup_(g_dbus_proxy_unrefp) GDBusProxy *dproxy = NULL;
        _cleanup_(g_freep) gchar *introspection_xml = NULL;
        _cleanup_(g_error_freep) GError *error = NULL;
        /** Information about nodes in a remote object hierarchy. */
        _cleanup_(g_dbus_node_info_unrefp) GDBusNodeInfo *node_data = NULL;
        GDBusNodeInfo *node = NULL;
        int i = 0;
        int ret = 0;        // return value of this function

        if (strstr(root_node, target_proc.obj_path) != NULL)
                return 1;

        if (!df_is_valid_dbus(target_proc.name, root_node, intro_iface))
                return 0;
        dproxy = g_dbus_proxy_new_sync(
                        dcon,
                        G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
                        NULL,
                        target_proc.name,
                        root_node,
                        intro_iface,
                        NULL,
                        &error);
        if (!dproxy) {
                df_fail("Error: Unable to create proxy for bus name '%s'.\n", target_proc.name);
                df_error("Error in g_dbus_proxy_new_sync()", error);
                return 0;
        }

        response = g_dbus_proxy_call_sync(
                        dproxy,
                        intro_method,
                        NULL,
                        G_DBUS_CALL_FLAGS_NONE,
                        -1,
                        NULL,
                        &error);
        if (!response) {
                g_dbus_error_strip_remote_error(error);
                df_fail("Error: %s.\n", error->message);
                df_error("Error in g_dbus_proxy_call_sync()", error);
                return 0;
        }
        g_variant_get(response, "(s)", &introspection_xml);
        if (!introspection_xml) {
                df_fail("Error: Unable to get introspection data from GVariant.\n");
                return 0;
        }

        // Parses introspection_xml and returns a GDBusNodeInfo representing
        // the data.
        node_data = g_dbus_node_info_new_for_xml(introspection_xml, &error);
        if (!node_data) {
                df_fail("Error: Unable to get introspection data.\n");
                df_error("Error in g_dbus_node_info_new_for_xml()", error);
                return 0;
        }

        // go through all nodes
        i = 0;
        node = node_data->nodes[i++];
        while (node != NULL) {
                _cleanup_free_ char *object = NULL;
                // create next object path
                object = strjoin(root_node, strlen(root_node) == 1 ? "" : "/", node->path);
                if (object == NULL) {
                        df_fail("Error: Could not allocate memory for object string.\n");
                        return DF_BUS_ERROR;
                }
                ret = df_is_object_on_bus(dcon, object);
                if (ret == 1) {
                        free(object);
                        return 1;
                }
                // move to next node
                node = node_data->nodes[i++];
        }

        return ret;
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
int df_traverse_node(GDBusConnection *dcon, const char *root_node)
{
        char *intro_iface = "org.freedesktop.DBus.Introspectable";
        char *intro_method = "Introspect";
        _cleanup_(g_variant_unrefp) GVariant *response = NULL;
        _cleanup_(g_dbus_proxy_unrefp) GDBusProxy *dproxy = NULL;
        _cleanup_(g_freep) gchar *introspection_xml = NULL;
        _cleanup_(g_error_freep) GError *error = NULL;
        /** Information about nodes in a remote object hierarchy. */
        _cleanup_(g_dbus_node_info_unrefp) GDBusNodeInfo *node_data = NULL;
        GDBusNodeInfo *node = NULL;
        int i = 0;
        /** Information about a D-Bus interface. */
        GDBusInterfaceInfo *interface = NULL;
        /** Return values */
        int rd = 0;          // return value from df_fuzz()
        int rt = 0;          // return value from recursive transition
        int ret = DF_BUS_OK; // return value of this function


        if (!df_is_valid_dbus(target_proc.name, root_node, intro_iface))
                return DF_BUS_ERROR;
        dproxy = g_dbus_proxy_new_sync(
                        dcon,
                        G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
                        NULL,
                        target_proc.name,
                        root_node,
                        intro_iface,
                        NULL,
                        &error);
        if (!dproxy) {
                df_fail("Error: Unable to create proxy for bus name '%s'.\n", target_proc.name);
                df_error("Error in g_dbus_proxy_new_sync()", error);
                return DF_BUS_ERROR;
        }

        response = g_dbus_proxy_call_sync(
                        dproxy,
                        intro_method,
                        NULL,
                        G_DBUS_CALL_FLAGS_NONE,
                        -1,
                        NULL,
                        &error);
        if (!response) {
                _cleanup_(g_freep) gchar *dbus_error = NULL;
                // D-Bus exceptions
                if ((dbus_error = g_dbus_error_get_remote_error(error)) != NULL) {
                        // if process does not respond
                        if (strcmp(dbus_error, "org.freedesktop.DBus.Error.NoReply") == 0)
                                return DF_BUS_FAIL;
                        if (strcmp(dbus_error, "org.freedesktop.DBus.Error.Timeout") == 0)
                                return DF_BUS_FAIL;
                        return DF_BUS_OK;
                } else {
                        g_dbus_error_strip_remote_error(error);
                        df_fail("Error: %s.\n", error->message);
                        df_error("Error in g_dbus_proxy_call_sync()", error);
                        return DF_BUS_ERROR;
                }
        }
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
        i = 0;
        interface = node_data->interfaces[i++];
        while (interface != NULL) {
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
                interface = node_data->interfaces[i++];
        }

        // if object path was set as dfuzzer option, do not traverse
        // through all objects
        if (strlen(target_proc.obj_path) != 0)
                return ret;

        // go through all nodes
        i = 0;
        node = node_data->nodes[i++];
        while (node != NULL) {
                _cleanup_free_ char *object = NULL;
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
                // move to next node
                node = node_data->nodes[i++];
        }

        return ret;
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
int df_fuzz(GDBusConnection *dcon, const char *name, const char *obj, const char *intf)
{
        _cleanup_(g_dbus_proxy_unrefp) GDBusProxy *dproxy = NULL; // D-Bus interface proxy
        _cleanup_(g_error_freep) GError *error = NULL;
        GDBusMethodInfo *m;
        GDBusArgInfo *in_arg;
        _cleanup_(closep) int statfd = -1;
        int ret = 0;
        int method_found = 0;   // If df_test_method is found in an interface,
        // method_found is set to 1, otherwise is 0.
        int void_method;        // If method has out args 1, 0 otherwise.
        int rv = DF_BUS_OK;     // return value of function
        int i;


        // Sanity check fuzzing target
        if (isempty(name) || isempty(obj) || isempty(intf)) {
                df_fail("Error in target specification.\n");
                return DF_BUS_ERROR;
        }

        // Creates a proxy for accessing intf on the remote object at path obj
        // owned by name at dcon.
        if (!df_is_valid_dbus(name, obj, intf))
                return DF_BUS_ERROR;
        dproxy = g_dbus_proxy_new_sync(
                        dcon,
                        G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
                        NULL,
                        name,
                        obj,
                        intf,
                        NULL,
                        &error);
        if (!dproxy) {
                df_fail("Error: Unable to create proxy for bus name '%s'.\n", name);
                df_error("Error in g_dbus_proxy_new_sync() on creating proxy", error);
                return DF_BUS_ERROR;
        }

        // Introspection of object through proxy.
        if (df_init_introspection(dproxy, name, intf) == -1) {
                df_debug("Error in df_init_introspection() on introspecting object\n");
                return DF_BUS_ERROR;
        }

        // opens process status file
        statfd = df_open_proc_status_file(df_pid);
        if (statfd == -1) {
                df_unref_introspection();
                df_debug("Error in df_open_proc_status_file()\n");
                return DF_BUS_ERROR;
        }

        // tells fuzz module to call methods on dproxy, use FD statfd
        // for monitoring tested process and memory limit for process
        if (df_fuzz_init(dproxy, statfd, df_pid, df_mem_limit) == -1) {
                df_unref_introspection();
                df_debug("Error in df_fuzz_add_proxy()\n");
                return DF_BUS_ERROR;
        }

        for (; (m = df_get_method()) != NULL; df_next_method()) {
                // testing only one method with name df_test_method
                if (df_test_method != NULL) {
                        if (strcmp(df_test_method, m->name) != 0) {
                                continue;
                        }
                        method_found = 1;
                }

                // if method name is in df_suppression array of names, it is skipped
                if (df_suppression[0] != NULL) {
                        int skipflg = 0;
                        for (i = 0; df_suppression[i] != NULL; i++) {
                                if (strcmp(df_suppression[i], m->name) == 0) {
                                        skipflg++;
                                        break;
                                }
                        }
                        if (skipflg) {
                                if (strlen(df_supp_description[i]) == 0) {
                                        df_verbose("%s  %sSKIP%s %s - suppressed method\n",
                                                   ansi_cr(), ansi_blue(), ansi_normal(), df_suppression[i]);
                                } else {
                                        df_verbose("%s  %sSKIP%s %s - %s\n",
                                                   ansi_cr(), ansi_blue(), ansi_normal(),
                                                   df_suppression[i], df_supp_description[i]);
                                }
                                continue;
                        }
                }

                // adds method name to the fuzzing module
                if (df_fuzz_add_method(m->name) == -1) {
                        df_unref_introspection();
                        df_debug("Error in df_fuzz_add_method()\n");
                        return DF_BUS_ERROR;
                }

                for (; (in_arg = df_get_method_arg()) != NULL; df_next_method_arg()) {
                        // adds method argument signature to the fuzzing module
                        if (df_fuzz_add_method_arg(in_arg->signature) == -1) {
                                df_unref_introspection();
                                df_debug("Error in df_fuzz_add_method_arg()\n");
                                return DF_BUS_ERROR;
                        }
                }

                // methods with no arguments are not tested
                if (df_list_args_count() == 0) {
                        df_verbose("%s  %sSKIP%s %s - void method\n",
                                   ansi_cr(), ansi_blue(), ansi_normal(), m->name);
                        df_fuzz_clean_method();
                        continue;
                }

                if (df_method_has_out_args())
                        void_method = 0;
                else
                        void_method = 1;

                // tests for method
                ret = df_fuzz_test_method(
                                statfd,
                                df_buf_size,
                                name,
                                obj,
                                intf,
                                df_pid,
                                void_method,
                                df_execute_cmd);
                if (ret == -1) {
                        // error during testing method
                        df_fuzz_clean_method();
                        df_unref_introspection();
                        df_debug("Error in df_fuzz_test_method()\n");
                        return DF_BUS_ERROR;
                } else if (ret == 1 && df_test_method == NULL) {
                        // launch process again after crash
                        rv = DF_BUS_FAIL;
                        g_object_unref(dproxy);
                        dproxy = NULL;

                        if (!df_is_valid_dbus(name, obj, intf))
                                return DF_BUS_ERROR;
                        dproxy = g_dbus_proxy_new_sync(
                                        dcon,
                                        G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
                                        NULL,
                                        name,
                                        obj,
                                        intf,
                                        NULL,
                                        &error);
                        if (!dproxy) {
                                df_fuzz_clean_method();
                                df_unref_introspection();
                                df_fail("Error: Unable to create proxy for bus name '%s'.\n", name);
                                df_error("Error in g_dbus_proxy_new_sync() on creating proxy", error);
                                return DF_BUS_ERROR;
                        }

                        sleep(5);       // wait for application to launch

                        // gets pid of tested process
                        df_pid = df_get_pid(dcon);
                        if (df_pid < 0) {
                                df_fuzz_clean_method();
                                df_unref_introspection();
                                df_debug("Error in df_get_pid() on getting pid of process\n");
                                return DF_BUS_ERROR;
                        }
                        fprintf(stderr, "%s%s[RE-CONNECTED TO PID: %d]%s\n",
                                        ansi_cr(), ansi_cyan(), df_pid, ansi_blue());

                        // opens process status file
                        close(statfd);
                        statfd = -1;
                        if ((statfd = df_open_proc_status_file(df_pid)) == -1) {
                                df_fuzz_clean_method();
                                df_unref_introspection();
                                df_debug("Error in df_open_proc_status_file()\n");
                                return DF_BUS_ERROR;
                        }

                        // tells fuzz module to call methods on different dproxy and to use
                        // new status file of process with PID df_pid
                        if (df_fuzz_init(dproxy, statfd, df_pid, df_mem_limit) == -1) {
                                df_fuzz_clean_method();
                                df_unref_introspection();
                                df_debug("Error in df_fuzz_add_proxy()\n");
                                return DF_BUS_ERROR;
                        }
                } else if (ret == 1 && df_test_method != NULL) {
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

                df_fuzz_clean_method();     // cleaning up after testing method
        }


        if (method_found == 0 && df_test_method != NULL) {
                df_fail("Error: Method '%s' is not in the interface '%s'.\n", df_test_method, intf);
                df_unref_introspection();
                return rv;
        }
        df_unref_introspection();
        return rv;
}

/**
 * @function Checks if name is valid D-Bus name, obj is valid
 * D-Bus object path and intf is valid D-Bus interface.
 * @param name D-Bus name
 * @param obj D-Bus object path
 * @param intf D-Bus interface
 * @return 1 if name, obj and intf are valid, 0 otherwise
 */
int df_is_valid_dbus(const char *name, const char *obj, const char *intf)
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
 * @function Opens process status file.
 * @param pid PID - identifier of process
 * @return FD of status file on success, -1 on error
 */
int df_open_proc_status_file(const int pid)
{
        char file_path[14 + DECIMAL_STR_MAX(pid)]; // "/proc/PID/status"
        int statfd;

        sprintf(file_path, "/proc/%d/status", pid);

        statfd = open(file_path, O_RDONLY);
        if (statfd == -1) {
                df_fail("Error: Unable to open file '%s'.\n", file_path);
                return -1;
        }
        return statfd;
}

/**
 * @function Calls method GetConnectionUnixProcessID on the interface
 * org.freedesktop.DBus to get process pid.
 * @param dcon D-Bus connection structure
 * @return Process PID on success, -1 on error
 */
int df_get_pid(GDBusConnection *dcon)
{
        _cleanup_(g_error_freep) GError *error = NULL;
        _cleanup_(g_dbus_proxy_unrefp) GDBusProxy *pproxy = NULL;
        _cleanup_(g_variant_unrefp) GVariant *variant_pid = NULL;
        int pid = -1;

        // Uses dcon (GDBusConnection *) to create proxy for accessing
        // org.freedesktop.DBus (for calling its method GetConnectionUnixProcessID)
        pproxy = g_dbus_proxy_new_sync(
                        dcon,
                        G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES|G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
                        NULL,
                        "org.freedesktop.DBus",
                        "/org/freedesktop/DBus",
                        "org.freedesktop.DBus",
                        NULL,
                        &error);
        if (!pproxy) {
                df_fail("Error: Unable to create proxy for getting process pid.\n");
                df_error("Error on creating proxy for getting process pid", error);
                return -1;
        }

        // Synchronously invokes method GetConnectionUnixProcessID
        variant_pid = g_dbus_proxy_call_sync(
                        pproxy,
                        "GetConnectionUnixProcessID",
                        g_variant_new("(s)", target_proc.name),
                        G_DBUS_CALL_FLAGS_NONE,
                        -1,
                        NULL,
                        &error);
        if (!variant_pid) {
                g_dbus_error_strip_remote_error(error);
                df_fail("Error: %s.\n", error->message);
                df_error("Error in g_dbus_proxy_call_sync()", error);
                return -1;
        }
        g_variant_get(variant_pid, "(u)", &pid);

        return pid;
}

/**
 * @function Prints process name and package to which process belongs.
 * @param pid PID of process
 * Note: Any error in this function is suppressed. On error, process name
 *       and package is just not printed.
 */
void df_print_process_info(int pid)
{
        char proc_path[15 + DECIMAL_STR_MAX(int)]; // "/proc/(int)/[exe|cmdline]"
        char name[PATH_MAX + 1];
        _cleanup_close_ int fd = -1;
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

/**
 * @function Parses program options and stores them into global
 * variables:
 *  - df_buf_size -
 *     Maximum buffer size for generated strings by rand
 *     module (in Bytes)
 *  - df_mem_limit -
 *     Memory limit for tested process in kB
 *  - df_test_method -
 *     Contains method name or NULL. When not NULL, only
 *     method with this name will be tested
 *  - target_proc -
 *     Is of type struct fuzzing_target and is used
 *     to store bus name, object path and interface
 *  - df_verbose_flag -
 *     Be verbose
 *  - df_debug_flag -
 *     Include debug output
 *  - df_supflg -
 *     If -s option is passed 1, otherwise 0
 *  - df_execute_cmd -
 *     Command/script to execute after each method call
 * If error occures function ends program.
 * @param argc Count of options
 * @param argv Pointer on strings containing options of program
 */
void df_parse_parameters(int argc, char **argv)
{
        int c = 0;

        static const struct option options[] = {
                { "buffer-limit",       required_argument,  NULL,   'b' },
                { "debug",              no_argument,        NULL,   'd' },
                { "command",            required_argument,  NULL,   'e' },
                { "help",               no_argument,        NULL,   'h' },
                { "interface",          required_argument,  NULL,   'i' },
                { "list",               no_argument,        NULL,   'l' },
                { "mem-limit",          required_argument,  NULL,   'm' },
                { "bus",                required_argument,  NULL,   'n' },
                { "object",             required_argument,  NULL,   'o' },
                { "no-suppressions",    no_argument,        NULL,   's' },
                { "method",             required_argument,  NULL,   't' },
                { "verbose",            no_argument,        NULL,   'v' },
                { "log-dir",            required_argument,  NULL,   'L' },
                { "version",            no_argument,        NULL,   'V' },
                {}
        };

        while ((c = getopt_long(argc, argv, "n:o:i:m:b:t:e:L:sdvlhV", options, NULL)) >= 0) {
                switch (c) {
                        case 'n':
                                if (strlen(optarg) >= MAXLEN) {
                                        df_fail("%s: maximum %d characters for option --"
                                                " 'n'\n", argv[0], MAXLEN - 1);
                                        exit(1);
                                }
                                target_proc.name = optarg;
                                break;
                        case 'o':
                                if (strlen(optarg) >= MAXLEN) {
                                        df_fail("%s: maximum %d characters for option --"
                                                " 'o'\n", argv[0], MAXLEN - 1);
                                        exit(1);
                                }
                                target_proc.obj_path = optarg;
                                break;
                        case 'i':
                                if (strlen(optarg) >= MAXLEN) {
                                        df_fail("%s: maximum %d characters for option --"
                                                " 'i'\n", argv[0], MAXLEN - 1);
                                        exit(1);
                                }
                                target_proc.interface = optarg;
                                break;
                        case 'm':
                                df_mem_limit = strtol(optarg, NULL, 10);
                                if (df_mem_limit <= 0 || errno == ERANGE || errno == EINVAL) {
                                        df_fail("%s: invalid value for option -- 'm'\n", argv[0]);
                                        exit(1);
                                }
                                break;
                        case 'b':
                                df_buf_size = strtol(optarg, NULL, 10);
                                if (df_buf_size < MINLEN || errno == ERANGE || errno == EINVAL) {
                                        df_fail("%s: invalid value for option -- 'b'\n"
                                                " -- at least %d B are required\n", argv[0], MINLEN);
                                        exit(1);
                                }
                                break;
                        case 't':
                                df_test_method = optarg;
                                break;
                        case 'e':
                                df_execute_cmd = optarg;
                                break;
                        case 's':
                                df_supflg = 1;
                                break;
                        case 'd':
                                df_debug_flag = 1;
                                break;
                        case 'v':
                                df_verbose_flag = 1;
                                break;
                        case 'l':
                                df_list_names = 1;
                                break;
                        case 'V':
                                printf("%s", DF_VERSION);
                                exit(0);
                                break;
                        case 'h':
                                df_print_help(argv[0]);
                                exit(0);
                                break;
                        case 'L':
                                //we need at least 1 more char than usual for directory separator
                                if (strlen(optarg) >= MAXLEN -1) {
                                        df_fail("%s: maximum %d characters for option --"
                                                " 'L'\n", argv[0], MAXLEN - 1);
                                        exit(1);
                                }
                                log_dir_name = optarg;
                                df_full_log_flag = 1;
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
}

/**
 * @function Searches target_proc.name in suppression file SF1, SF2 and SF3
 * (the file which is opened first is parsed). If it is found, df_suppression
 * array is seeded with names of methods and df_supp_description is seeded
 * with descriptions why methods are skipped (df_suppression array is used
 * to skip methods which it contains when testing target_proc.name).
 * Suppression file is in format:
 * [bus_name]
 * method1 description
 * method2 description
 * [bus_name2]
 * method1 description
 * method2 description
 * ...
 * @return 0 on success, -1 on error
 */
int df_load_suppressions(void)
{
        FILE *f;
        char *sup_file;
        char *env = NULL;
        // buf = method (max. 255) + description (max. 255) + '[' + ']' + '\0'
        char buf[(MAXLEN*2)+2];
        char *ptr;
        int name_found = 0;
        int i, j;


        // the same dir
        sup_file = SF1;
        f = fopen(sup_file, "r");
        if (f == NULL)
                df_verbose("'%s' file not found.\n", sup_file);
        else
                goto file_open;
        // home dir
        env = getenv("HOME");
        if (env) {
                sup_file = malloc(sizeof(char) * (strlen(env) + strlen(SF2) + 2));
                if (sup_file == NULL) {
                        df_fail("Error: Could not allocate memory for suppression file name\n");
                        return -1;
                }
                sprintf(sup_file, "%s/%s", env, SF2);
                f = fopen(sup_file, "r");
                if (f == NULL) {
                        df_verbose("'%s' file not found.\n", sup_file);
                        free(sup_file);
                        env = NULL;
                }
                else
                        goto file_open;
        }
        // dir /etc
        sup_file = SF3;     // mandatory (must exist)
        f = fopen(sup_file, "r");
        if (f == NULL) {
                df_fail("Error: Unable to open file '%s'.\n", sup_file);
                return -1;
        }

file_open:
        df_verbose("Suppressions from '%s'\n", sup_file);

        // determines if currently tested bus name is in suppression file
        while (fgets(buf, MAXLEN+2, f) != NULL) {
                if (strstr(buf, target_proc.name) != NULL) {
                        name_found++;
                        break;
                }
        }
        if (ferror(f)) {
                df_fail("Error: Reading from file '%s'.\n", sup_file);
                fclose(f);
                if (env != NULL)
                        free(sup_file);
                return -1;
        }

        // no suppressions for tested bus name
        if (!name_found) {
                fclose(f);
                if (env != NULL)
                        free(sup_file);
                return 0;
        } else
                df_verbose("Found suppressions for bus name '%s'\n", target_proc.name);


        // seeds method names into df_suppression array
        for (i = 0; (fgets(buf, MAXLEN*2, f) != NULL) && (i < MAXLEN); i++) {
                if (buf[0] == '[')
                        break;
                ptr = buf;
                while (isspace(*ptr))
                        ptr++;
                if (strlen(ptr) == 0) {
                        --i;
                        continue;
                }

                df_suppression[i] = malloc(MAXLEN * sizeof(char));
                if (df_suppression[i] == NULL) {
                        df_fail("Error: Could not allocate memory for suppression\n");
                        fclose(f);
                        if (env != NULL)
                                free(sup_file);
                        return -1;
                }
                df_supp_description[i] = malloc(MAXLEN * sizeof(char));
                if (df_supp_description[i] == NULL) {
                        df_fail("Error: Could not allocate memory for suppression description\n");
                        fclose(f);
                        if (env != NULL)
                                free(sup_file);
                        return -1;
                }

                ptr = buf;
                j = 0;
                while ((*ptr != ' ') && (*ptr != '\n') && j < (MAXLEN-1)) {
                        df_suppression[i][j++] = *ptr;
                        ptr++;
                }
                df_suppression[i][j] = '\0';

                j = 0;
                if (*ptr != '\n') {
                        ptr++;  // skips the space
                        while ((*ptr != '\n') && j < (MAXLEN-1)) {
                                df_supp_description[i][j++] = *ptr;
                                ptr++;
                        }
                }
                df_supp_description[i][j] = '\0';
        }
        df_suppression[i] = NULL;
        if (ferror(f)) {
                df_fail("Error: Reading from file '%s'.\n", sup_file);
                fclose(f);
                if (env != NULL)
                        free(sup_file);
                return -1;
        }

        fclose(f);
        if (env != NULL)
                free(sup_file);
        return 0;
}

/**
 * @function Prints help.
 * @param name Name of program
 */
void df_print_help(const char *name)
{
        printf(
                "Usage: dfuzzer -n BUS_NAME [OTHER_OPTIONS]\n\n"
                "Tool for fuzz testing processes communicating through D-Bus.\n"
                "The fuzzer traverses through all the methods on the given bus name.\n"
                "By default only failures and warnings are printed."
                " Use -v for verbose mode.\n\n"
                "REQUIRED OPTIONS:\n"
                "-n --bus=BUS_NAME\n\n"
                "OTHER OPTIONS:\n"
                "-V --version\n"
                "   Print dfuzzer version and exit.\n"
                "-h --help\n"
                "   Print dfuzzer help and exit.\n"
                "-l --list\n"
                "   List all available connection names on both buses.\n"
                "-v --verbose\n"
                "   Enable verbose messages.\n"
                "-d --debug\n"
                "   Enable debug messages. Implies -v. This option should not be normally\n"
                "   used during testing.\n"
                "-L --log-dir=DIRNAME\n"
                "   Write full, parseable log to a DIRNAME/BUS_NAME file. The directory must exist.\n"
                "-s --no-suppressions\n"
                "   Do not use suppression file. Default behaviour is to use suppression\n"
                "   files in this order (if one doesn't exist next in order is taken\n"
                "   for loading suppressions - this way user can define his own file):\n"
                "   1. '%s'\n"
                "   2. '~/%s'\n"
                "   3. '%s'\n"
                "   Suppression files must be defined in this format:\n"
                "   [bus_name_1]\n"
                "   method0\n"
                "   [bus_name_2]\n"
                "   method1\n"
                "   method2\n"
                "   ...\n"
                "   which tells that for example methods 'method1' and 'method2' will be\n"
                "   skipped when testing bus name 'bus_name_2'.\n"
                "-o --object=OBJECT_PATH\n"
                "   Optional object path to test. All children objects are traversed.\n"
                "-i --interface=INTERFACE\n"
                "   Interface to test. Requires also -o option.\n"
                "-m --mem-limit=MEM_LIMIT [in kB]\n"
                "   When tested process exceeds this limit, warning is printed\n"
                "   on the output. Default value for this limit is 3x process intial\n"
                "   memory size. If set memory limit value is less than or\n"
                "   equal to process initial memory size, it will be adjusted\n"
                "   to default value (3x process intial memory size).\n"
                "-b --buffer-limit=MAX_BUF_SIZE [in B]\n"
                "   Maximum buffer size for generated strings, minimal value for this\n"
                "   option is 256 B. Default maximum size is 50000 B ~= 50 kB (the greater\n"
                "   the limit, the longer the testing).\n"
                "-t --method=METHOD_NAME\n"
                "   When this parameter is provided, only method METHOD_NAME is tested.\n"
                "   All other methods of an interface are skipped.\n"
                "   Requires also -o and -i options.\n"
                "-e --command=COMMAND\n"
                "   Command/Script to execute after each method call. If command/script\n"
                "   finishes unsuccessfuly, fail message is printed with its return\n"
                "   value.\n"
                "\nExamples:\n\n"
                " Test all methods of GNOME Shell. Be verbose.\n"
                " # %s -v -n org.gnome.Shell\n\n"
                " Test only method of the given bus name, object path and interface.\n"
                " # %s -n org.freedesktop.Avahi -o / -i org.freedesktop.Avahi.Server -t"
                " GetAlternativeServiceName\n\n"
                " Test all methods of Avahi and be verbose. Redirect all log messages\n"
                " including failures and warnings into avahi.log:\n"
                " # %s -v -n org.freedesktop.Avahi 2>&1 | tee avahi.log\n\n"
                " Test name org.freedesktop.Avahi, be verbose and do not use suppression\n"
                " file:\n"
                " # %s -v -s -n org.freedesktop.Avahi\n",
                SF1, SF2, SF3, name, name, name, name);
}

/**
 * @function Displays an error message.
 * @param message Error message which will be printed
 * @param error Pointer on GError structure containing error specification
 */
void df_error(const char *message, GError *error)
{
        if (!df_debug_flag) {
                return;
        }
        if (error == NULL)
                fprintf(stderr, "%s\n", message);
        else
                fprintf(stderr, "%s: %s\n", message, error->message);
}

/**
 * @function Prints debug message.
 * @param format Format string
 */
void df_debug(const char *format, ...)
{
        if (!df_debug_flag)
                return;
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
        fflush(stdout);
}

/**
 * @function Prints verbose message.
 * @param format Format string
 */
void df_verbose(const char *format, ...)
{
        if (!df_verbose_flag && !df_debug_flag)
                return;
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
        fflush(stdout);
}

/**
 * @function Prints error message.
 * @param format Format string
 */
void df_fail(const char *format, ...)
{
        va_list args;
        va_start(args, format);
        vfprintf(stderr, format, args);
        va_end(args);
        fflush(stderr);
}
