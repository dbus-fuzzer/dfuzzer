/** @file dfuzzer.c */
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
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "dfuzzer.h"
#include "introspection.h"
#include "fuzz.h"


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
	will be tested*/
static char *df_test_method = NULL;
/** Tested process PID */
static int df_pid = -1;


/**
	@function Main function controls fuzzing.
	@param argc Number of program arguments
	@param argv Pointer on string with program arguments
	@return 0 on success, 1 on error, 2 when testing detected any failures
*/
int main(int argc, char **argv)
{
	GDBusConnection *dcon;		// D-Bus connection structure
	GError *error = NULL;		// must be set to NULL
	char *root_node = "/";
	int rses = 0;				// return value from session bus testing
	int rsys = 0;				// return value from system bus testing

	df_parse_parameters(argc, argv);

	// Initializes the type system.
	g_type_init();


	// Synchronously connects to the session bus daemon.
	printf("\e[36m[SESSION BUS]\e[0m\n", target_proc.name);
	if ((dcon = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error)) == NULL) {
		df_fail("Session bus not found.\n");
		df_error("Error in g_bus_get_sync()", error);
		error = NULL;
		goto skip_session;
	}
	if (df_list_names) {
		// list names on the bus
		if (df_list_bus_names(dcon) == -1) {
			df_debug("Error in df_list_bus_names() for session bus\n");
			rses = 1;
		}
	} else {
		// gets pid of tested process
		df_pid = df_get_pid(dcon);
		if (df_pid > 0) {
			printf("\e[36m[CONNECTED TO PID: %d]\e[0m\n", df_pid);
			if (strlen(target_proc.interface) != 0) {
				printf("Object: \e[1m%s\e[0m\n", target_proc.obj_path);
				printf(" Interface: \e[1m%s\e[0m\n", target_proc.interface);
				if (!df_is_object_on_bus(dcon, root_node)) {
					df_fail("Error: Unknown object path '%s'.\n",
							target_proc.obj_path);
					rses = 1;
				} else {
					rses = df_fuzz(dcon, target_proc.name, target_proc.obj_path,
								target_proc.interface);
				}
			} else if (strlen(target_proc.obj_path) != 0) {
				printf("Object: \e[1m%s\e[0m\n", target_proc.obj_path);
				if (!df_is_object_on_bus(dcon, root_node)) {
					df_fail("Error: Unknown object path '%s'.\n",
							target_proc.obj_path);
					rses = 1;
				} else
					rses = df_traverse_node(dcon, target_proc.obj_path);
			} else {
				printf("Object: \e[1m/\e[0m\n");
				rses = df_traverse_node(dcon, root_node);
			}
		} else
			rses = 1;
	}
	g_object_unref(dcon);


skip_session:


	// Synchronously connects to the system bus daemon.
	printf("\e[36m[SYSTEM  BUS]\e[0m\n", target_proc.name);
	if ((dcon = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error)) == NULL) {
		df_fail("System bus not found.\n");
		df_error("Error in g_bus_get_sync()", error);
		error = NULL;
		goto skip_system;
	}
	if (df_list_names) {
		// list names on the bus
		if (df_list_bus_names(dcon) == -1) {
			df_debug("Error in df_list_bus_names() for system bus\n");
			rsys = 1;
		}
	} else {
		// gets pid of tested process
		df_pid = df_get_pid(dcon);
		if (df_pid > 0) {
			printf("\e[36m[CONNECTED TO PID: %d]\e[0m\n", df_pid);
			if (strlen(target_proc.interface) != 0) {
				printf("Object: \e[1m%s\e[0m\n", target_proc.obj_path);
				printf(" Interface: \e[1m%s\e[0m\n", target_proc.interface);
				if (!df_is_object_on_bus(dcon, root_node)) {
					df_fail("Error: Unknown object path '%s'.\n",
							target_proc.obj_path);
					rsys = 1;
				} else {
					rsys = df_fuzz(dcon, target_proc.name, target_proc.obj_path,
								target_proc.interface);
				}
			} else if (strlen(target_proc.obj_path) != 0) {
				printf("Object: \e[1m%s\e[0m\n", target_proc.obj_path);
				if (!df_is_object_on_bus(dcon, root_node)) {
					df_fail("Error: Unknown object path '%s'.\n",
							target_proc.obj_path);
					rsys = 1;
				} else
					rsys = df_traverse_node(dcon, target_proc.obj_path);
			} else {
				printf("Object: \e[1m/\e[0m\n");
				rsys = df_traverse_node(dcon, root_node);
			}
		} else
			rsys = 1;
	}
	g_object_unref(dcon);


skip_system:


	// both tests ended with error
	if (rses == 1 && rsys == 1)
		return 1;
	// at least one test found failures
	else if (rses == 2 || rsys == 2)
		return 2;
	// at least one test found warnings
	else if (rses == 3 || rsys == 3)
		return 3;
	// cases where rses=1,rsys=0 or rses=0,rsys=1 are ok,
	// because tests on one of the bus daemons finished
	// successfuly
	else
		return 0;
}

/**
	@function Calls method ListNames to get all available connection names
	on the bus and prints them on the program output.
	@param dcon D-Bus connection structure
	@return 0 on success, -1 on error
*/
int df_list_bus_names(const GDBusConnection *dcon)
{
	GError *error = NULL;			// must be set to NULL
	GDBusProxy *proxy;				// proxy for getting bus names
	GVariant *response = NULL;		// response from method ListNames
	GVariantIter *iter;
	char *str;


	// Uses dcon (GDBusConnection *) to create proxy for accessing
	// org.freedesktop.DBus (for calling its method ListNames)
	proxy = g_dbus_proxy_new_sync(dcon,
				G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
				| G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS, NULL,
				"org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus",
				NULL, &error);
	if (proxy == NULL) {
		df_fail("Error: Unable to create proxy for getting bus names.\n");
		df_error("Error in g_dbus_proxy_new_sync()", error);
		return -1;
	}

	// Synchronously invokes method ListNames
	response = g_dbus_proxy_call_sync(proxy, "ListNames", NULL,
					G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (response == NULL) {
		df_fail("Error: Unable to get bus names.\n");
		df_error("Error in g_dbus_proxy_call_sync()", error);
		g_object_unref(proxy);
		return -1;
	}
	g_object_unref(proxy);


	g_variant_get(response, "(as)", &iter);
	while (g_variant_iter_loop(iter, "s", &str)) {
		if (str[0] != ':')
			printf("%s\n", str);
	}
	g_variant_iter_free(iter);
	g_variant_unref(response);
}

/**
	@function Traverses through all objects of bus name target_proc.name
	and is looking for object path target_proc.obj_path
	@param dcon D-Bus connection structure
	@param root_node Starting object path (all nodes from this object path
	will be traversed)
	@return 1 when obj. path target_proc.obj_path is found on bus, 0 otherwise
*/
int df_is_object_on_bus(const GDBusConnection *dcon, const char *root_node)
{
	char *intro_iface = "org.freedesktop.DBus.Introspectable";
	char *intro_method = "Introspect";
	GVariant *response = NULL;
	GDBusProxy *dproxy = NULL;
	GError *error = NULL;
	gchar *introspection_xml = NULL;
	/** Information about nodes in a remote object hierarchy. */
	GDBusNodeInfo *node_data = NULL;
	GDBusNodeInfo *node = NULL;
	char *object = NULL;
	int i = 0;
	int ret = 0;		// return value of this function


	if (strstr(root_node, target_proc.obj_path) != NULL)
		return 1;

	if (!df_is_valid_dbus(target_proc.name, root_node, intro_iface))
		return 0;
	dproxy = g_dbus_proxy_new_sync(dcon,
						G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
						| G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS, NULL,
						target_proc.name, root_node, intro_iface,
						NULL, &error);
	if (dproxy == NULL) {
		df_fail("Error: Unable to create proxy for bus name '%s'.\n",
				target_proc.name);
		df_error("Error in g_dbus_proxy_new_sync()", error);
		return 0;
	}


	response = g_dbus_proxy_call_sync(dproxy, intro_method,
					NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (response == NULL) {
		g_object_unref(dproxy);
		df_fail("Unknown bus name '%s'.\n", target_proc.name);
		df_error("Error in g_dbus_proxy_call_sync()", error);
		return 0;
	}
	g_variant_get(response, "(s)", &introspection_xml);
	g_variant_unref(response);
	if (introspection_xml == NULL) {
		df_fail("Error: Unable to get introspection data from GVariant.\n");
		return 0;
	}

	// Parses introspection_xml and returns a GDBusNodeInfo representing
	// the data.
	node_data = g_dbus_node_info_new_for_xml(introspection_xml, &error);
	g_free(introspection_xml);
	if (node_data == NULL) {
		df_fail("Error: Unable to get introspection data.\n");
		df_error("Error in g_dbus_node_info_new_for_xml()", error);
		g_object_unref(dproxy);
		return 0;
	}

	// go through all nodes
	i = 0;
	node = node_data->nodes[i++];
	while (node != NULL) {
		// create next object path
		object = (char *) calloc(strlen(node->path) + strlen(root_node) + 3,
					sizeof(char));
		if (object == NULL) {
			df_fail("Error: Could not allocate memory for root_node string.\n");
			g_dbus_node_info_unref(node_data);
			g_object_unref(dproxy);
			return 0;
		}
		if (strlen(root_node) == 1)
			sprintf(object, "%s%s", root_node, node->path);
		else
			sprintf(object, "%s/%s", root_node, node->path);
		ret = df_is_object_on_bus(dcon, object);
		if (ret == 1) {
			free(object);
			g_dbus_node_info_unref(node_data);
			g_object_unref(dproxy);
			return 1;
		}
		free(object);
		// move to next node
		node = node_data->nodes[i++];
	}

	// cleanup
	g_dbus_node_info_unref(node_data);
	g_object_unref(dproxy);
	return ret;
}

/**
	@function Traverses through all interfaces and objects of bus
	name target_proc.name and for each interface it calls df_fuzz()
	to fuzz test all its methods.
	@param dcon D-Bus connection structure
	@param root_node Starting object path (all nodes from this object path
	will be traversed)
	@return 0 on success, 1 on error, 2 when testing detected any failures
	or warnings, 3 on warnings
*/
int df_traverse_node(const GDBusConnection *dcon, const char *root_node)
{
	char *intro_iface = "org.freedesktop.DBus.Introspectable";
	char *intro_method = "Introspect";
	GVariant *response = NULL;
	GDBusProxy *dproxy = NULL;
	GError *error = NULL;
	gchar *introspection_xml = NULL;
	/** Information about nodes in a remote object hierarchy. */
	GDBusNodeInfo *node_data = NULL;
	GDBusNodeInfo *node = NULL;
	char *object = NULL;
	int i = 0;
	/** Information about a D-Bus interface. */
	GDBusInterfaceInfo *interface = NULL;
	/** Return values */
	int rd = 0;			// return value from df_fuzz()
	int rt = 0;			// return value from recursive transition
	int ret = 0;		// return value of this function


	if (!df_is_valid_dbus(target_proc.name, root_node, intro_iface))
		return 1;
	dproxy = g_dbus_proxy_new_sync(dcon,
						G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
						| G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS, NULL,
						target_proc.name, root_node, intro_iface,
						NULL, &error);
	if (dproxy == NULL) {
		df_fail("Error: Unable to create proxy for bus name '%s'.\n",
				target_proc.name);
		df_error("Error in g_dbus_proxy_new_sync()", error);
		return 1;
	}


	response = g_dbus_proxy_call_sync(dproxy, intro_method,
					NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (response == NULL) {
		g_object_unref(dproxy);
		df_fail("Unknown bus name '%s'.\n", target_proc.name);
		df_error("Error in g_dbus_proxy_call_sync()", error);
		return 1;
	}
	g_variant_get(response, "(s)", &introspection_xml);
	g_variant_unref(response);
	if (introspection_xml == NULL) {
		df_fail("Error: Unable to get introspection data from GVariant.\n");
		return 1;
	}

	// Parses introspection_xml and returns a GDBusNodeInfo representing
	// the data.
	node_data = g_dbus_node_info_new_for_xml(introspection_xml, &error);
	g_free(introspection_xml);
	if (node_data == NULL) {
		df_fail("Error: Unable to get introspection data.\n");
		df_error("Error in g_dbus_node_info_new_for_xml()", error);
		g_object_unref(dproxy);
		return 1;
	}


	// go through all interfaces
	i = 0;
	interface = node_data->interfaces[i++];
	while (interface != NULL) {
		printf(" Interface: \e[1m%s\e[0m\n", interface->name);
		// start fuzzing on the target_proc.name
		rd = df_fuzz(dcon, target_proc.name, root_node, interface->name);
		if (rd == 1) {
			g_dbus_node_info_unref(node_data);
			g_object_unref(dproxy);
			return 1;
		} else {
			if (ret != 2)
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
		// create next object path
		object = (char *) calloc(strlen(node->path) + strlen(root_node) + 3,
					sizeof(char));
		if (object == NULL) {
			df_fail("Error: Could not allocate memory for root_node string.\n");
			g_dbus_node_info_unref(node_data);
			g_object_unref(dproxy);
			return 1;
		}
		if (strlen(root_node) == 1)
			sprintf(object, "%s%s", root_node, node->path);
		else
			sprintf(object, "%s/%s", root_node, node->path);
		printf("Object: \e[1m%s\e[0m\n", object);
		rt = df_traverse_node(dcon, object);
		if (rt == 1) {
			free(object);
			g_dbus_node_info_unref(node_data);
			g_object_unref(dproxy);
			return 1;
		} else {
			if (ret != 2)
				ret = rt;
		}
		free(object);
		// move to next node
		node = node_data->nodes[i++];
	}

	// cleanup
	g_dbus_node_info_unref(node_data);
	g_object_unref(dproxy);
	return ret;
}

/**
	@function Controls fuzz testing of all methods of specified interface (intf)
	and reports results.
	@param dcon D-Bus connection structure
	@param name D-Bus name
	@param obj D-Bus object path
	@param intf D-Bus interface
	@return 0 on success, 1 on error, 2 when testing detected any failures,
	3 on warnings
*/
int df_fuzz(const GDBusConnection *dcon, const char *name,
			const char *obj, const char *intf)
{
	int method_found = 0;	// If df_test_method is found in an interface,
							// method_found is set to 1, otherwise is 0.
	int void_method;		// If method has out args 1, 0 otherwise.
	GDBusProxy *dproxy;		// D-Bus interface proxy
	int statfd;				// FD for process status file
	GError *error = NULL;	// must be set to NULL
	int rv = 0;				// return value of function


	// Sanity check fuzzing target
	if (strlen(name) == 0 || strlen(obj) == 0 || strlen(intf) == 0) {
		df_fail("Error in target specification.\n");
		return 1;
	}

	// Creates a proxy for accessing intf on the remote object at path obj
	// owned by name at dcon.
	if (!df_is_valid_dbus(name, obj, intf))
		return 1;
	dproxy = g_dbus_proxy_new_sync(dcon,
					G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
					| G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS, NULL,
					name, obj, intf, NULL, &error);
	if (dproxy == NULL) {
		df_fail("Error: Unable to create proxy for bus name '%s'.\n", name);
		df_error("Error in g_dbus_proxy_new_sync() on creating proxy",
				error);
		return 1;
	}

	// Introspection of object through proxy.
	if (df_init_introspection(dproxy, name, intf) == -1) {
		g_object_unref(dproxy);
		df_debug("Error in df_init_introspection() on introspecting object\n");
		return 1;
	}

	// opens process status file
	if ((statfd = df_open_proc_status_file(df_pid)) == -1) {
		df_unref_introspection();
		g_object_unref(dproxy);
		df_debug("Error in df_open_proc_status_file()\n");
		return 1;
	}

	// tells fuzz module to call methods on dproxy, use FD statfd
	// for monitoring tested process and memory limit for process
	if (df_fuzz_init(dproxy, statfd, df_pid, df_mem_limit) == -1) {
		close(statfd);
		df_unref_introspection();
		g_object_unref(dproxy);
		df_debug("Error in df_fuzz_add_proxy()\n");
		return 1;
	}

	GDBusMethodInfo *m;
	GDBusArgInfo *in_arg;
	int ret = 0;
	for (; (m = df_get_method()) != NULL; df_next_method())
	{
		// testing only one method with name df_test_method
		if (df_test_method != NULL) {
			if (strcmp(df_test_method, m->name) != 0) {
				continue;
			}
			method_found = 1;
		}

		// adds method name to the fuzzing module
		if (df_fuzz_add_method(m->name) == -1) {
			close(statfd);
			df_unref_introspection();
			g_object_unref(dproxy);
			df_debug("Error in df_fuzz_add_method()\n");
			return 1;
		}

		for (; (in_arg = df_get_method_arg()) != NULL; df_next_method_arg()) {
			// adds method argument signature to the fuzzing module
			if (df_fuzz_add_method_arg(in_arg->signature) == -1) {
				close(statfd);
				df_unref_introspection();
				g_object_unref(dproxy);
				df_debug("Error in df_fuzz_add_method_arg()\n");
				return 1;
			}
		}

		// methods with no arguments are not tested
		if (df_list_args_count() == 0) {
			df_verbose("  \e[34mSKIP\e[0m method %s - void method\n", m->name);
			df_fuzz_clean_method();
			continue;
		}

		if (df_method_has_out_args())
			void_method = 0;
		else
			void_method = 1;
		

		// tests for method
		ret = df_fuzz_test_method(statfd, df_buf_size, name, obj, intf,
					df_pid, void_method);
		if (ret == -1) {
			// error during testing method
			close(statfd);
			df_fuzz_clean_method();
			df_unref_introspection();
			g_object_unref(dproxy);
			df_debug("Error in df_fuzz_test_method()\n");
			return 1;
		} else if (ret == 1 && df_test_method == NULL) {
			// launch process again after crash
			rv = 2;
			g_object_unref(dproxy);
			if (!df_is_valid_dbus(name, obj, intf))
				return 1;
			dproxy = g_dbus_proxy_new_sync(dcon,
						G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
						| G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
						NULL, name, obj, intf, NULL, &error);
			if (dproxy == NULL) {
				close(statfd);
				df_fuzz_clean_method();
				df_unref_introspection();
				df_fail("Error: Unable to create proxy for bus name '%s'.\n",
						name);
				df_error("Error in g_dbus_proxy_new_sync() on creating"
				     	" proxy", error);
				return 1;
			}

			sleep(5);		// wait for application to launch

			// gets pid of tested process
			df_pid = df_get_pid(dcon);
			if (df_pid < 0) {
				close(statfd);
				df_fuzz_clean_method();
				df_unref_introspection();
				g_object_unref(dproxy);
				df_debug("Error in df_get_pid() on getting pid of process\n");
				return 1;
			}
			printf("\e[36m[RE-CONNECTED TO PID: %d]\e[0m\n", df_pid);

			// opens process status file
			close(statfd);
			if ((statfd = df_open_proc_status_file(df_pid)) == -1) {
				close(statfd);
				df_fuzz_clean_method();
				df_unref_introspection();
				g_object_unref(dproxy);
				df_debug("Error in df_open_proc_status_file()\n");
				return 1;
			}

			// tells fuzz module to call methods on different dproxy and to use
			// new status file of process with PID df_pid
			if (df_fuzz_init(dproxy, statfd, df_pid, df_mem_limit) == -1) {
				close(statfd);
				df_fuzz_clean_method();
				df_unref_introspection();
				g_object_unref(dproxy);
				df_debug("Error in df_fuzz_add_proxy()\n");
				return 1;
			}
		} else if (ret == 2) {
			// method returning void is returning illegal value
			rv = 2;
		} else if (ret == 3) {
			// warnings
			rv = 3;
		}

		df_fuzz_clean_method();		// cleaning up after testing method
	}


	if (method_found == 0 && df_test_method != NULL) {
		df_fail("Error: Method '%s' is not in the interface '%s'.\n",
				df_test_method, intf);
		df_unref_introspection();
		g_object_unref(dproxy);
		close(statfd);
		return rv;
	}
	df_debug(" Cleaning up after fuzzing of interface\n");
	df_unref_introspection();
	g_object_unref(dproxy);
	close(statfd);
	return rv;
}

/**
	@function Checks if name is valid D-Bus name, obj is valid
	D-Bus object path and intf is valid D-Bus interface.
	@param name D-Bus name
	@param obj D-Bus object path
	@param intf D-Bus interface
	@return 1 if name, obj and intf are valid, 0 otherwise
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
	@function Opens process status file.
	@param pid PID - identifier of process
	@return FD of status file on success, -1 on error
*/
int df_open_proc_status_file(const int pid)
{
	char file_path[20];		// "/proc/(max5chars)/status"
	sprintf(file_path, "/proc/%d/status", pid);

	int statfd = open(file_path, O_RDONLY);
	if (statfd == -1) {
		df_fail("Error: Unable to open file '%s'.\n", file_path);
		return -1;
	}
	return statfd;
}

/**
	@function Calls method GetConnectionUnixProcessID on the interface
	org.freedesktop.DBus to get process pid.
	@param dcon D-Bus connection structure
	@return Process PID on success, -1 on error
*/
int df_get_pid(const GDBusConnection *dcon)
{
	GError *error = NULL;			// must be set to NULL
	GDBusProxy *pproxy;				// proxy for getting process PID
	GVariant *variant_pid = NULL;	// response from GetConnectionUnixProcessID
	int pid = -1;

	// Uses dcon (GDBusConnection *) to create proxy for accessing
	// org.freedesktop.DBus (for calling its method GetConnectionUnixProcessID)
	pproxy = g_dbus_proxy_new_sync(dcon,
				G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
				| G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS, NULL,
				"org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus",
				NULL, &error);
	if (pproxy == NULL) {
		df_fail("Error: Unable to create proxy for getting process pid.\n");
		df_error("Error on creating proxy for getting process pid", error);
		return -1;
	}

	// Synchronously invokes method GetConnectionUnixProcessID
	variant_pid = g_dbus_proxy_call_sync(pproxy,
					"GetConnectionUnixProcessID",
					g_variant_new("(s)", target_proc.name),
					G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (variant_pid == NULL) {
		df_fail("Unknown bus name '%s'.\n", target_proc.name);
		df_error("Error in g_dbus_proxy_call_sync()", error);
		g_object_unref(pproxy);
		return -1;
	}
	g_variant_get(variant_pid, "(u)", &pid);
	g_variant_unref(variant_pid);
	g_object_unref(pproxy);

	return pid;
}

/**
	@function Parses program options and stores them into global
	variables:
	* df_buf_size
		Maximum buffer size for generated strings by rand
		module (in Bytes)
	* df_mem_limit
		Memory limit for tested process in kB
	* df_test_method
		Contains method name or NULL. When not NULL, only
		method with this name will be tested
	* target_proc
		Is of type struct fuzzing_target and is used
		to store bus name, object path and interface
	* df_verbose_flag
		Be verbose
	* df_debug_flag	
		Include debug output
	If error occures function ends program.
	@param argc Count of options
	@param argv Pointer on strings containing options of program
*/
void df_parse_parameters(int argc, char **argv)
{
	int c = 0;
	int nflg = 0, oflg = 0, iflg = 0, mflg = 0, bflg = 0, tflg = 0;

	while ((c = getopt(argc, argv, "n:o:i:m:b:t:dvlhV")) != -1) {
		switch (c) {
		case 'n':
			if (nflg != 0) {
				df_fail("%s: no duplicate options -- 'n'\n", argv[0]);
				exit(1);
			}
			nflg++;
			if (strlen(optarg) >= MAXLEN) {
				df_fail("%s: maximum %d characters for option --"
						" 'n'\n", argv[0], MAXLEN - 1);
				exit(1);
			}
			strncpy(target_proc.name, optarg, MAXLEN);
			break;
		case 'o':
			if (oflg != 0) {
				df_fail("%s: no duplicate options -- 'o'\n", argv[0]);
				exit(1);
			}
			oflg++;
			if (strlen(optarg) >= MAXLEN) {
				df_fail("%s: maximum %d characters for option --"
						" 'o'\n", argv[0], MAXLEN - 1);
				exit(1);
			}
			strncpy(target_proc.obj_path, optarg, MAXLEN);
			break;
		case 'i':
			if (iflg != 0) {
				df_fail("%s: no duplicate options -- 'i'\n", argv[0]);
				exit(1);
			}
			iflg++;
			if (strlen(optarg) >= MAXLEN) {
				df_fail("%s: maximum %d characters for option --"
						" 'i'\n", argv[0], MAXLEN - 1);
				exit(1);
			}
			strncpy(target_proc.interface, optarg, MAXLEN);
			break;
		case 'm':
			if (mflg != 0) {
				df_fail("%s: no duplicate options -- 'm'\n", argv[0]);
				exit(1);
			}
			mflg++;
			df_mem_limit = strtol(optarg, NULL, 10);
			if (df_mem_limit <= 0 || errno == ERANGE || errno == EINVAL) {
				df_fail("%s: invalid value for option -- 'm'\n", argv[0]);
				exit(1);
			}
			break;
		case 'b':
			if (bflg != 0) {
				df_fail("%s: no duplicate options -- 'b'\n", argv[0]);
				exit(1);
			}
			bflg++;
			df_buf_size = strtol(optarg, NULL, 10);
			if (df_buf_size < MINLEN || errno == ERANGE || errno == EINVAL) {
				df_fail("%s: invalid value for option -- 'b'\n"
						" -- at least %d B are required\n", argv[0], MINLEN);
				exit(1);
			}
			break;
		case 't':
			if (tflg != 0) {
				df_fail("%s: no duplicate options -- 't'\n", argv[0]);
				exit(1);
			}
			tflg++;
			df_test_method = optarg;
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
		default:	// '?'
			exit(1);
			break;
		}
	}

	if (!nflg && !df_list_names) {
		df_fail("Error: Connection name is required!\n"
				"See -h for help.\n");
		exit(1);
	}

	if (iflg && !oflg) {
		df_fail("Error: Object path is required if interface specified!\n"
				"See -h for help.\n");
		exit(1);
	}
}

/**
	@function Prints help.
	@param name Name of program
*/
void df_print_help(const char *name)
{
	printf("Usage: dfuzzer -n BUS_NAME [OTHER_OPTIONS]\n\n"
	"Tool for fuzz testing processes communicating through D-Bus.\n"
	"The fuzzer traverses through all the methods on the given bus name.\n"
	"By default only failures and warnings are printed."
	" Use -v for verbose mode.\n\n"
	"REQUIRED OPTIONS:\n"
	"-n BUS_NAME\n\n"
	"OTHER OPTIONS:\n"
	"-V\n"
	"   Print dfuzzer version and exit.\n"
	"-h\n"
	"   Print dfuzzer help and exit.\n"
	"-l\n"
	"   List all available connection names on both buses.\n"
	"-v\n"
	"   Enable verbose messages.\n"
	"-d\n"
	"   Enable debug messages. Implies -v. This option should not be normally\n"
	"   used during testing.\n"
	"-o OBJECT_PATH\n"
	"   Optional object path to test. All children objects are traversed.\n"
	"-i INTERFACE\n"
	"   Interface to test. Requires also -o option.\n"
	"-m MEM_LIMIT [in kB]\n"
	"   When tested process exceeds this limit, warning is printed\n"
	"   on the output. Default vSalue for this limit is 3x process intial\n"
	"   memory size. If set memory limit value is less than or\n"
	"   equal to process initial memory size, it will be adjusted\n"
	"   to default value (3x process intial memory size).\n"
	"-b MAX_BUF_SIZE [in B]\n"
	"   Maximum buffer size for generated strings, minimal value for this\n"
	"   option is 256 B. Default maximum size is 50000 B ~= 50 kB (the greater\n"
	"   the limit, the longer the testing).\n"
	"-t METHOD_NAME\n"
	"   When this parameter is provided, only method METHOD_NAME is tested.\n"
	"   All other methods of an interface are skipped.\n\n"
	"Examples:\n\n"
	" Test all methods of GNOME Shell. Be verbose.\n"
	" # %s -v -n org.gnome.Shell\n\n"
	" Test only method of the given bus name, object path and interface.\n"
	" # %s -n org.freedesktop.Avahi -o / -i org.freedesktop.Avahi.Server -t"
	" GetAlternativeServiceName\n\n"
	" Test all systemd D-Bus methods under object"
	" /org/freedesktop/systemd1/unit.\n Be verbose and print on the program"
	" output and also to the file systemd1.log:\n"
	" # %s -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1/unit"
	" 1>&2 | tee ./systemd1.log\n\n",
	name, name, name);
}

/**
	@function Displays an error message.
	@param message Error message which will be printed
	@param error Pointer on GError structure containing error specification
*/
void df_error(const char *message, GError *error)
{
	if (!df_debug_flag) {
		if (error != NULL)
			g_error_free(error);
		return;
	}
	if (error == NULL)
		fprintf(stderr, "%s\n", message);
	else {
		fprintf(stderr, "%s: %s\n", message, error->message);
		g_error_free(error);
	}
}

/**
	@function Prints debug message.
	@param format Format string
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
	@function Prints verbose message.
	@param format Format string
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
	@function Prints error message.
	@param format Format string
*/
void df_fail(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fflush(stderr);
}
