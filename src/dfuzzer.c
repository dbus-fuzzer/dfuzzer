/** @file dfuzzer.c */
/*

	dfuzzer - tool for fuzz testing processes communicating through D-Bus.
	Copyright(C) 2013, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>,
	Miroslav Vadkerti <mvadkert@redhat.com>

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
struct fuzzing_target target_proc = { "", "", "" };
/** Debug flag */
int df_verbose_flag = 0;
/** Verbose flag */
int df_debug_flag = 0;
/** Memory limit for tested process in kB */
long mem_limit = 0;
/** Maximum buffer size for generated strings by rand module (in Bytes) */
long buf_size = 0;
/** Contains method name or NULL. When not NULL, only method with this name
	will be tested*/
char *test_method = NULL;
/** Tested process PID */
int pid = -1;


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
	int rses;					// return value from session bus testing
	int rsys;					// return value from system bus testing

	df_parse_parameters(argc, argv);

	// Initializes the type system.
	g_type_init();


	// Synchronously connects to the session bus daemon.
	printf("\e[36m[SESSION BUS]\e[0m\n", target_proc.name);
	if ((dcon = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error)) == NULL) {
		df_fail("Error: Unable to connect to the session bus.\n");
		df_error("Error in g_bus_get_sync() on connecting to the session bus",
				error);
		return 1;
	}
	// gets pid of tested process
	pid = df_get_pid(dcon);
	if (pid > 0) {
		df_verbose("\e[36m[CONNECTED TO PID:%d]\e[0m\n", pid);
		if (strlen(target_proc.interface) != 0) {
			df_verbose("Object: \e[1m%s\e[0m\n", target_proc.obj_path);
			df_verbose(" Interface: \e[1m%s\e[0m\n", target_proc.interface);
			rses = df_fuzz(dcon, target_proc.name, target_proc.obj_path,
						target_proc.interface);
		} else if (strlen(target_proc.obj_path) != 0) {
			df_verbose("Object: \e[1m%s\e[0m\n", target_proc.obj_path);
			rses = df_traverse_node(dcon, target_proc.obj_path);
		} else {
			df_verbose("Object: \e[1m/\e[0m\n");
			rses = df_traverse_node(dcon, root_node);
		}
		g_object_unref(dcon);
	} else
		rses = 1;



	// Synchronously connects to the system bus daemon.
	printf("\e[36m[SYSTEM  BUS]\e[0m\n", target_proc.name);
	if ((dcon = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error)) == NULL) {
		df_fail("Error: Unable to connect to the system bus.\n");
		df_error("Error in g_bus_get_sync() on connecting to the system bus",
				error);
		return 1;
	}
	// gets pid of tested process
	pid = df_get_pid(dcon);
	if (pid > 0) {
		df_verbose("\e[36m[CONNECTED TO PID:%d]\e[0m\n", pid);
		if (strlen(target_proc.interface) != 0) {
			df_verbose("Object: \e[1m%s\e[0m\n", target_proc.obj_path);
			df_verbose(" Interface: \e[1m%s\e[0m\n", target_proc.interface);
			rsys = df_fuzz(dcon, target_proc.name, target_proc.obj_path,
						target_proc.interface);
		} else if (strlen(target_proc.obj_path) != 0) {
			df_verbose("Object: \e[1m%s\e[0m\n", target_proc.obj_path);
			rsys = df_traverse_node(dcon, target_proc.obj_path);
		} else {
			df_verbose("Object: \e[1m/\e[0m\n");
			rsys = df_traverse_node(dcon, root_node);
		}
		g_object_unref(dcon);
	} else
		rsys = 1;


	if (rses == 1 && rsys == 1)			// error
		return 1;
	else if (rses == 2 || rsys == 2)	// testing found failures
		return 2;
	else
		return 0;
}

/**
	@function Traverses through all interfaces and objects of bus
	name target_proc.name and for each interface it calls df_fuzz()
	to fuzz test all its methods.
	@param dcon D-Bus connection structure
	@param root_node Starting object path (all nodes from this object path
	will be traversed)
	@return 0 on success, 1 on error, 2 when testing detected any failures
*/
int df_traverse_node(GDBusConnection * dcon, const char *root_node)
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
	dproxy = g_dbus_proxy_new_sync(dcon, G_DBUS_PROXY_FLAGS_NONE, NULL,
						target_proc.name, root_node, intro_iface,
						NULL, &error);
	if (dproxy == NULL) {
		df_fail("Error: Unable to create proxy for bus name '%s'.\n",
				target_proc.name);
		df_error("Error in g_dbus_proxy_new_sync() on creating proxy",
				 error);
		return 1;
	}


	response = g_dbus_proxy_call_sync(dproxy, intro_method,
						NULL, G_DBUS_CALL_FLAGS_NONE, -1,
						NULL, &error);
	if (response == NULL) {
		g_object_unref(dproxy);
		df_fail("Error: Unknown bus name '%s'.\n", target_proc.name);
		return 1;
	}
	g_variant_get(response, "(s)", &introspection_xml);
	g_variant_unref(response);
	if (introspection_xml == NULL) {
		df_fail("Error: Unable to get introspection data from GVariant.\n");
		return -1;
	}

	// Parses introspection_xml and returns a GDBusNodeInfo representing
	// the data.
	node_data = g_dbus_node_info_new_for_xml(introspection_xml, &error);
	g_free(introspection_xml);
	if (node_data == NULL) {
		df_fail("Error: Unable to get introspection data.\n");
		df_error("Call of g_dbus_node_info_new_for_xml() returned NULL"
			" pointer", error);
		g_object_unref(dproxy);
		return 1;
	}

	// go through all interfaces
	i = 0;
	interface = node_data->interfaces[i++];
	while (interface != NULL) {
		df_verbose(" Interface: \e[1m%s\e[0m\n", interface->name);
		// start fuzzing on the target_proc.name
		rd = df_fuzz(dcon, target_proc.name, root_node, interface->name);
		if (rd == 1) {
			g_dbus_node_info_unref(node_data);
			g_object_unref(dproxy);
			return 1;
		}
		if (rd == 2)
			ret = rd;
		interface = node_data->interfaces[i++];
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
			return 1;
		}
		if (strlen(root_node) == 1)
			sprintf(object, "%s%s", root_node, node->path);
		else
			sprintf(object, "%s/%s", root_node, node->path);
		df_verbose("Object: \e[1m%s\e[0m\n", object);
		rt = df_traverse_node(dcon, object);
		if (rt == 2)
			ret = rt;
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
	@return 0 on success, 1 on error, 2 when testing detected any failures
*/
int df_fuzz(GDBusConnection * dcon, const char *name,
			const char *obj, const char *intf)
{
	int method_found = 0;	// If test_method is found in an interface,
							// method_found is set to 1, otherwise is 0.
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
	dproxy = g_dbus_proxy_new_sync(dcon, G_DBUS_PROXY_FLAGS_NONE, NULL,
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
		df_error("Error in df_init_introspection() on introspecting object",
				NULL);
		return 1;
	}

	// opens process status file
	if ((statfd = df_open_proc_status_file(pid)) == -1) {
		df_unref_introspection();
		g_object_unref(dproxy);
		df_error("Error in df_open_proc_status_file()", NULL);
		return 1;
	}

	// tells fuzz module to call methods on dproxy, use FD statfd
	// for monitoring tested process and memory limit for process
	if (df_fuzz_init(dproxy, statfd, pid, mem_limit) == -1) {
		close(statfd);
		df_unref_introspection();
		g_object_unref(dproxy);
		df_error("Error in df_fuzz_add_proxy()", NULL);
		return 1;
	}

	GDBusMethodInfo *m;
	GDBusArgInfo *in_arg;
	int ret = 0;
	for (; (m = df_get_method()) != NULL; df_next_method())
	{
		// testing only one method with name test_method
		if (test_method != NULL) {
			if (strcmp(test_method, m->name) != 0) {
				continue;
			}
			method_found = 1;
		}

		// adds method name to the fuzzing module
		if (df_fuzz_add_method(m->name) == -1) {
			close(statfd);
			df_unref_introspection();
			g_object_unref(dproxy);
			df_error("Error in df_fuzz_add_method()", NULL);
			return 1;
		}

		for (; (in_arg = df_get_method_arg()) != NULL; df_next_method_arg()) {
			// adds method argument signature to the fuzzing module
			if (df_fuzz_add_method_arg(in_arg->signature) == -1) {
				close(statfd);
				df_unref_introspection();
				g_object_unref(dproxy);
				df_error("Error in df_fuzz_add_method_arg()", NULL);
				return 1;
			}
		}

		// methods with no arguments are not tested
		if (df_list_args_count() == 0)
			continue;

retest:
		// tests for method
		ret = df_fuzz_test_method(statfd, buf_size, name, obj, intf,
								pid, method_found);
		if (ret == -1) {			// error during testing method
			close(statfd);
			df_fuzz_clean_method();
			df_unref_introspection();
			g_object_unref(dproxy);
			df_error("Error in df_fuzz_test_method()", NULL);
			return 1;
		} else if (ret == 1) {		// launch process again after crash
			rv = 2;
			g_object_unref(dproxy);
			if (!df_is_valid_dbus(name, obj, intf))
				return 1;
			dproxy = g_dbus_proxy_new_sync(dcon, G_DBUS_PROXY_FLAGS_NONE,
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
			pid = df_get_pid(dcon);
			if (pid < 0) {
				close(statfd);
				df_fuzz_clean_method();
				df_unref_introspection();
				g_object_unref(dproxy);
				df_error("Error in df_get_pid() on getting pid of process",
						NULL);
				return 1;
			}
			df_verbose("\e[36m[RE-CONNECTED TO PID:%d]\e[0m\n", pid);

			// opens process status file
			close(statfd);
			if ((statfd = df_open_proc_status_file(pid)) == -1) {
				close(statfd);
				df_fuzz_clean_method();
				df_unref_introspection();
				g_object_unref(dproxy);
				df_error("Error in df_open_proc_status_file()", NULL);
				return 1;
			}

			// tells fuzz module to call methods on different dproxy and to use
			// new status file of process with PID pid
			if (df_fuzz_init(dproxy, statfd, pid, mem_limit) == -1) {
				close(statfd);
				df_fuzz_clean_method();
				df_unref_introspection();
				g_object_unref(dproxy);
				df_error("Error in df_fuzz_add_proxy()", NULL);
				return 1;
			}
		}

		// when testing only one specific method (-t option), do not clean
		if (test_method != NULL)
			goto retest;

		df_fuzz_clean_method();		// cleaning up after testing method
	}


	if (method_found == 0 && test_method != NULL) {
		df_fail("Method '%s' was not found in the interface '%s'.\n",
			test_method, target_proc.interface);
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
int df_open_proc_status_file(int pid)
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
int df_get_pid(GDBusConnection * dcon)
{
	GError *error = NULL;			// must be set to NULL
	GDBusProxy *pproxy;				// proxy for getting process PID
	GVariant *variant_pid = NULL;	// response from GetConnectionUnixProcessID
	int pid = -1;

	// Uses dcon (GDBusConnection *) to create proxy for accessing
	// org.freedesktop.DBus (for calling its method GetConnectionUnixProcessID)
	pproxy = g_dbus_proxy_new_sync(dcon, G_DBUS_PROXY_FLAGS_NONE, NULL,
							"org.freedesktop.DBus",
							"/org/freedesktop/DBus",
							"org.freedesktop.DBus", NULL, &error);
	if (pproxy == NULL) {
		df_fail("Error: Unable to create proxy for getting process pid.\n");
		df_error("Error on creating proxy for getting process pid", error);
		return -1;
	}

	// Synchronously invokes method GetConnectionUnixProcessID
	variant_pid = g_dbus_proxy_call_sync(pproxy,
										"GetConnectionUnixProcessID",
										g_variant_new("(s)",
										target_proc.name),
										G_DBUS_CALL_FLAGS_NONE, -1, NULL,
										NULL);
	if (variant_pid == NULL) {
		df_fail("Error: Unknown bus name '%s'.\n", target_proc.name);
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
	* buf_size
		Maximum buffer size for generated strings by rand
		module (in Bytes)
	* mem_limit
		Memory limit for tested process in kB
	* test_method
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

	while ((c = getopt(argc, argv, "n:o:i:m:b:t:dvhV")) != -1) {
		switch (c) {
		case 'd':
			df_debug_flag = 1;
			break;
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
			mem_limit = strtol(optarg, NULL, 10);
			if (mem_limit <= 0 || errno == ERANGE || errno == EINVAL) {
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
			buf_size = strtol(optarg, NULL, 10);
			if (buf_size < MINLEN || errno == ERANGE || errno == EINVAL) {
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
			test_method = optarg;
			break;
		case 'v':
			df_verbose_flag = 1;
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

	if (!nflg) {
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
void df_print_help(char *name)
{
	printf("Usage: dfuzzer -n BUS_NAME [OTHER_OPTIONS]\n\n"
	"Tool for fuzz testing processes communicating through D-Bus.\n"
	"The fuzzer traverses through all the methods on the given bus name.\n"
	"By default only failures are printed. Use -v for verbose mode.\n\n"
	"REQUIRED OPTIONS:\n"
	"-n BUS_NAME\n\n"
	"OTHER OPTIONS:\n"
	"-d\n"
	"   Enable debug messages. Implies -v.\n"
	"-h\n"
	"   Print dfuzzer help and exit.\n"
	"-v\n"
	"   Enable verbose messages.\n"
	"-V\n"
	"   Print dfuzzer version and exit.\n"
	"-o OBJECT_PATH\n"
	"   Optional object path to test. All children objects are traversed.\n"
	"-i INTERFACE\n"
	"   Interface to test. Requires also -o option.\n"
	"-b MAX_BUF_SIZE [in B]\n"
	"   Maximum buffer size for generated strings, minimum is 256 B.\n"
	"   Default maximum size is 50000 B ~= 50 kB (the greater the limit,\n"
	"   the longer the testing).\n"
	"-m MEM_LIMIT [in kB]\n"
	"   When tested process exceeds this limit it will be noted into\n"
	"   log file. Default value for this limit is 3x process intial\n"
	"   memory size. If set memory limit value is less than or\n"
	"   equal to process initial memory size, it will be adjusted\n"
	"   to default value (3x process intial memory size).\n"
	"-t METHOD_NAME\n"
	"   When this parameter is provided, only method METHOD_NAME is tested.\n"
	"   All other methods of an interface are skipped.\n\n"
	"Examples:\n\n"
	" Test all methods of GNOME Shell. Be verbose.\n"
	" # %s -n org.gnome.Shell\n\n"
	" Test only method of the given bus name, object path and interface.\n"
	" # %s -n org.freedesktop.Avahi -o / -i org.freedesktop.Avahi.Server -t"
	"GetAlternativeServiceName\n\n"
	" Test all systemd D-Bus methods under object"
	"/org/freedesktop/systemd1/unit.\n"
	" Be verbose.\n"
	" # %s -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1/unit\n\n",
	name, name, name);
}

/**
	@function Displays an error message.
	@param message Error message which will be printed
	@param error Pointer on GError structure containing error specification
*/
void df_error(char *message, GError * error)
{
	if (!df_debug_flag)
		return;
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
