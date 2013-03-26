/** @file dfuzzer.c *//*

	dfuzzer - tool for testing applications communicating through D-Bus.
	Copyright (C) 2013  Matus Marhefka

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
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dfuzzer.h"
#include "introspection.h"
#include "fuzz.h"


struct fuzzing_target target_app;


int main(int argc, char **argv)
{
	df_parse_parameters(argc, argv);

	GError *error = NULL;		// must be set to NULL
	GDBusConnection *dcon;		// D-Bus connection structure
	GDBusProxy *dproxy;			// D-Bus interface proxy
	int pid = -1;					// pid of tested process
	GVariant *variant_pid = NULL;	// response from GetConnectionUnixProcessID

	// Initializes the type system.
	g_type_init();

	// Synchronously connects to the message bus.
	if ( (dcon = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error)) == NULL ) {
		df_error("Error in g_bus_get_sync() on connecting to the message bus",
				error);
	}

	// Creates a proxy for accessing target_app.interface
	// on the remote object at target_app.obj_path owned by target_app.name
	// at dcon.
	dproxy = g_dbus_proxy_new_sync(dcon, G_DBUS_PROXY_FLAGS_NONE, NULL,
	target_app.name, target_app.obj_path, target_app.interface, NULL, &error);

	if (dproxy == NULL) {
		g_object_unref(dcon);
		df_error("Error in g_dbus_proxy_new_sync() on creating proxy", error);
	}

	/*
	// TODO: get pid of tested app
	// Synchronously invokes method GetConnectionUnixProcessID
	variant_pid = g_dbus_proxy_call_sync(dproxy,
		"org.freedesktop.DBus.GetConnectionUnixProcessID",
		NULL, G_DBUS_CALL_FLAGS_NONE,
		-1, NULL, &error);
	if (variant_pid == NULL) {
		g_object_unref(dproxy);
		g_object_unref(dcon);
		df_error("Error in g_dbus_proxy_call_sync() on calling"
				" 'GetConnectionUnixProcessID' method", error);
	}
	g_variant_get(variant_pid, "i", &pid);
	if (pid == -1) {
		g_object_unref(dproxy);
		g_object_unref(dcon);
		g_variant_unref(variant_pid);
		df_error("Error in g_variant_get() on getting pid from GVariant", error);
	}
	g_variant_unref(variant_pid);
	fprintf(stderr, "pid = [%d]\n", pid);
	*/

	// Introspection of object through proxy.
	if (df_init_introspection(dproxy, target_app.interface) == -1) {
		g_object_unref(dproxy);
		g_object_unref(dcon);
		df_error("Error in df_init_introspection() on introspecting object",
				error);
	}


	GDBusMethodInfo *m;
	GDBusArgInfo *in_arg;

	// tells fuzz module to call methods on dproxy
	if (df_fuzz_add_proxy(dproxy) == -1) {
		df_unref_introspection();
		g_object_unref(dproxy);
		g_object_unref(dcon);
		df_error("Error in df_fuzz_add_proxy()", error);
	}


	for (; (m = df_get_method()) != NULL; df_next_method()) {
		// adds method name to the fuzzing module
		if (df_fuzz_add_method(m->name) == -1) {
			df_unref_introspection();
			g_object_unref(dproxy);
			g_object_unref(dcon);
			df_error("Error in df_fuzz_add_method()", error);
		}

		for (; (in_arg = df_get_method_arg()) != NULL; df_next_method_arg()) {
			// adds method argument signature to the fuzzing module
			if (df_fuzz_add_method_arg(in_arg->signature) == -1) {
				df_unref_introspection();
				g_object_unref(dproxy);
				g_object_unref(dcon);
				df_error("Error in df_fuzz_add_method_arg()", error);
			}
		}
		if (df_fuzz_test_method() == -1) {	// tests for method
			df_unref_introspection();
			g_object_unref(dproxy);
			g_object_unref(dcon);
			df_error("Error in df_fuzz_test_method()", error);
		}

		df_fuzz_clean_method();		// cleaning up after fuzzing of method
	}


	df_unref_introspection();
	g_object_unref(dproxy);
	g_object_unref(dcon);
	return 0;
}

/** @function Displays an error message and exits with error code 1.
	@param message Error message which will be printed before exiting program
	@param error Pointer on GError structure containing error specification
*/
void df_error(char *message, GError *error)
{
	if (error == NULL)
		fprintf(stderr, "%s\n", message);
	else {
		fprintf(stderr, "%s: %s\n", message, error->message);
		g_error_free(error);
	}

	exit(1);
}

/** @function Parses program options and stores them into struct fuzzing_target.
	@param argc Count of options
	@param argv Pointer on strings containing options of program
*/
void df_parse_parameters(int argc, char **argv)
{
	int c = 0;
	int nflg = 0, oflg = 0, iflg = 0;

	while ( (c = getopt(argc, argv, "n:o:i:vh")) != -1 ) {
		switch (c) {
			case 'n':
				if (nflg != 0) {
					fprintf(stderr, "%s: no duplicate options 'n'\n", argv[0]);
					df_print_help(argv[0]);
					exit(1);
				}
				nflg++;
				strncpy(target_app.name, optarg, MAXLEN-2);
				break;
			case 'o':
				if (oflg != 0) {
					fprintf(stderr, "%s: no duplicate options 'o'\n", argv[0]);
					df_print_help(argv[0]);
					exit(1);
				}
				oflg++;
				strncpy(target_app.obj_path, optarg, MAXLEN-2);
				break;
			case 'i':
				if (iflg != 0) {
					fprintf(stderr, "%s: no duplicate options 'i'\n", argv[0]);
					df_print_help(argv[0]);
					exit(1);
				}
				iflg++;
				strncpy(target_app.interface, optarg, MAXLEN-2);
				break;
			case 'h':
				df_print_help(argv[0]);
				exit(0);
				break;
			default:	// '?'
				df_print_help(argv[0]);
				exit(1);
				break;
		}
	}

	if (!nflg || !oflg || !iflg) {
		fprintf(stderr, "%s: parameters 'n', 'o' and 'i' must be set\n",
				argv[0]);
		df_print_help(argv[0]);
		exit(1);
	}
}

/** @function Prints help.
	@param name Name of program
*/
void df_print_help(char *name)
{
	printf("%s: D-Bus fuzzer\n\n"
			"REQUIRED OPTIONS:\n\t-n name\n"
			"\t-o object path\n"
			"\t-i interface\n\n"
			"Example:\n%s -n org.gnome.Shell -o /org/gnome/Shell"
			" -i org.gnome.Shell\n", name, name);
}
