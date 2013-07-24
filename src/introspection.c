/** @file introspection.c */
/*

	dfuzzer - tool for fuzz testing processes communicating through D-Bus.
	Copyright(C) 2013, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>

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

#include "introspection.h"


/** Information about nodes in a remote object hierarchy. */
static GDBusNodeInfo *df_introspection_data;
/** Information about a D-Bus interface. */
static GDBusInterfaceInfo *df_interface_data;
/** Pointer on methods, each contains information about a method
	on a D-Bus interface. */
static GDBusMethodInfo **df_methods;
/** Pointer on arguments, each contains information about an argument
	for a method or a signal. */
static GDBusArgInfo **df_in_args;


/**
	@function Gets introspection of object pointed by dproxy (in XML format),
	then parses XML data and fills GDBusNodeInfo representing the data.
	At the end looks up information about an interface and initializes module
	global pointers on first method and its first argument.
	This function must be called before using any functions from this module.
	@param dproxy Pointer on D-Bus interface proxy
	@param interface Name of process interface
	@return 0 on success, -1 on error
*/
int df_init_introspection(GDBusProxy *dproxy, char *interface)
{
	if (dproxy == NULL || interface == NULL) {
		fprintf(stderr, "Passing NULL argument to function\n");
		return -1;
	}

	GError *error = NULL;
	GVariant *response = NULL;
	gchar *introspection_xml = NULL;

	// Synchronously invokes the org.freedesktop.DBus.Introspectable.Introspect
	// method on dproxy to get introspection data in XML format
	response = g_dbus_proxy_call_sync(dproxy,
		"org.freedesktop.DBus.Introspectable.Introspect",
		NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (response == NULL) {
		fprintf(stderr, "Call of g_dbus_proxy_call_sync() returned NULL"
						" pointer: %s\n", error->message);
		g_error_free(error);
		return -1;
	}

	g_variant_get(response, "(s)", &introspection_xml);


	// Parses introspection_xml and returns a GDBusNodeInfo representing
	// the data.
	df_introspection_data = g_dbus_node_info_new_for_xml(introspection_xml,
														&error);
	if (df_introspection_data == NULL) {
		fprintf(stderr, "Call of g_dbus_node_info_new_for_xml() returned NULL"
						" pointer: %s\n", error->message);
		g_error_free(error);
		return -1;
	}

	// Looks up information about an interface (methods, their arguments, etc).
	df_interface_data = g_dbus_node_info_lookup_interface(df_introspection_data,
														interface);
	if (df_interface_data == NULL) {
		fprintf(stderr, "Call of g_dbus_node_info_lookup_interface() returned"
						" NULL pointer\n");
		return -1;
	}

	// *df_methods is a pointer on the GDBusMethodInfo structure (first method)
	// of interface.
	df_methods = df_interface_data->methods;
	if (*df_methods == NULL) {
		fprintf(stderr, "Interface '%s' has no methods to test\n", interface);
		return -1;
	}

	// sets pointer on args of current method
	df_in_args = (*df_methods)->in_args;

	g_variant_unref(response);
	g_free(introspection_xml);
	return 0;
}

/**
	@return Pointer on GDBusMethodInfo which contains information about method
	(do not free it).
*/
GDBusMethodInfo * df_get_method(void)
{
	return *df_methods;
}

/**
	@function Function is used as "iterator" for interface methods.
*/
void df_next_method(void)
{
	df_methods++;
	if (*df_methods != NULL)
		// sets pointer on args of current method
		df_in_args = (*df_methods)->in_args;
}

/**
	@return Pointer on GDBusArgInfo which contains information about argument
	of current (df_get_method()) method (do not free it).
*/
GDBusArgInfo * df_get_method_arg(void)
{
	return *df_in_args;
}

/**
	@function Function is used as "iterator" for interface current
	(df_get_method()) method arguments.
*/
void df_next_method_arg(void)
{
	df_in_args++;
}

/**
	@function Call when done with this module functions (only after
	df_init_introspection() function call). It frees memory used
	by df_introspection_data (GDBusNodeInfo *) which is used to look up
	information about the interface (methods, their arguments, etc.).
*/
void df_unref_introspection(void)
{
	g_dbus_node_info_unref(df_introspection_data);
}
