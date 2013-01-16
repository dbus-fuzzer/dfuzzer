#include <glib.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char **argv)
{
	DBusGConnection *connection;
	GError *error;
	DBusGProxy *proxy;
	char **name_list;
	char **name_list_ptr;

	g_type_init();

	error = NULL;
	connection = dbus_g_bus_get(DBUS_BUS_SESSION, &error);
	if (connection == NULL) {
		g_printerr("Failed to open connection to bus: %s\n", error->message);
		g_error_free(error);
		exit(1);
	}

	// Create a proxy object for the "bus driver" (name "org.freedesktop.DBus").
	// This is a proxy for the message bus itself.
	proxy = dbus_g_proxy_new_for_name(connection,
									"org.freedesktop.DBus",		// name
									"/org/freedesktop/DBus",	// path
									"org.freedesktop.DBus");	// interface

	// Call ListNames method, wait for reply
	error = NULL;
	if (!dbus_g_proxy_call(proxy, "ListNames", &error, G_TYPE_INVALID,
						G_TYPE_STRV, &name_list, G_TYPE_INVALID)) {
		// Just do demonstrate remote exceptions versus regular GError
		if (error->domain == DBUS_GERROR && error->code == DBUS_GERROR_REMOTE_EXCEPTION)
			g_printerr("Caught remote method exception %s: %s",
					dbus_g_error_get_name(error),
					error->message);
		else
			g_printerr("Error: %s\n", error->message);
		g_error_free(error);
		exit(1);
	}

	// Print the results
	g_print("Names on the message bus:\n");
	for (name_list_ptr = name_list; *name_list_ptr; name_list_ptr++) {
		// if unique bus name, we found out pid and service name
		if (*name_list_ptr[0] == ':') {
			g_print("%s", *name_list_ptr);
			unsigned int pid = 0;
			if (!dbus_g_proxy_call(proxy, "GetConnectionUnixProcessID", &error,
						G_TYPE_STRING, *name_list_ptr , G_TYPE_INVALID,
						G_TYPE_UINT, &pid, G_TYPE_INVALID)) {
				g_printerr("Error: %s\n", error->message);
				g_error_free(error);
				exit(1);
			}
			g_print("\t  %d\t", pid);

			// gets the name of service according to pid number
			char fname[25];
			sprintf(fname, "/proc/%d/status", pid);
			FILE *f = fopen(fname, "r"); 
  			if (f == NULL) 
				fprintf(stderr, "Unable to open %s\n", fname);
			else {
				int c;
				int j;
				for (j = 1; j <= 5; j++)	// skip the "Name:" string
					c = fgetc(f);
				while ((c = fgetc(f)) && !feof(f) && c != '\n') {
					if (!isblank(c))
						putchar(c);
				}
				fclose(f);
			}
		}
		else
			g_print("\n%s", *name_list_ptr);
		g_print("\n");
	}

	g_strfreev(name_list);
	g_object_unref(proxy);
	return 0;
}

