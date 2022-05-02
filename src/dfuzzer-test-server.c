/*
 * D-Bus test server, for testing dfuzzer.
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
 *
 * After executing this test server, execute dfuzzer, for example like this:
 * $ ./dfuzzer -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject \
 * -i org.freedesktop.dfuzzerInterface
 *
 *
 * Introspect by:
 * $ gdbus introspect --session -d org.freedesktop.dfuzzerServer \
 * -o /org/freedesktop/dfuzzerObject --xml
 *
 * Test if org.freedesktop.dfuzzerServer is on SESSION bus:
 * $ gdbus call --session --dest org.freedesktop.DBus -o /org/freedesktop/Dbus \
 * --method org.freedesktop.DBus.ListNames | grep org.freedesktop.dfuzzerServer
 */
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <glib-unix.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"


static GMainLoop *loop;
static GDBusNodeInfo *introspection_data = NULL;


// Introspection data for the service we are exporting.
static const gchar introspection_xml[] =
"<node>"
"       <interface name='org.freedesktop.dfuzzerInterface'>"
"               <method name='df_hello'>"
"                       <arg type='s' name='msg' direction='in'/>"
"                       <arg type='i' name='lol' direction='in'/>"
"                       <arg type='s' name='response' direction='out'/>"
"               </method>"
"               <method name='df_crash'>"
"                       <arg type='o' name='lol' direction='in'/>"
"               </method>"
"               <method name='df_hang'>"
"                       <arg type='t' name='lol' direction='in'/>"
"               </method>"
"               <method name='df_noreply'>"
"                       <arg type='t' name='lol' direction='in'/>"
"               </method>"
"               <method name='df_variant_crash'>"
"                       <arg type='v' name='variant' direction='in'/>"
"               </method>"
"               <method name='df_complex_sig_1'>"
"                       <arg type='i' name='in1' direction='in'/>"
"                       <arg type='u' name='in2' direction='in'/>"
"                       <arg type='s' name='in3' direction='in'/>"
"                       <arg type='a{ss}' name='what' direction='in'/>"
"                       <arg type='a(uiyo)' name='also_what' direction='in'/>"
"                       <arg type='s' name='response' direction='out'/>"
"               </method>"
"               <method name='df_complex_sig_2'>"
"                       <arg type='i' name='in1' direction='in'/>"
"                       <arg type='s' name='in2' direction='in'/>"
"                       <arg type='aaaaaaaaaai' name='in3' direction='in'/>"
"                       <arg type='(y(b(n(q(iua{ov})v)o))x(dh))' name='in4' direction='in'/>"
"                       <arg type='a{i(bov)}' name='in5' direction='in'/>"
"                       <arg type='i' name='response' direction='out'/>"
"               </method>"
"       </interface>"
"</node>";


static void handle_method_call(
                GDBusConnection *connection, const gchar *sender,
                const gchar *object_path, const gchar *interface_name,
                const gchar *method_name, GVariant *parameters,
                GDBusMethodInvocation *invocation, gpointer user_data)
{
        _cleanup_(g_freep) gchar *response = NULL;

        g_printf("->[handle_method_call]\n");

        if (g_strcmp0(method_name, "df_hello") == 0) {
                gchar *msg;
                int n;

                // Deconstructs a GVariant instance parameters into gchar * msg.
                // "(&s)" means msg will point inside parameters structure, so do not
                // free it. If we would use "(s)", it is safe to free msg as data would
                // be only copied.
                g_variant_get(parameters, "(&si)", &msg, &n);

                g_printf("\n@@@\nMsg from Client: [--s-- \'%s\'\n--i-- \'%d\']\n", msg, n);
                response = g_strdup_printf("%s", msg);

                // Finishes handling a D-Bus method call by returning response
                // converted to GVariant. This method will free invocation,
                // you cannot use it afterwards.
                g_dbus_method_invocation_return_value(invocation,
                        g_variant_new("(s)", response));
                g_printf("Sending response to Client: [%s]\n", response);
        } else if (g_strcmp0(method_name, "df_crash") == 0 || g_strcmp0(method_name, "df_variant_crash") == 0)
                abort();
        else if (g_strcmp0(method_name, "df_hang") == 0)
                pause();
        else if (g_strcmp0(method_name, "df_noreply") == 0)
                return;
        else if (g_strcmp0(method_name, "df_complex_sig_1") == 0) {
                gchar *str = NULL;
                unsigned u;
                int i;

                g_variant_get(parameters, "(iu&s@a{ss}@a(uiyo))", &i, &u, &str, NULL, NULL);
                if (strlen(str) <= 0) {
                        g_printf("Got unexpected data for method %s\n", method_name);
                        abort();
                }

                g_printf("%s: string size: %zu\n", method_name, strlen(str));

                response = g_strdup_printf("%s", str);
                g_dbus_method_invocation_return_value(invocation, g_variant_new("(s)", response));
        } else if (g_strcmp0(method_name, "df_complex_sig_2") == 0)
                g_dbus_method_invocation_return_value(invocation, g_variant_new("(i)", 0));
}

// Virtual table for handling properties and method calls for a D-Bus interface.
static const GDBusInterfaceVTable interface_vtable = { .method_call = handle_method_call };

static void bus_acquired(GDBusConnection *connection, const gchar *name, gpointer user_data)
{
        g_printf("->[bus_acquired]\n");

        guint reg_id;

        // Registers callbacks for exported objects at
        // /org/freedesktop/dfuzzerObject with the D-Bus interface that is
        // described in introspection_data->interfaces[0].
        reg_id = g_dbus_connection_register_object(connection,
                                "/org/freedesktop/dfuzzerObject",
                                introspection_data->interfaces[0],
                                &interface_vtable,
                                NULL,   // user_data
                                NULL,   // user_data_free_func
                                NULL);  // GError**
        g_assert(reg_id > 0);
}

static void name_acquired(GDBusConnection *connection, const gchar *name, gpointer user_data)
{
        g_printf("->[name_acquired]\n");
}

static void name_lost(GDBusConnection *connection, const gchar *name, gpointer user_data)
{
        g_printerr("Unable to connect to the bus daemon!\n");
        exit(1);
}

gboolean handle_signal(gpointer userdata)
{
        if (loop)
                g_main_loop_quit(loop);

        return FALSE;
}

int main(int argc, char **argv)
{
        guint name_id;

        // Parses introspection_xml and returns a GDBusNodeInfo representing the data.
        // The introspection XML must contain exactly one top-level <node> element.
        introspection_data = g_dbus_node_info_new_for_xml(introspection_xml, NULL);
        g_assert(introspection_data != NULL);

        /* Handle SIGTERM/SIGINT cleanly, mainly to collect code coverage */
        g_unix_signal_add(SIGTERM, handle_signal, NULL);
        g_unix_signal_add(SIGINT, handle_signal, NULL);

        // Starts acquiring name on the bus (G_BUS_TYPE_SESSION) and calls
        // name_acquired handler and name_lost when the name is acquired
        // respectively lost.
        name_id = g_bus_own_name(G_BUS_TYPE_SYSTEM,
                                "org.freedesktop.dfuzzerServer",
                                G_BUS_NAME_OWNER_FLAGS_NONE,
                                bus_acquired,
                                name_acquired,
                                name_lost,
                                NULL,
                                NULL);

        g_printf("Name id: %d\n", name_id);
        loop = g_main_loop_new(NULL, FALSE);
        g_main_loop_run(loop);

        g_bus_unown_name(name_id);
        g_dbus_node_info_unref(introspection_data);
        g_main_loop_unref(loop);

        return 0;
}
