/** @file introspection.c */
/*
 * dfuzzer - tool for fuzz testing processes communicating through D-Bus.
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
 */
#include <assert.h>
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>

#include "introspection.h"
#include "bus.h"
#include "dfuzzer.h"
#include "util.h"


GDBusNodeInfo *df_get_interface_info(GDBusProxy *dproxy, const char *interface, GDBusInterfaceInfo **ret_iinfo)
{
        _cleanup_(g_error_freep) GError *error = NULL;
        _cleanup_(g_freep) gchar *introspection_xml = NULL;
        _cleanup_(g_variant_unrefp) GVariant *response = NULL;
        GDBusNodeInfo *introspection_data = NULL;
        GDBusInterfaceInfo *interface_info = NULL;

        assert(dproxy);
        assert(interface);
        assert(ret_iinfo);

        // Synchronously invokes the org.freedesktop.DBus.Introspectable.Introspect
        // method on dproxy to get introspection data in XML format
        response = df_bus_call(dproxy,
                               "org.freedesktop.DBus.Introspectable.Introspect",
                               NULL,
                               G_DBUS_CALL_FLAGS_NONE);
        if (!response)
                return NULL;;

        g_variant_get(response, "(s)", &introspection_xml);
        if (!introspection_xml) {
                df_fail("Error: Unable to get introspection data from GVariant.\n");
                return NULL;
        }

        // Parses introspection_xml and returns a GDBusNodeInfo representing
        // the data.
        introspection_data = g_dbus_node_info_new_for_xml(introspection_xml, &error);
        if (!introspection_data) {
                df_fail("Error: Unable to get introspection data.\n");
                df_error("Error in g_dbus_node_info_new_for_xml()", error);
                return NULL;
        }

        // Looks up information about an interface (methods, their arguments, etc).
        interface_info = g_dbus_node_info_lookup_interface(introspection_data, interface);
        if (!interface_info) {
                df_fail("Error: Unable to get interface '%s' data.\n", interface);
                df_debug("Error in g_dbus_node_info_lookup_interface()\n");
                return NULL;
        }

        *ret_iinfo = interface_info;

        return introspection_data;
}

char *df_method_get_full_signature(const GDBusMethodInfo *method)
{
        char *r, *e;
        size_t len = 0;

        assert(method);

        for (GDBusArgInfo **arg = method->in_args; *arg; arg++)
                len += strlen((*arg)->signature);

        /* '(' + signature + ')' + '\0' */
        r = malloc(sizeof(*r) * (len + 3));
        if (!r)
                return NULL;

        e = stpcpy(r, "(");
        for (GDBusArgInfo **arg = method->in_args; *arg; arg++)
                e = stpcpy(e, (*arg)->signature);

        e = stpcpy(e, ")");
        *e = 0;

        return r;
}

gboolean df_method_returns_reply(const GDBusMethodInfo *method)
{
        const gchar *annotation_str;

        assert(method);

        annotation_str = g_dbus_annotation_info_lookup(method->annotations,
                                                       "org.freedesktop.DBus.Method.NoReply");
        if (!isempty(annotation_str) && g_strcmp0(annotation_str, "true") == 0)
                return FALSE;

        return TRUE;
}
