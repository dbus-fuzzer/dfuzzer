#include <stdio.h>
#include <stdlib.h>

#include "bus.h"
#include "dfuzzer.h"
#include "log.h"
#include "util.h"

GDBusProxy *df_bus_new_full(GDBusConnection *dcon, const char *name, const char *object,
                       const char *interface, GDBusProxyFlags flags, GError **ret_error)
{
        g_autoptr(GError) error = NULL;
        GDBusProxy *dproxy = NULL;

        dproxy = g_dbus_proxy_new_sync(
                        dcon,
                        flags,
                        NULL,
                        name,
                        object,
                        interface,
                        NULL,
                        &error);
        if (!dproxy) {
                if (ret_error)
                        *ret_error = g_steal_pointer(&error);
                else {
                        df_fail("Error: Unable to create proxy for bus name '%s'.\n", name);
                        df_error("Error in g_dbus_proxy_new_sync() on creating proxy", error);
                }

                return NULL;
        }

        return dproxy;
}

GVariant *df_bus_call_full(GDBusProxy *proxy, const char *method, GVariant *value,
                           GDBusCallFlags flags, GError **ret_error)
{
        g_autoptr(GError) error = NULL;
        GVariant *response = NULL;

        response = g_dbus_proxy_call_sync(
                        proxy,
                        method,
                        value,
                        flags,
                        -1,
                        NULL,
                        &error);
        if (!response) {
                if (ret_error)
                        *ret_error = g_steal_pointer(&error);
                else {
                        df_fail("Error while calling method '%s': %s\n", method, error->message);
                        df_error("Error in g_dbus_proxy_call_sync()", error);
                }

                return NULL;
        }

        return response;
}

