#include <stdio.h>
#include <stdlib.h>

#include "bus.h"
#include "dfuzzer.h"
#include "util.h"

GDBusProxy *df_bus_new_full(GDBusConnection *dcon, const char *name, const char *object,
                       const char *interface, GDBusProxyFlags flags, GError **ret_error)
{
        _cleanup_(g_error_freep) GError *error = NULL;
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
                        *ret_error = TAKE_PTR(error);
                else {
                        df_fail("Error: Unable to create proxy for bus name '%s'.\n", name);
                        df_error("Error in g_dbus_proxy_new_sync() on creating proxy", error);
                }

                return NULL;
        }

        return dproxy;
}

GVariant *df_bus_call_full(GDBusProxy *proxy, const char *method, GVariant *signature,
                           GDBusCallFlags flags, GError **ret_error)
{
        _cleanup_(g_error_freep) GError *error = NULL;
        GVariant *response = NULL;

        response = g_dbus_proxy_call_sync(
                        proxy,
                        method,
                        signature,
                        flags,
                        -1,
                        NULL,
                        &error);
        if (!response) {
                if (ret_error)
                        *ret_error = TAKE_PTR(error);
                else {
                        g_dbus_error_strip_remote_error(error);
                        df_fail("Error while calling method '%s': %s.\n", method, error->message);
                        df_error("Error in g_dbus_proxy_call_sync()", error);
                }

                return NULL;
        }

        return response;
}
