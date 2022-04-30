#pragma once

#include <gio/gio.h>

GDBusProxy *df_bus_new_full(GDBusConnection *dcon, const char *name, const char *object,
                       const char *interface, GDBusProxyFlags flags, GError **ret_error);
#define df_bus_new(d,n,o,i,f) df_bus_new_full(d, n, o, i, f, NULL)

GVariant *df_bus_call_full(GDBusProxy *proxy, const char *method, GVariant *signature,
                           GDBusCallFlags flags, GError **ret_error);
#define df_bus_call(p,m,s,f) df_bus_call_full(p, m, s, f, NULL)
