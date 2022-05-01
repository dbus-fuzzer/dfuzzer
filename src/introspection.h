/** @file introspection.h */
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
#ifndef INTROSPECTION_H
#define INTROSPECTION_H

/**
 * @function Gets introspection of object pointed by dproxy (in XML format),
 * then parses XML data and fills GDBusNodeInfo representing the data.
 * At the end looks up information about an interface and initializes module
 * global pointers on first method and its first argument.
 * @param dproxy Pointer on D-Bus interface proxy
 * @param interface D-Bus interface
 * @return 0 on success, -1 on error
 */
int df_init_introspection(GDBusProxy *dproxy, const char *interface);

/**
 * @return Pointer on GDBusMethodInfo which contains information about method
 * (do not free it).
 */
GDBusMethodInfo *df_get_method(void);

/**
 * @function Function is used as "iterator" for interface methods.
 */
void df_next_method(void);

gboolean df_method_has_out_args(const GDBusMethodInfo *method);
char *df_method_get_full_signature(const GDBusMethodInfo *method);

/**
 * @function Call when done with this module functions (only after
 * df_init_introspection() function call). It frees memory used
 * by introspection_data (GDBusNodeInfo *) which is used to look up
 * information about the interface (methods, their arguments, etc.).
 */
void df_unref_introspection(void);

#endif
