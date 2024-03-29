/** @file fuzz.h */
/*
 * dfuzzer - tool for fuzz testing processes communicating through D-Bus.
 *
 * Copyright(C) 2013, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>
 *                                   Miroslav Vadkerti <mvadkert@redhat.com>
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
#pragma once

/** Minimal buffer size for generated strings */
#define MIN_BUFFER_LENGTH 512
/** Maximum buffer size for generated strings, default is cca 50 kB */
#define MAX_BUFFER_LENGTH 50000
/** Maximum length of strings containing D-Bus object path */
#define MAX_OBJECT_PATH_LENGTH 256
/** Maximum length of D-Bus signature string */
#define MAX_SIGNATURE_LENGTH 255
#define MAX_SIGNATURE_NEST_LEVEL 64
#define MAX_SUPPRESSIONS 256

/* Basic (non-container) types which can appear in a signature
 *
 * https://dbus.freedesktop.org/doc/dbus-specification.html#id-1.3.8
 */
#define SIGNATURE_BASIC_TYPES "ybnqiuxtdsogh"

/** Maximum amount of unimportant exceptions for one method; if reached
  * testing continues with a next method */
#define MAX_EXCEPTIONS 50

typedef struct df_dbus_method {
        char *name;
        char *signature;
        gboolean returns_value;
        gboolean expect_reply;
} df_dbus_method_t;

static inline void df_dbus_method_clear(df_dbus_method_t *p)
{
        free(p->name);
        free(p->signature);
        memset(p, 0, sizeof(*p));
}

typedef struct df_dbus_property {
        char *name;
        char *signature;
        gboolean is_readable;
        gboolean is_writable;
        gboolean expect_reply;
} df_dbus_property_t;

static inline void df_dbus_property_clear(df_dbus_property_t *p)
{
        free(p->name);
        free(p->signature);
        memset(p, 0, sizeof(*p));
}

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(df_dbus_method_t, df_dbus_method_clear)
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(df_dbus_property_t, df_dbus_property_clear)

void df_fuzz_set_buffer_length(const guint64 length);
guint64 df_fuzz_get_buffer_length(void);
void df_fuzz_set_show_command_output(gboolean value);

guint64 df_get_number_of_iterations(const char *signature);
/**
 * @function Saves pointer on D-Bus interface proxy for this module to be
 * able to call methods through this proxy during fuzz testing. Also saves
 * process initial memory size to global var. df_initial_mem from file
 * described by statfd.
 * @param dproxy Pointer on D-Bus interface proxy
 * @param statfd FD of process status file
 * @param pid PID of tested process
 * @param mem_limit Memory limit in kB - if tested process exceeds this limit
 * it will be noted into log file
 * @return 0 on success, -1 on error
 */
int df_fuzz_init(GDBusProxy *dproxy);

/**
 * @function Initializes the global variable df_list (struct df_sig_list)
 * including allocationg memory for method name inside df_list.
 * @param name Name of method which will be tested
 * @return 0 on success, -1 on error
 */
int df_fuzz_add_method(const char *name);

/**
 * @function Adds item (struct df_signature) at the end of the linked list
 * in the global variable df_list (struct df_sig_list). This includes
 * allocating memory for item and for signature string.
 * @param signature D-Bus signature of the argument
 * @return 0 on success, -1 on error
 */
int df_fuzz_add_method_arg(const char *signature);

/**
 * @function Function is testing a method in a cycle, each cycle generates
 * data for function arguments, calls method and waits for result.
 * @param statfd FD of process status file
 * @param buf_size Maximum buffer size for generated strings
 * by rand module (in Bytes)
 * @param name D-Bus name
 * @param obj D-Bus object path
 * @param intf D-Bus interface
 * @param pid PID of tested process
 * @param void_method If method has out args 1, 0 otherwise
 * @param execute_cmd Command/Script to execute after each method call.
 * @return 0 on success, -1 on error, 1 on tested process crash, 2 on void
 * function returning non-void value, 3 on warnings and 4 when executed
 * command finished unsuccessfuly
 */
int df_fuzz_test_method(
                const struct df_dbus_method *method, const char *name,
                const char *obj, const char *intf, const int pid, const char *execute_cmd,
                guint64 iterations);

int df_fuzz_test_property(GDBusConnection *dcon, const struct df_dbus_property *property,
                          const char *bus, const char *object, const char *interface,
                          const int pid, guint64 iterations);
