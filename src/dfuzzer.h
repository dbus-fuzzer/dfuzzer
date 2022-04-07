/** @file dfuzzer.h */
/*
 * dfuzzer - tool for fuzz testing processes communicating through D-Bus.
 *
 * Copyright(C) 2013,2014,2015, Red Hat, Inc.
 *     Matus Marhefka <mmarhefk@redhat.com>
 *     Miroslav Vadkerti <mvadkert@redhat.com>
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
#ifndef DFUZZER_H
#define DFUZZER_H

#include <unistd.h>

/** Version of dfuzzer */
#define DF_VERSION "dfuzzer 1.4\n" \
	"Copyright(C) 2013,2014,2015, Red Hat, Inc.\n" \
	"Author: Matus Marhefka <mmarhefk@redhat.com>\n" \
	"Additional changes: Miroslav Vadkerti <mvadkert@redhat.com>\n" \
	"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"

/** Minimal buffer size for generated strings */
#define MINLEN 512

/** Maximum length of strings containing D-Bus name, interface and object path */
#define MAXLEN 256

/** Structure containing D-Bus name, object path and interface of process. */
struct fuzzing_target {
	/* names on D-Bus have the most MAXLEN characters */
	/** Bus name */
	char name[MAXLEN];
	/** Object path */
	char obj_path[MAXLEN];
	/** Interface */
	char interface[MAXLEN];
};

#define ANSI_RED        "\x1B[0;31m"
#define ANSI_GREEN      "\x1B[0;32m"
#define ANSI_YELLOW     "\x1B[0;33m"
#define ANSI_BLUE       "\x1B[0;34m"
#define ANSI_MAGENTA    "\x1B[0;35m"
#define ANSI_CYAN       "\x1B[0;36m"

#define ANSI_NORMAL     "\x1B[0m"
#define ANSI_BOLD       "\x1B[1m"

#define ANSI_CR         "\r"

static inline int df_isatty(void) {
	return isatty(STDOUT_FILENO) && isatty(STDERR_FILENO);
}

#define DEFINE_ANSI_FUNC(name, NAME)					\
	static inline const char *ansi_##name(void) {		\
		return df_isatty() ? ANSI_##NAME : "";		 	\
	}

DEFINE_ANSI_FUNC(red,        RED);
DEFINE_ANSI_FUNC(green,      GREEN);
DEFINE_ANSI_FUNC(yellow,     YELLOW);
DEFINE_ANSI_FUNC(blue,       BLUE);
DEFINE_ANSI_FUNC(magenta,    MAGENTA);
DEFINE_ANSI_FUNC(cyan,       CYAN);
DEFINE_ANSI_FUNC(normal,     NORMAL);
DEFINE_ANSI_FUNC(bold,       BOLD);
DEFINE_ANSI_FUNC(cr,         CR);

/**
 * @function Calls method ListNames to get all available connection names
 * on the bus and prints them on the program output.
 * @param dcon D-Bus connection structure
 * @return 0 on success, -1 on error
 */
int df_list_bus_names(const GDBusConnection *dcon);

/**
 * @function Traverses through all objects of bus name target_proc.name
 * and is looking for object path target_proc.obj_path
 * @param dcon D-Bus connection structure
 * @param root_node Starting object path (all nodes from this object path
 * will be traversed)
 * @return 1 when obj. path target_proc.obj_path is found on bus, 0 otherwise
 */
int df_is_object_on_bus(const GDBusConnection *dcon, const char *root_node);

/**
 * @function Traverses through all interfaces and objects of bus
 * name target_proc.name and for each interface it calls df_fuzz()
 * to fuzz test all its methods.
 * @param dcon D-Bus connection structure
 * @param root_node Starting object path (all nodes from this object path
 * will be traversed)
 * @return 0 on success, 1 on error, 2 when testing detected any failures
 * or warnings, 3 on warnings
 */
int df_traverse_node(const GDBusConnection *dcon, const char *root_node);

/**
 * @function Controls fuzz testing of all methods of specified interface (intf)
 * and reports results.
 * @param dcon D-Bus connection structure
 * @param name D-Bus name
 * @param obj D-Bus object path
 * @param intf D-Bus interface
 * @return 0 on success, 1 on error, 2 when testing detected any failures
 * or warnings, 3 on warnings
 */
int df_fuzz(const GDBusConnection *dcon, const char *name,
			const char *obj, const char *intf);

/**
 * @function Checks if name is valid D-Bus name, obj is valid
 * D-Bus object path and intf is valid D-Bus interface.
 * @param name D-Bus name
 * @param obj D-Bus object path
 * @param intf D-Bus interface
 * @return 1 if name, obj and intf are valid, 0 otherwise
 */
int df_is_valid_dbus(const char *name, const char *obj, const char *intf);

/**
 * @function Opens process status file.
 * @param pid PID - identifier of process
 * @return FD of status file on success, -1 on error
 */
int df_open_proc_status_file(const int pid);

/**
 * @function Calls method GetConnectionUnixProcessID on the interface
 * org.freedesktop.DBus to get process pid.
 * @param dcon D-Bus connection structure
 * @return Process PID on success, -1 on error
 */
int df_get_pid(const GDBusConnection *dcon);

/**
 * @function Prints process name and package to which process belongs.
 * @param pid PID of process
 * Note: Any error in this function is suppressed. On error, process name
 *       and package is just not printed.
 */
void df_print_process_info(int pid);

/**
 * @function Parses program options and stores them into global
 * variables:
 *  - df_buf_size -
 * 	   Maximum buffer size for generated strings by rand
 *     module (in Bytes)
 *  - df_mem_limit -
 *     Memory limit for tested process in kB
 *  - df_test_method -
 *     Contains method name or NULL. When not NULL, only
 *     method with this name will be tested
 *  - target_proc -
 *     Is of type struct fuzzing_target and is used
 *     to store bus name, object path and interface
 *  - df_verbose_flag -
 *     Be verbose
 *  - df_debug_flag	-
 *     Include debug output
 *  - df_supflg -
 *     If -s option is passed 1, otherwise 0
 *  - df_execute_cmd -
 *     Command/script to execute after each method call
 * If error occures function ends program.
 * @param argc Count of options
 * @param argv Pointer on strings containing options of program
 */
void df_parse_parameters(int argc, char **argv);

/**
 * @function Searches target_proc.name in suppression file SF1, SF2 and SF3
 * (the file which is opened first is parsed). If it is found, df_suppression
 * array is seeded with names of methods and df_supp_description is seeded
 * with descriptions why methods are skipped (df_suppression array is used
 * to skip methods which it contains when testing target_proc.name).
 * Suppression file is in format:
 * [bus_name]
 * method1 description
 * method2 description
 * [bus_name2]
 * method1 description
 * method2 description
 * ...
 * @return 0 on success, -1 on error
 */
int df_load_suppressions(void);

/**
 * @function Prints help.
 * @param name Name of program
 */
void df_print_help(const char *name);

/**
 * @function Displays an error message.
 * @param message Error message which will be printed
 * @param error Pointer on GError structure containing error specification
 */
void df_error(const char *message, GError *error);

/**
 * @function Prints debug message.
 * @param format Format string
 */
void df_debug(const char *format, ...);

/**
 * @function Prints verbose message.
 * @param format Format string
 */
void df_verbose(const char *format, ...);

/**
 * @function Prints error message.
 * @param format Format string
 */
void df_fail(const char *format, ...);

#endif
