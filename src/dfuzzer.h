/** @file dfuzzer.h */
/*

	dfuzzer - tool for fuzz testing processes communicating through D-Bus.
	Copyright(C) 2013, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>,
	Miroslav Vadkerti <mvadkert@redhat.com>

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
#ifndef DFUZZER_H
#define DFUZZER_H

/** Version of dfuzzer */
#define DF_VERSION "dfuzzer 1.2\n" \
	"Copyright(C) 2013, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>\n" \
	"Additional changes by Miroslav Vadkerti <mvadkert@redhat.com>\n" \
	"License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.\n"

/** minimal buffer size for generated strings */
#define MINLEN 512

/** maximum length of strings containing D-Bus name, interface and object path */
#define MAXLEN 256

/** Structure containing D-Bus name, object path and interface of process. */
struct fuzzing_target {		// names on D-Bus have the most MAXLEN characters
	/** Bus name */
	char name[MAXLEN];
	/** Object path */
	char obj_path[MAXLEN];
	/** Interface */
	char interface[MAXLEN];
};

/**
	@function Traverses through all interfaces and objects of bus
	name target_proc.name and for each interface it calls df_fuzz()
	to fuzz test all its methods.
	@param dcon D-Bus connection structure
	@param root_node Starting object path (all nodes from this object path
	will be traversed)
	@return 0 on success, 1 on error, 2 when testing detected any failures
*/
int df_traverse_node(GDBusConnection * dcon, const char *root_node);

/**
	@function Controls fuzz testing of all methods of specified interface (intf)
	and reports results.
	@param dcon D-Bus connection structure
	@param name D-Bus name
	@param obj D-Bus object path
	@param intf D-Bus interface
	@return 0 on success, 1 on error, 2 when testing detected any failures
*/
int df_fuzz(GDBusConnection * dcon, const char *name,
			const char *obj, const char *intf);

/**
	@function Checks if name is valid D-Bus name, obj is valid
	D-Bus object path and intf is valid D-Bus interface.
	@param name D-Bus name
	@param obj D-Bus object path
	@param intf D-Bus interface
	@return 1 if name, obj and intf are valid, 0 otherwise
*/
int df_is_valid_dbus(const char *name, const char *obj, const char *intf);

/**
	@function Opens process status file.
	@param pid PID - identifier of process
	@return FD of status file on success, -1 on error
*/
int df_open_proc_status_file(int pid);

/**
	@function Calls method GetConnectionUnixProcessID on the interface
	org.freedesktop.DBus to get process pid.
	@param dcon D-Bus connection structure
	@return Process PID on success, -1 on error
*/
int df_get_pid(GDBusConnection * dcon);

/**
	@function Parses program options and stores them into global
	variables:
	* buf_size
		Maximum buffer size for generated strings by rand
		module (in Bytes)
	* mem_limit
		Memory limit for tested process in kB
	* test_method
		Contains method name or NULL. When not NULL, only
		method with this name will be tested
	* target_proc
		Is of type struct fuzzing_target and is used
		to store bus name, object path and interface
	* df_verbose_flag
		Be verbose
	* df_debug_flag	
		Include debug output
	If error occures function ends program.
	@param argc Count of options
	@param argv Pointer on strings containing options of program
*/
void df_parse_parameters(int argc, char **argv);

/**
	@function Prints help.
	@param name Name of program
*/
void df_print_help(char *name);

/**
	@function Displays an error message.
	@param message Error message which will be printed
	@param error Pointer on GError structure containing error specification
*/
void df_error(char *message, GError * error);

/**
	@function Prints debug message.
	@param format Format string
*/
void df_debug(const char *format, ...);

/**
	@function Prints verbose message.
	@param format Format string
*/
void df_verbose(const char *format, ...);

/**
	@function Prints error message.
	@param format Format string
*/
void df_fail(const char *format, ...);

#endif
