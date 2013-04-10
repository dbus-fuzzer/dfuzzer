/** @file dfuzzer.c *//*

	dfuzzer - tool for testing processes communicating through D-Bus.
	Copyright (C) 2013  Matus Marhefka

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
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "dfuzzer.h"
#include "introspection.h"
#include "fuzz.h"


struct fuzzing_target target_proc;

/** Indicates SIGHUP, SIGINT signals (defined in fuzz.h) */
extern volatile sig_atomic_t df_exit_flag;

/** Memory limit for tested process in kB - if tested process exceeds this
	limit it will be noted into log file */
static long df_mem_limit;


int main(int argc, char **argv)
{
	char *log_file = "./log.log";	// file for logs
	int logfd;						// FD for log_file
	int statfd;					// FD for process status file
	GError *error = NULL;		// must be set to NULL
	GDBusConnection *dcon;		// D-Bus connection structure
	GDBusProxy *dproxy;			// D-Bus interface proxy

	GDBusProxy *pproxy;				// proxy for getting process PID
	int pid = -1;					// pid of tested process
	GVariant *variant_pid = NULL;	// response from GetConnectionUnixProcessID

	signal(SIGINT, df_signal_handler);
	signal(SIGHUP, df_signal_handler);		// terminal closed signal


	// do not free log_file - it points to argv
	df_parse_parameters(argc, argv, &log_file);

	// Initializes the type system.
	g_type_init();


	// Synchronously connects to the message bus.
	if ( (dcon = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error)) == NULL ) {
		df_error("Error in g_bus_get_sync() on connecting to the message bus",
				error);
	}


	// Creates a proxy for accessing target_proc.interface
	// on the remote object at target_proc.obj_path owned by target_proc.name
	// at dcon.
	dproxy = g_dbus_proxy_new_sync(dcon, G_DBUS_PROXY_FLAGS_NONE, NULL,
			target_proc.name, target_proc.obj_path, target_proc.interface,
			NULL, &error);
	if (dproxy == NULL) {
		g_object_unref(dcon);
		df_error("Error in g_dbus_proxy_new_sync() on creating proxy", error);
	}


	// Uses dcon (GDBusConnection *) to create proxy for accessing
	// org.freedesktop.DBus (for calling its method GetConnectionUnixProcessID)
	pproxy = g_dbus_proxy_new_sync(dcon, G_DBUS_PROXY_FLAGS_NONE, NULL,
			"org.freedesktop.DBus", "/org/freedesktop/DBus",
			"org.freedesktop.DBus", NULL, &error);
	if (pproxy == NULL) {
		g_object_unref(dproxy);
		g_object_unref(dcon);
		df_error("Error in g_dbus_proxy_new_sync() on creating proxy", error);
	}


	// Synchronously invokes method GetConnectionUnixProcessID
	variant_pid = g_dbus_proxy_call_sync(pproxy,
		"GetConnectionUnixProcessID",
		g_variant_new("(s)", target_proc.name), G_DBUS_CALL_FLAGS_NONE,
		-1, NULL, &error);
	if (variant_pid == NULL) {
		g_object_unref(pproxy);
		g_object_unref(dproxy);
		g_object_unref(dcon);
		df_error("Error in g_dbus_proxy_call_sync() on calling"
				" 'GetConnectionUnixProcessID' method", error);
	}
	g_variant_get(variant_pid, "(u)", &pid);
	if (pid < 0) {
		g_object_unref(pproxy);
		g_object_unref(dproxy);
		g_object_unref(dcon);
		g_variant_unref(variant_pid);
		df_error("Error in g_variant_get() on getting pid from GVariant", error);
	}
	g_variant_unref(variant_pid);
	g_object_unref(pproxy);



	// Introspection of object through proxy.
	if (df_init_introspection(dproxy, target_proc.interface) == -1) {
		g_object_unref(dproxy);
		g_object_unref(dcon);
		df_error("Error in df_init_introspection() on introspecting object",
				error);
	}

	// opens process status file
	if ((statfd = df_open_proc_status_file(pid)) == -1) {
		df_unref_introspection();
		g_object_unref(dproxy);
		g_object_unref(dcon);
		df_error("Error in df_open_proc_status_file()", error);
	}

	// tells fuzz module to call methods on dproxy, use FD statfd
	// for monitoring tested process and memory limit for process
	if (df_fuzz_init(dproxy, statfd, df_mem_limit) == -1) {
		close(statfd);
		df_unref_introspection();
		g_object_unref(dproxy);
		g_object_unref(dcon);
		df_error("Error in df_fuzz_add_proxy()", error);
	}

	// opens log file - all test events is going to be noted here
	logfd = open(log_file, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
	if (logfd == -1) {
		close(statfd);
		df_unref_introspection();
		g_object_unref(dproxy);
		g_object_unref(dcon);
		df_error("Error on opening log file", error);
	}


	GDBusMethodInfo *m;
	GDBusArgInfo *in_arg;
	for (; (m = df_get_method()) != NULL; df_next_method()) {
		// adds method name to the fuzzing module
		if (df_fuzz_add_method(m->name) == -1) {
			close(statfd);
			close(logfd);
			df_unref_introspection();
			g_object_unref(dproxy);
			g_object_unref(dcon);
			df_error("Error in df_fuzz_add_method()", error);
		}

		for (; (in_arg = df_get_method_arg()) != NULL; df_next_method_arg()) {
			// adds method argument signature to the fuzzing module
			if (df_fuzz_add_method_arg(in_arg->signature) == -1) {
				close(statfd);
				close(logfd);
				df_unref_introspection();
				g_object_unref(dproxy);
				g_object_unref(dcon);
				df_error("Error in df_fuzz_add_method_arg()", error);
			}
		}
		if (df_fuzz_test_method(statfd, logfd) == -1) {	// tests for method
			close(statfd);
			close(logfd);
			df_unref_introspection();
			g_object_unref(dproxy);
			g_object_unref(dcon);
			df_error("Error in df_fuzz_test_method()", error);
		}

		df_fuzz_clean_method();		// cleaning up after testing

		if (df_exit_flag) {
			fprintf(stderr, "\nExiting %s...\n", argv[0]);
			break;
		}
	}

	df_unref_introspection();
	g_object_unref(dproxy);
	g_object_unref(dcon);
	close(statfd);
	close(logfd);
	return 0;
}

/** @function Function is called when SIGINT signal is emitted. It sets
	flag df_exit_flag for fuzzer to know, that it should end testing, free
	memory and exit.
	@param sig Catched signal number
*/
void df_signal_handler(int sig)
{
	if (sig == SIGINT || sig == SIGHUP)
		df_exit_flag++;
}

/** @function Displays an error message and exits with error code 1.
	@param message Error message which will be printed before exiting program
	@param error Pointer on GError structure containing error specification
*/
void df_error(char *message, GError *error)
{
	if (error == NULL)
		fprintf(stderr, "%s\n", message);
	else {
		fprintf(stderr, "%s: %s\n", message, error->message);
		g_error_free(error);
	}

	exit(1);
}

/** @function Opens process status file.
	@param pid PID - identifier of process
	@return FD of status file on success, -1 on error
*/
int df_open_proc_status_file(int pid)
{
	char file_path[20];		// "/proc/(max5chars)/status"
	sprintf(file_path, "/proc/%d/status", pid);

	int statfd = open(file_path, O_RDONLY);
	if (statfd == -1) {
		fprintf(stderr, "Error on opening '%s' file\n", file_path);
		return -1;
	}
	return statfd;
}

/** @function Parses program options and stores them into struct fuzzing_target.
	If error occures function ends program.
	@param argc Count of options
	@param argv Pointer on strings containing options of program
	@param log_file File for logs
*/
void df_parse_parameters(int argc, char **argv, char **log_file)
{
	int c = 0;
	int nflg = 0, oflg = 0, iflg = 0;

	while ( (c = getopt(argc, argv, "n:o:i:l:m:h")) != -1 ) {
		switch (c) {
			case 'n':
				if (nflg != 0) {
					fprintf(stderr, "%s: no duplicate options -- 'n'\n",
							argv[0]);
					df_print_help(argv[0]);
					exit(1);
				}
				nflg++;
				// copy everything including null byte
				memcpy(target_proc.name, optarg, MAXLEN);
				break;
			case 'o':
				if (oflg != 0) {
					fprintf(stderr, "%s: no duplicate options -- 'o'\n",
							argv[0]);
					df_print_help(argv[0]);
					exit(1);
				}
				oflg++;
				// copy everything including null byte
				memcpy(target_proc.obj_path, optarg, MAXLEN);
				break;
			case 'i':
				if (iflg != 0) {
					fprintf(stderr, "%s: no duplicate options -- 'i'\n",
							argv[0]);
					df_print_help(argv[0]);
					exit(1);
				}
				iflg++;
				// copy everything including null byte
				memcpy(target_proc.interface, optarg, MAXLEN);
				break;
			case 'l':
				*log_file = optarg;
				break;
			case 'm':
				df_mem_limit = atol(optarg);
				if (df_mem_limit <= 0) {
					fprintf(stderr, "%s: invalid value for option -- 'm'\n",
							argv[0]);
					df_print_help(argv[0]);
					exit(1);
				}
				break;
			case 'h':
				df_print_help(argv[0]);
				exit(0);
				break;
			default:	// '?'
				df_print_help(argv[0]);
				exit(1);
				break;
		}
	}

	if (!nflg || !oflg || !iflg) {
		fprintf(stderr, "%s: options 'n', 'o' and 'i' must be set\n",
				argv[0]);
		df_print_help(argv[0]);
		exit(1);
	}
}

/** @function Prints help.
	@param name Name of program
*/
void df_print_help(char *name)
{
	printf("dfuzzer - Tool for testing processes communicating through D-Bus\n\n"
			"REQUIRED OPTIONS:\n\t-n <name>\n"
			"\t-o <object path>\n"
			"\t-i <interface>\n\n"
			"OTHER OPTIONS:\n"
			"\t-l <log file>\n\t   If not set, the log.log file is created.\n"
			"\t-m <memory limit in kB>\n\t   When tested"
			" process exceeds this limit it will be noted into log\n"
			"\t   file. Default value for this limit is 3x intial memory"
			" of process.\n\n"
			"Example:\n%s -n org.gnome.Shell -o /org/gnome/Shell"
			" -i org.gnome.Shell\n", name);
}
