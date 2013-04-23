/** @file dfuzzer.c */
/*

	dfuzzer - tool for fuzz testing processes communicating through D-Bus.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#include "dfuzzer.h"
#include "introspection.h"
#include "fuzz.h"


/** Structure containing D-Bus name, object path and interface of process */
struct fuzzing_target target_proc;

/** Indicates SIGHUP, SIGINT signals (defined in fuzz.h) */
extern volatile sig_atomic_t df_exit_flag;


int main(int argc, char **argv)
{
	char *log_file = "./log.log";	// file for logs
	int logfd;						// FD for log_file
	int statfd;						// FD for process status file
	long buf_size = 0;			// maximum buffer size for generated strings
								// by rand module (in Bytes)
	long mem_limit = 0;		// Memory limit for tested process in kB - if
							// tested process exceeds this limit it will be
							// noted into log file
	int cont_flg = 0;			// when tested process crashes and this
								// flag is set to 1, it is relaunched
								// and testing continue

	GError *error = NULL;			// must be set to NULL
	GDBusConnection *dcon;			// D-Bus connection structure
	GDBusProxy *dproxy;				// D-Bus interface proxy

	int pid = -1;					// pid of tested process


	signal(SIGINT, df_signal_handler);
	signal(SIGHUP, df_signal_handler);		// terminal closed signal


	// do not free log_file - it points to argv
	df_parse_parameters(argc, argv, &log_file, &buf_size, &mem_limit, &cont_flg);

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


	// gets pid of tested process
	pid = df_get_pid(dcon);
	if (pid < 0) {
		g_object_unref(dproxy);
		g_object_unref(dcon);
		df_error("Error in df_get_pid() on getting pid of process", error);
	}


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
	if (df_fuzz_init(dproxy, statfd, mem_limit) == -1) {
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

	// truncates log file to zero length
	if (ftruncate(logfd, 0L) == -1) {
		perror("Error on truncating file to size 0");
		return -1;
	}


	printf("Fuzzing started...\n");
	GDBusMethodInfo *m;
	GDBusArgInfo *in_arg;
	for (; (m = df_get_method()) != NULL; df_next_method())
	{
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

		// tests for method
		int ret = df_fuzz_test_method(statfd, logfd, buf_size);
		if (ret == -1) {
			close(statfd);
			close(logfd);
			df_unref_introspection();
			g_object_unref(dproxy);
			g_object_unref(dcon);
			df_error("Error in df_fuzz_test_method()", error);
		}

		df_fuzz_clean_method();		// cleaning up after testing method

		if (df_exit_flag)
			goto end_label;

		// launch process again after crash
		if (ret == 1 && cont_flg)
		{
			g_object_unref(dproxy);
			dproxy = g_dbus_proxy_new_sync(dcon, G_DBUS_PROXY_FLAGS_NONE, NULL,
				target_proc.name, target_proc.obj_path, target_proc.interface,
				NULL, &error);
			if (dproxy == NULL) {
				close(statfd);
				close(logfd);
				df_unref_introspection();
				g_object_unref(dproxy);
				g_object_unref(dcon);
				df_error("Error in g_dbus_proxy_new_sync() on creating"
						" proxy", error);
			}

			if (sleep(5)) {		// wait for application to launch
				if (df_exit_flag)
					goto end_label;
			}

			// gets pid of tested process
			pid = df_get_pid(dcon);
			if (pid < 0) {
				close(statfd);
				close(logfd);
				df_unref_introspection();
				g_object_unref(dproxy);
				g_object_unref(dcon);
				df_error("Error in df_get_pid() on getting pid of process",
						error);
			}

			// opens process status file
			close(statfd);
			if ((statfd = df_open_proc_status_file(pid)) == -1) {
				close(statfd);
				close(logfd);
				df_unref_introspection();
				g_object_unref(dproxy);
				g_object_unref(dcon);
				df_error("Error in df_open_proc_status_file()", error);
			}

			// tells fuzz module to call methods on different dproxy nad to use
			// new status file of process with PID pid
			if (df_fuzz_init(dproxy, statfd, mem_limit) == -1) {
				close(statfd);
				close(logfd);
				df_unref_introspection();
				g_object_unref(dproxy);
				g_object_unref(dcon);
				df_error("Error in df_fuzz_add_proxy()", error);
			}
		}
		else if (ret == 1 && !cont_flg)	// end of fuzzing after process crash
			goto end_label;
	}

end_label:
	printf("\nEnd of fuzzing.");
	printf("\nLook into '%s' for results of fuzzing.", log_file);
	printf("\nReleasing all used memory...");
	df_unref_introspection();
	g_object_unref(dproxy);
	g_object_unref(dcon);
	close(statfd);
	close(logfd);
	printf("\nExiting...\n");
	return 0;
}

/**
	@function Function is called when SIGINT signal is emitted. It sets
	flag df_exit_flag for fuzzer to know, that it should end testing, free
	memory and exit.
	@param sig Catched signal number
*/
void df_signal_handler(int sig)
{
	if (sig == SIGINT || sig == SIGHUP)
		df_exit_flag++;
}

/**
	@function Displays an error message and exits with error code 1.
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

/**
	@function Opens process status file.
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

/**
	@function Calls method GetConnectionUnixProcessID on the interface
	org.freedesktop.DBus to get process pid.
	@param dcon D-Bus connection structure
	@return Process PID on success, -1 on error
*/
int df_get_pid(GDBusConnection *dcon)
{
	GError *error = NULL;			// must be set to NULL
	GDBusProxy *pproxy;				// proxy for getting process PID
	GVariant *variant_pid = NULL;	// response from GetConnectionUnixProcessID
	int pid = -1;

	// Uses dcon (GDBusConnection *) to create proxy for accessing
	// org.freedesktop.DBus (for calling its method GetConnectionUnixProcessID)
	pproxy = g_dbus_proxy_new_sync(dcon, G_DBUS_PROXY_FLAGS_NONE, NULL,
			"org.freedesktop.DBus", "/org/freedesktop/DBus",
			"org.freedesktop.DBus", NULL, &error);
	if (pproxy == NULL) {
		fprintf(stderr, "Error on creating proxy for getting process pid: %s\n",
				error->message);
		return -1;
	}


	// Synchronously invokes method GetConnectionUnixProcessID
	variant_pid = g_dbus_proxy_call_sync(pproxy,
		"GetConnectionUnixProcessID",
		g_variant_new("(s)", target_proc.name), G_DBUS_CALL_FLAGS_NONE,
		-1, NULL, &error);
	if (variant_pid == NULL) {
		fprintf(stderr, "Error on calling GetConnectionUnixProcessID"
				" through D-Bus: %s\n", error->message);
		g_object_unref(pproxy);
		return -1;
	}
	g_variant_get(variant_pid, "(u)", &pid);
	g_variant_unref(variant_pid);
	g_object_unref(pproxy);

	return pid;
}

/**
	@function Parses program options and stores them into struct fuzzing_target.
	If error occures function ends program.
	@param argc Count of options
	@param argv Pointer on strings containing options of program
	@param log_file File for logs
	@param buf_size Maximum buffer size for generated strings
	by rand module (in Bytes)
	@param mem_limit Memory limit for tested process in kB
	@param cont_flg When 1 and tested process crashes, it is relaunched
	and testing continue; 0 means end of testing after crash
*/
void df_parse_parameters(int argc, char **argv, char **log_file,
						long *buf_size, long *mem_limit, int *cont_flg)
{
	int c = 0;
	int nflg = 0, oflg = 0, iflg = 0, lflg = 0, mflg = 0, bflg = 0, cflg = 0;

	while ( (c = getopt(argc, argv, "n:o:i:l:m:b:ch")) != -1 ) {
		switch (c) {
			case 'n':
				if (nflg != 0) {
					fprintf(stderr, "%s: no duplicate options -- 'n'\n",
							argv[0]);
					exit(1);
				}
				nflg++;
				if (strlen(optarg) >= MAXLEN) {
					fprintf(stderr, "%s: maximum %d characters for option --"
							" 'n'\n", argv[0], MAXLEN-1);
					exit(1);
				}
				// copy everything including null byte
				memcpy(target_proc.name, optarg, MAXLEN);
				break;
			case 'o':
				if (oflg != 0) {
					fprintf(stderr, "%s: no duplicate options -- 'o'\n",
							argv[0]);
					exit(1);
				}
				oflg++;
				if (strlen(optarg) >= MAXLEN) {
					fprintf(stderr, "%s: maximum %d characters for option --"
							" 'o'\n", argv[0], MAXLEN-1);
					exit(1);
				}
				// copy everything including null byte
				memcpy(target_proc.obj_path, optarg, MAXLEN);
				break;
			case 'i':
				if (iflg != 0) {
					fprintf(stderr, "%s: no duplicate options -- 'i'\n",
							argv[0]);
					exit(1);
				}
				iflg++;
				if (strlen(optarg) >= MAXLEN) {
					fprintf(stderr, "%s: maximum %d characters for option --"
							" 'i'\n", argv[0], MAXLEN-1);
					exit(1);
				}
				// copy everything including null byte
				memcpy(target_proc.interface, optarg, MAXLEN);
				break;
			case 'l':
				if (lflg != 0) {
					fprintf(stderr, "%s: no duplicate options -- 'l'\n",
							argv[0]);
					exit(1);
				}
				lflg++;
				*log_file = optarg;
				break;
			case 'm':
				if (mflg != 0) {
					fprintf(stderr, "%s: no duplicate options -- 'm'\n",
							argv[0]);
					exit(1);
				}
				mflg++;
				*mem_limit = strtol(optarg, NULL, 10);
				if (*mem_limit <= 0 || errno == ERANGE || errno == EINVAL) {
					fprintf(stderr, "%s: invalid value for option -- 'm'\n",
							argv[0]);
					exit(1);
				}
				break;
			case 'b':
				if (bflg != 0) {
					fprintf(stderr, "%s: no duplicate options -- 'b'\n",
							argv[0]);
					exit(1);
				}
				bflg++;
				*buf_size = strtol(optarg, NULL, 10);
				if (*buf_size < MINLEN || errno == ERANGE || errno == EINVAL) {
					fprintf(stderr, "%s: invalid value for option -- 'b'\n"
							" -- at least %d B are required\n", argv[0], MINLEN);
					exit(1);
				}
				break;
			case 'c':
				if (cflg != 0) {
					fprintf(stderr, "%s: no duplicate options -- 'c'\n",
							argv[0]);
					exit(1);
				}
				cflg++;
				(*cont_flg)++;
				break;
			case 'h':
				df_print_help(argv[0]);
				exit(0);
				break;
			default:	// '?'
				exit(1);
				break;
		}
	}

	if (!nflg || !oflg || !iflg) {
		fprintf(stderr, "%s: options 'n', 'o' and 'i' are required\n",
				argv[0]);
		exit(1);
	}
}

/**
	@function Prints help.
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
			"\t-m <memory limit in kB>\n"
			"\t   When tested process exceeds this limit it will be noted into\n"
			"\t   log file. Default value for this limit is 3x process intial\n"
			"\t   memory size. If set memory limit value is less than or\n"
			"\t   equal to process initial memory size, it will be adjusted\n"
			"\t   to default value (3x process intial memory size).\n"
			"\t-b <maximum buffer size in B>\n"
			"\t   Maximum buffer size for generated strings, minimum is 256 B.\n"
			"\t   Default maximum size is 50000 B ~= 50 kB.\n"
			"\t-c\n"
			"\t   If tested process crashes during fuzzing and this option is\n"
			"\t   set, crashed process will be launched again and testing will\n"
			"\t   continue."
			"\n"
			"Example:\n%s -n org.gnome.Shell -o /org/gnome/Shell"
			" -i org.gnome.Shell -c\n", name);
}
