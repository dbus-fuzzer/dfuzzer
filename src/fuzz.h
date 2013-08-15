/** @file fuzz.h */
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
#ifndef FUZZ_H
#define FUZZ_H

/** maximum length of D-Bus signature string */
#define MAXSIG 255

/** MAXSIG * 2 because of '@' character for every signature */
#define MAXFMT MAXSIG * 2

/** maximum length read from file */
#define MAXLINE 1024


/** Structure contains a D-Bus signature of the argument and pointer to a next
	argument (arguments belongs to the method df_method_name
	in structure df_sig_list).
*/
struct df_signature {
	/** D-Bus signature of the argument */
	char *sig;
	/** Storage for randomly generated data for the argument */
	GVariant *var;
	/** Pointer on next argument */
	struct df_signature *next;
};

/** Linked list of the method arguments and theirs signatures. */
struct df_sig_list {
	/** name of the current fuzzed method */
	char *df_method_name;
	/** number of arguments for method */
	int args;
	/** if 1, fuzzing will be controlled by generated random strings lengths */
	int fuzz_on_str_len;
	/** if no arguments - NULL, otherwise NULL terminated linked list */
	struct df_signature *list;
};


/** Error checked write function with short write correction (when write
	is interrupted by a signal).
	@param fd File descriptor where to write
	@param buf Buffer from which to write to file descriptor fd
	@param count Number of bytes to be written
	@return 0 on success, -1 on error
*/
inline int df_ewrite(int fd, const void *buf, size_t count);

/**
	@function Saves pointer on D-Bus interface proxy for this module to be
	able to call methods through this proxy during fuzz testing. Also saves
	process initial memory size to global var. df_initial_mem from file
	described by statfd.
	@param dproxy Pointer on D-Bus interface proxy
	@param statfd FD of process status file
	@param mem_limit Memory limit in kB - if tested process exceeds this limit
	it will be noted into log file
	@return 0 on success, -1 on error
*/
int df_fuzz_init(GDBusProxy *dproxy, int statfd, long mem_limit);

/**
	@function Initializes the global variable df_list (struct df_sig_list)
	including allocationg memory for method name inside df_list.
	@param name Name of method which will be tested
	@return 0 on success, -1 on error
*/
int df_fuzz_add_method(char *name);

/**
	@function Adds item (struct df_signature) at the end of the linked list
	in the global variable df_list (struct df_sig_list). This includes
	allocating memory for item and for signature string.
	@param signature D-Bus signature of the argument
	@return 0 on success, -1 on error
*/
int df_fuzz_add_method_arg(char *signature);

/**
	@return Number of arguments of tested method
*/
int df_list_args_count(void);

/**
	@function Function is testing a method in cycle, each cycle generates data
	for function arguments, calls method and waits for result.
	@param statfd FD of process status file
	@param buf_size Maximum buffer size for generated strings
	by rand module (in Bytes)
	@param name D-Bus name
	@param obj D-Bus object path
	@param intf D-Bus interface
	@param one_method_test If set to 1, reinitialization of rand module
	is disabled, otherwise it is enabled
	@return 0 on success, -1 on error or 1 on tested process crash
*/
int df_fuzz_test_method(int statfd, long buf_size, const char *name,
						const char *obj, const char *intf, int one_method_test);

/**
	@function Releases memory used by this module. This function must be called
	after df_fuzz_add_method() and df_fuzz_add_method_arg() functions calls
	after the end of fuzz testing of each method.
*/
void df_fuzz_clean_method(void);

#endif
