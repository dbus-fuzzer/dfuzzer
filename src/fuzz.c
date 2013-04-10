/** @file fuzz.c */
/*

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <ffi.h>		// dynamic function call construction

#include "fuzz.h"
#include "rand.h"


/** Pointer on D-Bus interface proxy for calling methods. */
static GDBusProxy *df_dproxy;

/** Structure containing information about the linked list. */
static struct df_sig_list df_list;

/** Pointer on the last item of the linked list in the global var. df_list. */
static struct df_signature *df_last;

/** Initial memory size of process is saved into this variable */
static long df_initial_mem = -1;

/** Memory limit for tested process in kB - if tested process exceeds this
	limit it will be noted into log file */
static long df_mem_limit;

/** Flag for unsupported method signature, 1 means signature is unsupported */
static int unsupported_sig;
/** Pointer on unsupported signature string (do not free it) */
static char *unsupported_sig_str;


/* Module static functions */
static long df_fuzz_get_proc_mem_size(int statfd);
static int df_fuzz_write_log(int logfd, unsigned long buf_size);
static GVariant * df_fuzz_create_variant(void);
static int df_fuzz_create_list_variants(void);
static int df_fuzz_create_fmt_string(char **fmt, int n);
static int df_fuzz_call_method(GVariant *value);


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
int df_fuzz_init(GDBusProxy *dproxy, int statfd, long mem_limit)
{
	if (dproxy == NULL) {
		fprintf(stderr, "Passing NULL argument to function.\n");
		return -1;
	}
	df_dproxy = dproxy;

	df_initial_mem = df_fuzz_get_proc_mem_size(statfd);
	if (df_initial_mem == -1) {
		fprintf(stderr, "Error in df_fuzz_get_proc_mem_size()\n");
		return -1;
	}

	if (mem_limit <= df_initial_mem)
		df_mem_limit = 3 * df_initial_mem;
	else
		df_mem_limit = mem_limit;

	return 0;
}

/**
	@function Initializes the global variable df_list (struct df_sig_list)
	including allocationg memory for method name inside df_list.
	@param name Name of method which will be tested
	@return 0 on success, -1 on error
*/
int df_fuzz_add_method(char *name)
{
	if (name == NULL) {
		fprintf(stderr, "Passing NULL argument to function.\n");
		return -1;
	}

	df_list.df_method_name = malloc(sizeof(char) * strlen(name) + 1);
	if (df_list.df_method_name == NULL) {
		fprintf(stderr, "Could not allocate memory for method name.\n");
		return -1;
	}
	strcpy(df_list.df_method_name, name);

	// must be initialized because after df_fuzz_clean_method() memory
	// of df_list contains junk
	df_list.list = NULL;	// no arguments so far
	df_list.args = 0;

	return 0;
}

/**
	@function Adds item (struct df_signature) at the end of the linked list
	in the global variable df_list (struct df_sig_list). This includes
	allocating memory for item and for signature string.
	@param signature D-Bus signature of the argument
	@return 0 on success, -1 on error
*/
int df_fuzz_add_method_arg(char *signature)
{
	if (signature == NULL)
		return 0;

	struct df_signature *s;
	if ( (s = malloc(sizeof(struct df_signature))) == NULL ) {
		fprintf(stderr, "Could not allocate memory for struct df_signature.\n");
		return -1;
	}

	df_list.args++;
	s->next = NULL;
	s->var = NULL;
	s->sig = malloc(sizeof(char) * strlen(signature) + 1);
	if (s->sig == NULL) {
		fprintf(stderr, "Could not allocate memory for argument signature.\n");
		return -1;
	}
	strcpy(s->sig, signature);

	if (df_list.list == NULL) {
		df_list.list = s;
		df_last = s;
	}
	else {
		df_last->next = s;
		df_last = s;
	}

	return 0;
}

/**
	@function Parses VmRSS (Resident Set Size) value from statfd and returns it
	as process memory size.
	@param statfd FD of process status file
	@return Process memory size on success, 0 when statfd is not readable (that
	means process disconnected from D-Bus) or -1 on error
*/
static long df_fuzz_get_proc_mem_size(int statfd)
{
	long mem_size = -1;
	char buf[MAXLINE];		// buffer for reading from file
	char *ptr;				// pointer into buf buffer

	// rewinds file position to the beginning
	if (lseek(statfd, 0L, SEEK_SET) == -1)
		return 0;

	int stopr = 0;
	while (!stopr) {
		int n = read(statfd, buf, MAXLINE-1);
		if (n == -1) {
			fprintf(stderr, "Error on reading process status file\n");
			return -1;
		}
		if (n == 0)
			stopr++;
		buf[n] = '\0';

		if ( (ptr = strstr(buf, "VmRSS:")) == NULL)
			return 0;

		// check for new line (that whole memory size number is in buffer)
		char *nl = ptr;
		while (*nl != '\0') {
			if (*nl == '\n') {
				stopr++;
				break;
			}
			nl++;
		}
	}

	// now ptr points to VmRSS:
	while (isdigit(*ptr) == 0)
		ptr++;

	mem_size = atol(ptr);
	return mem_size;
}

/**
	@function Writes all method signatures and their values into the log file.
	@param logfd FD of log file
	@param buf_size Maximum buffer size for generated strings
	by rand module (in Bytes)
*/
static int df_fuzz_write_log(int logfd, unsigned long buf_size)
{	// TODO: try g_variant_get_data()
	struct df_signature *s = df_list.list;		// pointer on first signature
	int len;
	int str_len = -1;
	char *buf = malloc(sizeof(char) * buf_size);
	char *ptr = buf;

	while (s != NULL) {
		len = strlen(s->sig);
		if (len <= 0) {
			fprintf(stderr, "No argument signature\n");
			return -1;
		}
		else if (len == 1) {	// one character argument
			switch (s->sig[0]) {
				case 'y':
					; guint8 tmp;
					g_variant_get(s->var, s->sig, &tmp);
					sprintf(ptr, "%u", tmp);
					break;
				case 'b':
					; gboolean tmp1;
					g_variant_get(s->var, s->sig, &tmp1);
					sprintf(ptr, "%s", ((tmp1 == 1) ? "true" : "false"));
					break;
				case 'n':
					; gint16 tmp2;
					g_variant_get(s->var, s->sig, &tmp2);
					sprintf(ptr, "%d", tmp2);
					break;
				case 'q':
					; guint16 tmp3;
					g_variant_get(s->var, s->sig, &tmp3);
					sprintf(ptr, "%u", tmp3);
					break;
				case 'i':
					; gint32 tmp4;
					g_variant_get(s->var, s->sig, &tmp4);
					sprintf(ptr, "%d", tmp4);
					break;
				case 'u':
					; guint32 tmp5;
					g_variant_get(s->var, s->sig, &tmp5);
					sprintf(ptr, "%u", tmp5);
					break;
				case 'x':
					; gint64 tmp6;
					g_variant_get(s->var, s->sig, &tmp6);
					sprintf(ptr, "%ld", tmp6);
					break;
				case 't':
					; guint64 tmp7;
					g_variant_get(s->var, s->sig, &tmp7);
					sprintf(ptr, "%lu", tmp7);
					break;
				case 'd':
					; gdouble tmp8;
					g_variant_get(s->var, s->sig, &tmp8);
					sprintf(ptr, "%lg", tmp8);
					break;
				case 's':
					; gchar *tmp9 = NULL;
					g_variant_get(s->var, s->sig, &tmp9);
					str_len = strlen(tmp9);
					if (tmp9 != NULL)
						sprintf(ptr, " [length: %d B]-- '%s", str_len, tmp9);
					break;
				case 'o':
					; gchar *tmp10 = NULL;
					g_variant_get(s->var, s->sig, &tmp10);
					str_len = strlen(tmp10);
					if (tmp10 != NULL)
						sprintf(ptr, " [length: %d B]-- '%s", str_len, tmp10);
					break;
				case 'g':
					; gchar *tmp11 = NULL;
					g_variant_get(s->var, s->sig, &tmp11);
					str_len = strlen(tmp11);
					if (tmp11 != NULL)
						sprintf(ptr, " [length: %d B]-- '%s", str_len, tmp11);
					break;
				case 'v':
					; GVariant *var = NULL; gchar *tmp12 = NULL;
					g_variant_get(s->var, s->sig, var);
					g_variant_get(var, "s", &tmp12);
					str_len = strlen(tmp12);
					if (tmp12 != NULL)
						sprintf(ptr, " [length: %d B]-- '%s", str_len, tmp12);
					break;
				case 'h':
					; gint32 tmp13;
					g_variant_get(s->var, s->sig, &tmp13);
					sprintf(ptr, "%d", tmp13);
					break;
				default:
					fprintf(stderr, "Unknown argument signature '%s'\n", s->sig);
					return -1;
			}
		}
		else {	// advanced argument (array of something, dictionary, ...)
			fprintf(stderr, "Not yet implemented in df_fuzz_write_log()\n");
		}

		write(logfd, "  --", 4);
		write(logfd, s->sig, len);
		if (str_len == -1)	// no string, no length printing
			write(logfd, "-- '", 4);
		write(logfd, buf, strlen(buf));
		write(logfd, "'\n", 2);

		str_len = -1;
		ptr = buf;
		s = s->next;
	}

	free(buf);
	return 0;
}

/**
	@function Function is testing a method in cycle, each cycle generates data
	for function arguments, calls method and waits for result.
	@param statfd FD of process status file
	@param logfd FD of log file
	@param buf_size Maximum buffer size for generated strings
	by rand module (in Bytes)
	@return 0 on success, -1 on error
*/
int df_fuzz_test_method(int statfd, int logfd, unsigned long buf_size)
{
	struct df_signature *s = df_list.list;		// pointer on first signature
	GVariant *value = NULL;
	int i;
	long used_memory = 0;				// memory size used by process in kB
	long prev_memory = 0;				// last known memory size
	long max_memory = df_mem_limit;		// maximum normal memory size used
										// by process in kB

	char *ptr, *log_buffer = malloc(sizeof(char) * buf_size);
	ptr = log_buffer;


	// writes to log file which method is going to be tested
	ptr += sprintf(ptr,"==========================================="
						"===================================\n");
	ptr += sprintf(ptr, "testing method %s(", df_list.df_method_name);
	for (i = 0; i < df_list.args; i++, s = s->next)
		ptr += sprintf(ptr, ((i < df_list.args-1) ? "%s, " : "%s"), s->sig);
	ptr += sprintf(ptr, "):\n");
	write(logfd, log_buffer, strlen(log_buffer));

	// restarts position in log_buffer
	ptr = log_buffer;


	df_rand_init(buf_size);		// initialization of random module


	i = 1;			// log number for current method
	while (df_rand_continue()) {
		// parsing proces memory size from its status file described by statfd
		used_memory = df_fuzz_get_proc_mem_size(statfd);
		if (used_memory == -1) {
			fprintf(stderr, "Error in df_fuzz_get_proc_mem_size()\n");
			g_variant_unref(value);
			return -1;
		}
		if (used_memory == 0) {
			fprintf(stderr, "PROCESS DISCONNECTED FROM D-BUS!\n");
			sprintf(ptr, "[LOG %d]\n  process disconnected from D-Bus\n"
							"  last known process memory size: [%ld kB]\n"
							"  on input:\n", i, prev_memory);
			write(logfd, log_buffer, strlen(log_buffer));
			ptr = log_buffer;
			i++;
			df_fuzz_write_log(logfd, buf_size);

			g_variant_unref(value);
			free(log_buffer);
			return -1;
		}
		prev_memory = used_memory;

		// creates variant containing all (fuzzed) method arguments
		if ( (value = df_fuzz_create_variant()) == NULL) {
			if (unsupported_sig) {
				unsupported_sig = 0;
				// writes to the logfd to let tester know
				ptr += sprintf(ptr, "  unsupported argument by dfuzzer: ");
				ptr += sprintf(ptr, "%s\n", unsupported_sig_str);
				write(logfd, log_buffer, strlen(log_buffer));
				unsupported_sig_str = NULL;
				free(log_buffer);
				return 0;
			}
			fprintf(stderr, "Call of df_fuzz_create_variant() returned NULL"
					" pointer\n");
			return -1;
		}


		if (df_fuzz_call_method(value) == -1) {
			fprintf(stderr, "PROCESS DISCONNECTED FROM D-BUS!\n");
			sprintf(ptr, "[LOG %d]\n  process disconnected from D-Bus\n"
							"  last known process memory size: [%ld kB]\n"
							"  on input:\n", i, prev_memory);
			write(logfd, log_buffer, strlen(log_buffer));
			ptr = log_buffer;
			i++;
			df_fuzz_write_log(logfd, buf_size);

			g_variant_unref(value);
			free(log_buffer);
			return -1;
		}


		// process memory size exceeded maximum normal memory size
		if (used_memory >= max_memory) {
			sprintf(ptr, "[LOG %d]\n  warning: process memory size exceeded"
							" set memory limit [%ld kB]\n    initial memory: "
							"[%ld kB]\n    current process memory size: "
							"[%ld kB]\n  on input:\n",
							i, df_mem_limit, df_initial_mem, used_memory);
			write(logfd, log_buffer, strlen(log_buffer));
			ptr = log_buffer;
			i++;
			max_memory *= 3;
			df_fuzz_write_log(logfd, buf_size);
		}


		if (df_exit_flag) {
			g_variant_unref(value);
			free(log_buffer);
			return 0;
		}

		g_variant_unref(value);
	}

	ptr += sprintf(ptr,"==========================================="
						"===================================\n");
	ptr += sprintf(ptr, "END OF FUZZING OF METHOD '%s'\n",
						df_list.df_method_name);
	write(logfd, log_buffer, strlen(log_buffer));

	free(log_buffer);
	return 0;
}

/**
	@function Creates GVariant tuple variable which contains all the signatures
	of method arguments including their values. This tuple is constructed
	from each signature of method argument by one call of g_variant_new()
	function. This call is constructed dynamically (using libffi) as we don't
	know number of function parameters on compile time.
	@return Pointer on a new GVariant variable containing tuple with method
	arguments
*/
static GVariant * df_fuzz_create_variant(void)
{
	struct df_signature *s = df_list.list;		// pointer on first signature

	// creates GVariant for every item signature in linked list
	int ret = df_fuzz_create_list_variants();
	if (ret == -1) {
		fprintf(stderr, "Error in df_fuzz_create_list_variants()\n");
		return NULL;
	}

	if (ret == 1) {		// unsupported method signature
		unsupported_sig++;
		return NULL;
	}

	// libffi part, to construct dynamic call of g_variant_new() on runtime
	GVariant *val = NULL;
	ffi_cif cif;
	// MAXSIG = max. amount of D-Bus signatures + 1 (format string)
	ffi_type *args[MAXSIG+1];
	void *values[MAXSIG+1];
	char *fmt;		// format string
	int i;


	if ( (fmt = malloc(MAXFMT+1)) == NULL ) {
		fprintf(stderr, "Could not allocate memory for format string\n");
		return NULL;
	}

	// creates the format string for g_variant_new() function call
	if (df_fuzz_create_fmt_string(&fmt, MAXFMT+1) == -1) {
		fprintf(stderr, "Error in df_fuzz_create_fmt_string()\n");
		return NULL;
	}

	#ifdef DEBUG
		//printf("fmt string: [%s]\nargs: [%d]\n\n", fmt, df_list.args);
	#endif

	// Initialize the argument info vectors
	args[0] = &ffi_type_pointer;
	values[0] = &fmt;
	for (i = 1; i <= df_list.args && s != NULL; i++) {
		args[i] = &ffi_type_pointer;
		values[i] = &(s->var);
		s = s->next;
	}

	// Initialize the cif
	if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, df_list.args+1,
		&ffi_type_pointer, args) == FFI_OK)
	{
		ffi_call(&cif, g_variant_new, &val, values);
		// val now holds the result of the call to g_variant_new()
	}
	else {
		fprintf(stderr, "ffi_prep_cif() failed on initializing cif\n");
		return NULL;
	}

	// GVariant containing method parameters must not be floating, because
	// it would be consumed by g_dbus_proxy_call_sync() function and as
	// result we couldn't have get GVariant values from items of linked list
	// (needed for loging into log file)
	val = g_variant_ref_sink(val);	// converts floating to normal reference
									// so val cannot be consumed
									// by g_dbus_proxy_call_sync() function
	if (g_variant_is_floating(val)) {
		fprintf(stderr, "GVariant containing '%s()' method parameters must not"
				" be floating\n", df_list.df_method_name);
		return NULL;
	}

	free(fmt);
	return val;
}

/**
	@function Generates data for each method argument according to argument
	signature and stores it into Gvariant variable in items of linked list.
	@return 0 on success, 1 on unsupported method signature, -1 on error
*/
static int df_fuzz_create_list_variants(void)
{
	struct df_signature *s = df_list.list;		// pointer on first signature
	int len;

	while (s != NULL) {
		len = strlen(s->sig);
		if (len <= 0) {
			fprintf(stderr, "No argument signature\n");
			return -1;
		}
		else if (len == 1) {	// one character argument
			switch (s->sig[0]) {
				case 'y':
					s->var = g_variant_new(s->sig, df_rand_guint8());
					break;
				case 'b':
					s->var = g_variant_new(s->sig, df_rand_gboolean());
					break;
				case 'n':
					s->var = g_variant_new(s->sig, df_rand_gint16());
					break;
				case 'q':
					s->var = g_variant_new(s->sig, df_rand_guint16());
					break;
				case 'i':
					s->var = g_variant_new(s->sig, df_rand_gint32());
					break;
				case 'u':
					s->var = g_variant_new(s->sig, df_rand_guint32());
					break;
				case 'x':
					s->var = g_variant_new(s->sig, df_rand_gint64());
					break;
				case 't':
					s->var = g_variant_new(s->sig, df_rand_guint64());
					break;
				case 'd':
					s->var = g_variant_new(s->sig, df_rand_gdouble());
					break;
				case 's':
					; gchar *buf;
					if (df_rand_string(&buf) == -1) {
						fprintf(stderr, "In df_rand_string()\n");
						return -1;
					}
					s->var = g_variant_new(s->sig, buf);
					free(buf);
					break;
				case 'o':
					; gchar *obj;
					if (df_rand_dbus_objpath_string(&obj) == -1) {
						fprintf(stderr, "In df_rand_dbus_objpath_string()\n");
						return -1;
					}
					s->var = g_variant_new(s->sig, obj);
					free(obj);
					break;
				case 'g':
					; gchar *sig;
					if (df_rand_dbus_signature_string(&sig) == -1) {
						fprintf(stderr, "In df_rand_dbus_signature_string()\n");
						return -1;
					}
					s->var = g_variant_new(s->sig, sig);
					free(sig);
					break;
				case 'v':
					; GVariant *var;
					if (df_rand_GVariant(&var) == -1) {
						fprintf(stderr, "In df_rand_GVariant()\n");
						return -1;
					}
					s->var = g_variant_new(sig, var);
					g_variant_unref(var);
					break;
				case 'h':
					s->var = g_variant_new(s->sig, df_rand_unixFD());
					break;
				default:
					fprintf(stderr, "Unknown argument signature '%s'\n", s->sig);
					return -1;
			}
		}
		else {	// advanced argument (array of something, dictionary, ...)
			// TODO
			fprintf(stderr, "Advanced signatures not yet implemented\n");
			unsupported_sig_str = s->sig;
			// TODO: can we create something like empty valid GVariant for
			// advanced data types in this function ?
			// If yes, remove whole unsupported thing
			return 1;	// unsupported method signature
		}

		if (s->var == NULL) {
			fprintf(stderr, "Failed to construct GVariant for '%s' signature\n",
					s->sig);
			return -1;
		}
		s = s->next;
	}

	return 0;
}

/**
	@function Creates format string (tuple) from method arguments signatures
	with maximum length of n-1. The final string is saved in parameter fmt.
	@param fmt Pointer on buffer where format string should be stored
	@param n Size of buffer
	@return 0 on success, -1 on error
*/
static int df_fuzz_create_fmt_string(char **fmt, int n)
{
	struct df_signature *s = df_list.list;		// pointer on first signature
	int total_len = 0;
	int len = 0;
	char *ptr = *fmt;

	// final fmt string, for example may look like this: "(@s@i)"
	*ptr = '(';
	total_len++;
	ptr++;

	while (s != NULL) {
		len = strlen(s->sig);
		total_len += len + 1;	// including '@' character
		if (total_len > n-3) {
			fprintf(stderr, "Format string is too small to consume all"
							" signatures\n");
			return -1;
		}
		*ptr = '@';
		ptr++;
		memcpy(ptr, s->sig, len);
		ptr += len;
		len = 0;
		s = s->next;
	}

	if (total_len > n-3) {
		fprintf(stderr, "Format string is too small to consume all"
						" signatures\n");
		return -1;
	}
	*ptr = ')';
	total_len++;
	ptr++;
	*ptr = '\0';

	return 0;
}

/**
	@function Calls method from df_list (using its name) with its arguments.
	@param value GVariant tuple containing all method arguments signatures and
	their values
	@return 0 on success, -1 on error
*/
static int df_fuzz_call_method(GVariant *value)
{
	GError *error = NULL;
	GVariant *response = NULL;

	// Synchronously invokes method with arguments stored in NULL terminated
	// linked list from df_list global variable on df_dproxy.
	// value (GVariant *) is consumed by g_dbus_proxy_call_sync().
	response = g_dbus_proxy_call_sync(df_dproxy,
		df_list.df_method_name,
		value, G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (response == NULL) {
		fprintf(stderr, "Call of g_dbus_proxy_call_sync() returned NULL"
						" pointer -- for '%s' method: %s\n",
						df_list.df_method_name, error->message);
		g_error_free(error);
		return -1;
	}

	g_variant_unref(response);
	return 0;
}

/**
	@function Releases memory used by this module. This function must be called
	after df_fuzz_add_method() and df_fuzz_add_method_arg() functions calls
	after the end of fuzz testing of each method.
*/
void df_fuzz_clean_method(void)
{
	free(df_list.df_method_name);

	// frees the linked list
	struct df_signature *tmp;
	while (df_list.list != NULL) {
		tmp = df_list.list->next;
		free(df_list.list->sig);
		free(df_list.list);
		df_list.list = tmp;
	}
}
