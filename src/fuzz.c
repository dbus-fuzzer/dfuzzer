/** @file fuzz.c */
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
#include <gio/gio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <ffi.h>		// dynamic function call construction

#include "fuzz.h"
#include "dfuzzer.h"
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
static int df_unsupported_sig;
/** Pointer on unsupported signature string (do not free it) */
static char *df_unsupported_sig_str;


/* Module static functions */
static long df_fuzz_get_proc_mem_size(const int statfd);
static int df_fuzz_write_log(void);
static GVariant *df_fuzz_create_variant(void);
static int df_fuzz_create_list_variants(void);
static int df_fuzz_create_fmt_string(char **fmt, const int n);
static int df_fuzz_call_method(const GVariant *value, const int void_method);


/** Error checked write function with short write correction (when write
	is interrupted by a signal).
	@param fd File descriptor where to write
	@param buf Buffer from which to write to file descriptor fd
	@param count Number of bytes to be written
	@return 0 on success, -1 on error
*/
inline int df_ewrite(int fd, const void *buf, size_t count)
{
	ssize_t written = 0;
	do {
		written = write(fd, buf, count);
		if (written == count)
			break;
		if (written > 0) {
			buf += written;
			count -= written;
		}
	} while (written >= 0 || errno == EINTR);
	if (written < 0) {
		perror("write");
		return -1;
	}
	return 0;
}

/**
	@function Saves pointer on D-Bus interface proxy for this module to be
	able to call methods through this proxy during fuzz testing. Also saves
	process initial memory size to global var. df_initial_mem from file
	described by statfd.
	@param dproxy Pointer on D-Bus interface proxy
	@param statfd FD of process status file
	@param pid PID of tested process
	@param mem_limit Memory limit in kB - if tested process exceeds this limit
	it will be noted into log file
	@return 0 on success, -1 on error
*/
int df_fuzz_init(GDBusProxy *dproxy, const int statfd,
				const int pid, const long mem_limit)
{
	if (dproxy == NULL) {
		df_debug("Passing NULL argument to function.\n");
		return -1;
	}
	df_dproxy = dproxy;

	df_initial_mem = df_fuzz_get_proc_mem_size(statfd);
	if (df_initial_mem == -1) {
		df_fail("Error: Unable to get memory size of [PID:%d].\n", pid);
		df_debug("Error in df_fuzz_get_proc_mem_size()\n");
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
int df_fuzz_add_method(const char *name)
{
	if (name == NULL) {
		df_debug("Passing NULL argument to function.\n");
		return -1;
	}

	df_list.df_method_name = malloc(sizeof(char) * strlen(name) + 1);
	if (df_list.df_method_name == NULL) {
		df_fail("Error: Could not allocate memory for method name.\n");
		return -1;
	}
	strcpy(df_list.df_method_name, name);

	// must be initialized because after df_fuzz_clean_method() memory
	// of df_list contains junk
	df_list.list = NULL;	// no arguments so far
	df_list.args = 0;
	df_list.fuzz_on_str_len = 0;

	return 0;
}

/**
	@function Adds item (struct df_signature) at the end of the linked list
	in the global variable df_list (struct df_sig_list). This includes
	allocating memory for item and for signature string.
	@param signature D-Bus signature of the argument
	@return 0 on success, -1 on error
*/
int df_fuzz_add_method_arg(const char *signature)
{
	if (signature == NULL)
		return 0;

	struct df_signature *s;
	if ((s = malloc(sizeof(struct df_signature))) == NULL) {
		df_fail("Error: Could not allocate memory for struct df_signature.\n");
		return -1;
	}

	df_list.args++;
	s->next = NULL;
	s->var = NULL;
	s->sig = malloc(sizeof(char) * strlen(signature) + 1);
	if (s->sig == NULL) {
		df_fail("Error: Could not allocate memory for argument signature.\n");
		return -1;
	}
	strcpy(s->sig, signature);

	// fuzzing controlled by generated random strings lengths
	if (strstr(s->sig, "s") != NULL)
		df_list.fuzz_on_str_len = 1;
	if (strstr(s->sig, "v") != NULL)
		df_list.fuzz_on_str_len = 1;

	if (df_list.list == NULL) {
		df_list.list = s;
		df_last = s;
	} else {
		df_last->next = s;
		df_last = s;
	}

	return 0;
}

/**
	@return Number of arguments of tested method
*/
int df_list_args_count(void)
{
	return df_list.args;
}

/**
	@function Parses VmRSS (Resident Set Size) value from statfd and returns it
	as process memory size.
	@param statfd FD of process status file
	@return Process memory size on success, 0 when statfd is not readable (that
	means process exited: errno set to ESRCH - no such process) or -1 on error
*/
static long df_fuzz_get_proc_mem_size(const int statfd)
{
	long mem_size = -1;
	char buf[MAXLINE];	// buffer for reading from file
	char *ptr;			// pointer into buf buffer
	off_t ret;
	ssize_t n;

	// rewinds file position to the beginning
	ret = lseek(statfd, 0L, SEEK_SET);
	if (ret == ((off_t) -1) && errno == ESRCH)	// process exited
		return 0;
	else if (ret == -1)
		return -1;


	int stopr = 0;
	while (!stopr) {
		n = read(statfd, buf, MAXLINE - 1);
		if (n == -1 && errno == ESRCH)	// process exited
			return 0;
		else if (n == -1)
			return -1;
		else if (n == 0)
			stopr++;
		buf[n] = '\0';

		if ((ptr = strstr(buf, "VmRSS:")) == NULL)	// process exited
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

	mem_size = strtol(ptr, NULL, 10);
	if (errno == ERANGE || errno == EINVAL) {
		df_debug("Error on conversion of process memory to a long integer\n");
		return -1;
	}
	return mem_size;
}

/**
	@function Writes all method signatures and their values into the log file.
	//@param logfd FD of log file
	//@param buf_size Maximum buffer size for generated strings
	//by rand module (in Bytes)
	@return 0 on success, -1 on error
*/
static int df_fuzz_write_log(void)
{
	struct df_signature *s = df_list.list;	// pointer on first signature
	int len = 0;
	int str_len = 0;

	while (s != NULL) {
		len = strlen(s->sig);
		if (len <= 0) {
			fprintf(stderr, "No argument signature\n");
			return -1;
		} else if (len == 1) {	// one character argument
			df_fail("    --");
			df_fail("%s", s->sig);

			switch (s->sig[0]) {
			case 'y':
				;
				guint8 tmp;
				g_variant_get(s->var, s->sig, &tmp);
				df_fail("-- '%u'\n", tmp);
				break;
			case 'b':
				;
				gboolean tmp1;
				g_variant_get(s->var, s->sig, &tmp1);
				df_fail("-- '%s'\n", ((tmp1 == 1) ? "true" : "false"));
				break;
			case 'n':
				;
				gint16 tmp2;
				g_variant_get(s->var, s->sig, &tmp2);
				df_fail("-- '%d'\n", tmp2);
				break;
			case 'q':
				;
				guint16 tmp3;
				g_variant_get(s->var, s->sig, &tmp3);
				df_fail("-- '%u'\n", tmp3);
				break;
			case 'i':
				;
				gint32 tmp4;
				g_variant_get(s->var, s->sig, &tmp4);
				df_fail("-- '%d'\n", tmp4);
				break;
			case 'u':
				;
				guint32 tmp5;
				g_variant_get(s->var, s->sig, &tmp5);
				df_fail("-- '%u'\n", tmp5);
				break;
			case 'x':
				;
				gint64 tmp6;
				g_variant_get(s->var, s->sig, &tmp6);
				df_fail("-- '%ld'\n", tmp6);
				break;
			case 't':
				;
				guint64 tmp7;
				g_variant_get(s->var, s->sig, &tmp7);
				df_fail("-- '%lu'\n", tmp7);
				break;
			case 'd':
				;
				gdouble tmp8;
				g_variant_get(s->var, s->sig, &tmp8);
				df_fail("-- '%lg'\n", tmp8);
				break;
			case 's':
				;
				gchar *tmp9 = NULL;
				g_variant_get(s->var, s->sig, &tmp9);
				str_len = strlen(tmp9);
				if (tmp9 != NULL)
					df_fail(" [length: %d B]-- '%s'\n", str_len, tmp9);
				free(tmp9);
				break;
			case 'o':
				;
				gchar *tmp10 = NULL;
				g_variant_get(s->var, s->sig, &tmp10);
				str_len = strlen(tmp10);
				if (tmp10 != NULL)
					df_fail(" [length: %d B]-- '%s'\n", str_len, tmp10);
				free(tmp10);
				break;
			case 'g':
				;
				gchar *tmp11 = NULL;
				g_variant_get(s->var, s->sig, &tmp11);
				str_len = strlen(tmp11);
				if (tmp11 != NULL)
					df_fail(" [length: %d B]-- '%s'\n", str_len, tmp11);
				free(tmp11);
				break;
			case 'v':
				;
				GVariant *var = NULL;
				gchar *tmp12 = NULL;
				g_variant_get(s->var, s->sig, var);
				g_variant_get(var, "s", &tmp12);
				str_len = strlen(tmp12);
				if (tmp12 != NULL)
					df_fail(" [length: %d B]-- '%s'\n", str_len, tmp12);
				free(tmp12);
				break;
			case 'h':
				;
				gint32 tmp13;
				g_variant_get(s->var, s->sig, &tmp13);
				df_fail("-- '%d'\n", tmp13);
				break;
			default:
				fprintf(stderr, "Unknown argument signature '%s'\n", s->sig);
				return -1;
			}
		} else {	// advanced argument (array of something, dictionary, ...)
			fprintf(stderr, "Not yet implemented in df_fuzz_write_log()\n");
			return 0;
		}

		s = s->next;
	}

	return 0;
}

/**
	@function Function is testing a method in a cycle, each cycle generates
	data for function arguments, calls method and waits for result.
	@param statfd FD of process status file
	@param buf_size Maximum buffer size for generated strings
	by rand module (in Bytes)
	@param name D-Bus name
	@param obj D-Bus object path
	@param intf D-Bus interface
	@param pid PID of tested process
	@param one_method_test If set to 1, reinitialization of rand module
	is disabled, otherwise it is enabled
	@param void_method If method has out args 1, 0 otherwise
	@return 0 on success, -1 on error, 1 on tested process crash or 2 on void
	function returning non-void value
*/
int df_fuzz_test_method(const int statfd, long buf_size, const char *name,
						const char *obj, const char *intf, const int pid,
						const int one_method_test, const int void_method)
{
	// methods with no arguments are not tested
	if (df_list.args == 0)
		return 0;

	if (buf_size < MINLEN)
		buf_size = MAX_BUF_LEN;

	// when testing only one specific method (-t option), rand module
	// should not be reinitialized
	static int reinit_rand_module = 1;
	if (one_method_test == 1) {
		if (reinit_rand_module)
			df_rand_init(buf_size);		// initialization of random module
		reinit_rand_module = 0;
	}


	struct df_signature *s = df_list.list;	// pointer on the first signature
	GVariant *value = NULL;
	int ret;
	long used_memory = 0;				// memory size used by process in kB
	long prev_memory = 0;				// last known memory size
	long max_memory = df_mem_limit;		// maximum normal memory size used
										// by process in kB

	int j = 0;
	df_debug("  Method: \e[1m%s", df_list.df_method_name);
	df_debug("(");
	for (; j < df_list.args; j++, s = s->next)
		df_debug(((j < df_list.args - 1) ? "%s, " : "%s"), s->sig);
	df_debug(")\e[0m\n");


	if (reinit_rand_module)
		df_rand_init(buf_size);		// initialization of random module


	while (df_rand_continue(df_list.fuzz_on_str_len)) {
		// parsing proces memory size from its status file described by statfd
		used_memory = df_fuzz_get_proc_mem_size(statfd);
		if (used_memory == -1) {
			df_fail("Error: Unable to get memory size of [PID:%d].\n", pid);
			df_debug("Error in df_fuzz_get_proc_mem_size()\n");
			goto err_label;
		}
		if (used_memory == 0) {
			df_fail("  \e[31mFAIL\e[0m method %s - process exited [PID: %d],"
					"[MEM: %ld kB]\n", df_list.df_method_name, pid, prev_memory);
			goto fail_label;
		}
		prev_memory = used_memory;

		// creates variant containing all (fuzzed) method arguments
		if ((value = df_fuzz_create_variant()) == NULL) {
			if (df_unsupported_sig) {
				df_unsupported_sig = 0;
				df_debug("  unsupported argument by dfuzzer: ");
				df_debug("%s\n", df_unsupported_sig_str);
				df_unsupported_sig_str = NULL;
				goto skip_label;
			}
			df_debug("Call of df_fuzz_create_variant() returned"
					" NULL pointer\n");
			goto err_label;
		}

		ret = df_fuzz_call_method(value, void_method);
		if (ret == -1) {
			// Here we look at process status file to be sure it really
			// exited. If file is readable it means process is
			// processing long string(s) and that is the reason it
			// didn't respond so we continue.
			used_memory = df_fuzz_get_proc_mem_size(statfd);
			if (used_memory == 0) {			// process exited
				df_fail("  \e[31mFAIL\e[0m method %s - process exited "
						"[PID: %d],[MEM: %ld kB]\n",
						df_list.df_method_name, pid, prev_memory);
				goto fail_label;
			} else if (used_memory == -1) {	// error on reading process status
				df_fail("Error: Unable to get memory size of [PID:%d].\n", pid);
				df_debug("Error in df_fuzz_get_proc_mem_size()\n");
				goto err_label;
			}
			// else continue, we managed to get process memory size
			prev_memory = used_memory;
		} else if (ret == 1) {
			// method returning void is returning illegal value
			goto fail_label;
		}

		// process memory size exceeded maximum normal memory size
		// (this is just a warning message)
		if (used_memory >= max_memory) {
			df_fail("  \e[35mWARN\e[0m method %s - [INIT.MEM: %ld kB],"
					"[CUR.MEM: %ld kB]\n", df_list.df_method_name,
					df_initial_mem, used_memory);
			max_memory = used_memory * 2;
		}

		if (value != NULL) {
			g_variant_unref(value);
			value = NULL;
		}
	}


	// test passed
	if (one_method_test != 1)
		df_verbose("  \e[32mPASS\e[0m method %s\n", df_list.df_method_name);
	return 0;


fail_label:
	if (ret == 1) {		// method returning void is returning illegal value
		df_fail("   reproducer: \e[33mdfuzzer -v -n %s -o %s -i %s"
				" -t %s \e[0m\n", name, obj, intf, df_list.df_method_name);
		if (value != NULL)
			g_variant_unref(value);
		return 2;
	}
	df_fail("   on input:\n");
	df_fuzz_write_log();
	df_fail("   reproducer: \e[33mdfuzzer -v -n %s -o %s -i %s"
			" -t %s \e[0m\n", name, obj, intf, df_list.df_method_name);
	if (value != NULL)
		g_variant_unref(value);
	return 1;


skip_label:
	df_verbose("  \e[34mSKIP\e[0m method %s - advanced signatures"
			" not yet implemented\n", df_list.df_method_name);
	if (value != NULL)
		g_variant_unref(value);
	return 0;


err_label:
	if (value != NULL)
		g_variant_unref(value);
	return -1;
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
static GVariant *df_fuzz_create_variant(void)
{
	struct df_signature *s = df_list.list;	// pointer on first signature

	// creates GVariant for every item signature in linked list
	int ret = df_fuzz_create_list_variants();
	if (ret == -1) {
		df_debug("Error in df_fuzz_create_list_variants()\n");
		return NULL;
	} else if (ret == 1) {		// unsupported method signature
		df_unsupported_sig++;
		return NULL;
	}

	// libffi part, to construct dynamic call of g_variant_new() on runtime
	GVariant *val = NULL;
	ffi_cif cif;

	// MAXSIG = max. amount of D-Bus signatures + 1 (format string)
	ffi_type *args[MAXSIG + 1];
	void *values[MAXSIG + 1];
	char *fmt;		// format string
	int i;

	if ((fmt = malloc(MAXFMT + 1)) == NULL) {
		df_fail("Error: Could not allocate memory for format string.\n");
		return NULL;
	}
	// creates the format string for g_variant_new() function call
	if (df_fuzz_create_fmt_string(&fmt, MAXFMT + 1) == -1) {
		df_fail("Error: Unable to create format string.\n");
		df_debug("Error in df_fuzz_create_fmt_string()\n");
		return NULL;
	}

	/*#ifdef DEBUG
	   printf("fmt string: [%s]\nargs: [%d]\n\n", fmt, df_list.args);
	   #endif */

	// Initialize the argument info vectors
	args[0] = &ffi_type_pointer;
	values[0] = &fmt;
	for (i = 1; i <= df_list.args && s != NULL; i++) {
		args[i] = &ffi_type_pointer;
		values[i] = &(s->var);
		s = s->next;
	}

	// Initialize the cif
	if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, df_list.args + 1,
		&ffi_type_pointer, args) == FFI_OK) {
		ffi_call(&cif, g_variant_new, &val, values);
		// val now holds the result of the call to g_variant_new().
		// When val will be freed, all the floating Gvariants which
		// was used to create it will be freed too, because val is
		// their owner
	} else {
		df_fail("ffi_prep_cif() failed on initializing cif.\n");
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
		df_fail("Error: Unable to convert GVariant from floating to normal"
				" reference\n(for method '%s()'.\n", df_list.df_method_name);
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
	struct df_signature *s = df_list.list;	// pointer on first signature
	int len;

	while (s != NULL) {
		len = strlen(s->sig);
		if (len <= 0) {
			df_debug("df_fuzz_create_list_variants(): No argument signature\n");
			return -1;
		} else if (len == 1) {		// one character argument
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
				s->var =
					g_variant_new(s->sig, df_rand_gdouble());
				break;
			case 's':
				;
				gchar *buf;
				if (df_rand_string(&buf) == -1) {
					df_debug("In df_rand_string()\n");
					return -1;
				}
				s->var = g_variant_new(s->sig, buf);
				free(buf);
				break;
			case 'o':
				;
				gchar *obj;
				if (df_rand_dbus_objpath_string(&obj) == -1) {
					df_debug("In df_rand_dbus_objpath_string()\n");
					return -1;
				}
				s->var = g_variant_new(s->sig, obj);
				free(obj);
				break;
			case 'g':
				;
				gchar *sig;
				if (df_rand_dbus_signature_string(&sig) == -1) {
					df_debug("In df_rand_dbus_signature_string()\n");
					return -1;
				}
				s->var = g_variant_new(s->sig, sig);
				free(sig);
				break;
			case 'v':
				;
				GVariant *var;
				if (df_rand_GVariant(&var) == -1) {
					df_debug("In df_rand_GVariant()\n");
					return -1;
				}
				s->var = g_variant_new(s->sig, var);
				break;
			case 'h':
				s->var = g_variant_new(s->sig, df_rand_unixFD());
				break;
			default:
				df_debug("Unknown argument signature '%s'\n", s->sig);
				return -1;
			}
		} else {	// advanced argument (array of something, dictionary, ...)
			// fprintf(stderr, "Advanced signatures not yet implemented\n");
			df_unsupported_sig_str = s->sig;
			return 1;	// unsupported method signature
		}

		if (s->var == NULL) {
			df_fail("Error: Failed to construct GVariant for '%s' signature"
					"of method '%s'\n",	s->sig, df_list.df_method_name);
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
static int df_fuzz_create_fmt_string(char **fmt, const int n)
{
	struct df_signature *s = df_list.list;	// pointer on first signature
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
		if (total_len > (n - 3)) {
			df_debug("Format string is too small to consume all signatures\n");
			return -1;
		}
		*ptr = '@';
		ptr++;
		memcpy(ptr, s->sig, len);
		ptr += len;
		len = 0;
		s = s->next;
	}

	if (total_len > (n - 3)) {
		df_debug("Format string is too small to consume all signatures\n");
		return -1;
	}
	*ptr = ')';
	ptr++;
	*ptr = '\0';

	return 0;
}

/**
	@function Calls method from df_list (using its name) with its arguments.
	@param value GVariant tuple containing all method arguments signatures and
	their values
	@param void_method If method has out args 1, 0 otherwise
	@return 0 on success, -1 on error or 1 if void method returned non-void
	value
*/
static int df_fuzz_call_method(const GVariant *value, const int void_method)
{
	GError *error = NULL;
	GVariant *response = NULL;
	gchar *dbus_error = NULL;
	char *fmt;


	// Synchronously invokes method with arguments stored in value (GVariant *)
	// on df_dproxy.
	response = g_dbus_proxy_call_sync(df_dproxy,
					df_list.df_method_name,
					value, G_DBUS_CALL_FLAGS_NONE, -1,
					NULL, &error);
	if (response == NULL) {
		// D-Bus exceptions are accepted
		if ((dbus_error = g_dbus_error_get_remote_error(error)) != NULL) {
			// if process does not respond
			if (strcmp(dbus_error, "org.freedesktop.DBus.Error.NoReply") == 0) {
				g_free(dbus_error);
				g_error_free(error);
				return -1;
			}
			g_free(dbus_error);
		}

		g_dbus_error_strip_remote_error(error);
		df_debug("  \e[32mPASS\e[0m method %s - D-Bus exception thrown: "
			"%s\n", df_list.df_method_name, error->message);
		g_error_free(error);
		return 0;
	} else {
		if (void_method) {
			fmt = g_variant_get_type_string(response);
			// void function can only return empty tuple
			if (strcmp(fmt, "()") != 0) {
				df_fail("  \e[31mFAIL\e[0m method %s - void method returns"
						" '%s' instead of '()'\n", df_list.df_method_name, fmt);
				g_variant_unref(response);
				return 1;
			}
		}
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
