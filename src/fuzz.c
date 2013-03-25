/** @file fuzz.c *//*

	dfuzzer - tool for testing applications communicating through D-Bus.
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
#include <ffi.h>		// dynamic function call construction

#include "fuzz.h"


/** Pointer on D-Bus interface proxy for calling methods. */
static GDBusProxy *df_dproxy;

/** Structure containing information about the linked list. */
static struct df_sig_list df_list;

/** Pointer on the last item of the linked list in the global var. df_list. */
static struct df_signature *df_last;


/** @function Saves pointer on D-Bus interface proxy for this module to be
	able to call methods through this proxy during fuzz testing.
	@param dproxy Pointer on D-Bus interface proxy
	@return 0 on success, -1 on error
*/
int df_fuzz_add_proxy(GDBusProxy *dproxy)
{
	if (dproxy == NULL) {
		fprintf(stderr, "Passing NULL argument to function.\n");
		return -1;
	}
	df_dproxy = dproxy;
	return 0;
}

/** @function Initializes the global variable df_list (struct df_sig_list)
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

/** @function Adds item (struct df_signature) at the end of the linked list
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

/** @function Function is testing a method in cycle, each cycle generates data
	for function arguments, calls method and waits for result.
	@return 0 on success, -1 on error
*/
int df_fuzz_test_method(void)
{
	GVariant *value = NULL;

	#ifdef DEBUG
		struct df_signature *s = df_list.list;		// pointer on first signature
		printf("Test of method\t\t%s(", df_list.df_method_name);
		int i;
		for (i = 0; i < df_list.args; i++, s = s->next)
			printf( ((i < df_list.args-1) ? "%s, " : "%s"), s->sig);
		printf(")\n");
	#endif

	// TODO: put this code into cycle (hint: rand module)
	// XXX
	// creates variant containing (fuzzed) method arguments
	if ( (value = df_fuzz_create_variant()) == NULL) {
		fprintf(stderr, "Call of df_fuzz_create_variant() returned NULL pointer\n");
		return -1;
	}

	df_fuzz_call_method(value);
	// XXX

	return 0;
}

/** @function Creates GVariant tuple variable which contains all the signatures
	of method arguments including their values. This tuple is constructed
	from each signature of method argument by one call of g_variant_new()
	function. This call is constructed dynamically (using libffi) as we don't
	know number of function parameters on compile time.
	@return Pointer on a new GVariant variable containing tuple with method
	arguments
*/
GVariant * df_fuzz_create_variant(void)
{
	struct df_signature *s = df_list.list;		// pointer on first signature

	// creates GVariant for every item signature in linked list
	if (df_fuzz_create_list_variants() == -1) {
		fprintf(stderr, "Error in df_fuzz_create_list_variants()\n");
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
		printf("\nfmt string: [%s]\n\n", fmt);
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

	free(fmt);
	return val;
}

/** @function Generates data for each method argument according to argument
	signature and stores it into Gvariant variable in items of linked list.
	@return 0 on success, -1 on error
*/
int df_fuzz_create_list_variants(void)
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
				// TODO: overwrite with functions for random data generation
				case 's':
					s->var = g_variant_new(s->sig, "fooooofoooo");
					break;
				case 'i':
					s->var = g_variant_new("i", 1024);
					break;
				// case for every signature ...
				default:
					fprintf(stderr, "Unknown argument signature '%s'\n", s->sig);
					return -1;
			}
		}
		else {	// advanced argument (array of something, dictionary, ...)
			;
		}
		s = s->next;
	}

	return 0;
}

/** @function Creates format string (tuple) from method arguments signatures
	with maximum length of n-1. The final string is saved in parameter fmt.
	@return 0 on success, -1 on error
*/
int df_fuzz_create_fmt_string(char **fmt, int n)
{
	struct df_signature *s = df_list.list;		// pointer on first signature
	int total_len = 0;
	int len = 0;
	char *ptr = *fmt;

	// final fmt string, for example may look like this: "(@s@i)"
	memcpy(ptr, "(", 1);
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
		memcpy(ptr, "@", 1);
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
	memcpy(ptr, ")", 1);
	total_len++;
	ptr++;
	ptr = "0";

	return 0;
}

/** @function Calls method from df_list (using its name) with its arguments.
	@param value GVariant tuple containing all method arguments signatures and
	their values
	@return 0 on success, -1 on error
*/
int df_fuzz_call_method(GVariant *value)
{
	GVariant *response;

	// Synchronously invokes method with arguments stored in NULL terminated
	// linked list from df_list global variable on df_dproxy.
	// value (GVariant *) is consumed by g_dbus_proxy_call_sync().
	// XXX: this hangs, when own server doesn't send response (try dbus apps)
	response = g_dbus_proxy_call_sync(df_dproxy,
		df_list.df_method_name,
		value, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);
	if (response == NULL) {
		fprintf(stderr, "Call of g_dbus_proxy_call_sync() returned NULL"
						" pointer -- for '%s' method\n", df_list.df_method_name);
		return -1;
	}

	g_variant_unref(response);
	return 0;
}

/** @function Releases memory used by this module. This function must be called
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
		// free also df_list.list->var ?? -- probably not
		free(df_list.list);
		df_list.list = tmp;
	}
}
