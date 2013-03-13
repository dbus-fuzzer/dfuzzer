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
*/
void df_fuzz_add_proxy(GDBusProxy *dproxy)
{
	df_dproxy = dproxy;
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

/** @function
*/
void df_fuzz_test_method()
{
	#ifdef DEBUG
		printf("Test of method\t\t%s(", df_list.df_method_name);
		int i;
		struct df_signature *s = df_list.list;
		for (i = 0; i < df_list.args; i++, s = s->next)
			printf( ((i < df_list.args-1) ? "%s, " : "%s"), s->sig);
		printf(")\n");
	#endif
/*
XXX: Like this:

GVariant *value1, *value2;

value1 = g_variant_new ("(s(ii))", "Hello", 55, 77);
value2 = g_variant_new ("()");

{
  gchar *string;
  gint x, y;

  g_variant_get (value1, "(s(ii))", &string, &x, &y);
  g_print ("%s, %d, %d\n", string, x, y);
  g_free (string);

  g_variant_get (value2, "()");   // do nothing...
}

XXX: parameters for method will be constructed by calling functions from
	 module rand.o instead of the g_variant_new params.
*/
}

/** @function Releases memory used by this module. This function must be called
	after df_fuzz_add_method() and df_fuzz_add_method_arg() functions calls
	after the end of fuzz testing.
*/
void df_fuzz_clean_method()
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
