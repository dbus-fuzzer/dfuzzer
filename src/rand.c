/** @file rand.c *//*

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
#include <limits.h>
#include <time.h>

#include "rand.h"


/* Flag variables for controlling pseudo-random numbers generation */
static unsigned short df_gu8f;
static unsigned short df_gi16f;
static unsigned short df_gu16f;
static unsigned short df_gi32f;
static unsigned short df_gu32f;
static unsigned short df_gi64f;
static unsigned short df_gu64f;
static unsigned short df_gdouf;

/* Lengths of  pseudo-random strings */
static int df_str_len;


/** @function Generates pseudo-random string of size size.
	@param buf Pointer on buffer where will be stored generated string
	@param size Size of buffer
*/
static void df_rand_random_string(char *buf, int size);

/** @function Initializes global flag variables and seeds pseudo-random
	numbers generators.
*/
void df_rand_init(void)
{
	srand(time(NULL));		// for int rand()
	srandom(time(NULL));	// for long int random()

	df_gu8f = 0;
	df_gi16f = 0;
	df_gu16f = 0;
	df_gi32f = 0;
	df_gu32f = 0;
	df_gi64f = 0;
	df_gu64f = 0;
	df_gdouf = 0;

	df_str_len = 0;
}

/** @return Generated pseudo-random 8-bit unsigned integer value
*/
guint8 df_rand_guint8(void)
{
	guint8 gu8;

	if (df_gu8f < 20)
		gu8 = G_MAXUINT8;
	else if (df_gu8f < 40)
		gu8 = G_MAXUINT8 / 2;
	else if (df_gu8f < 50)
		gu8 = 0;
	else {
		gu8 = rand() % G_MAXUINT8;
		if ((rand() % 2) == 0)
			gu8++;
	}

	if (df_gu8f < USHRT_MAX)
		df_gu8f++;
	else
		df_gu8f = 0;

	return gu8;
}

/** @return Generated pseudo-random boolean value
*/
gboolean df_rand_gboolean(void)
{
	return ((gboolean) (rand() % 2));
}

/** @return Generated pseudo-random 16-bit integer value
*/
gint16 df_rand_gint16(void)
{
	gint16 gi16;

	if (df_gi16f < 20)
		gi16 = G_MAXINT16;
	else if (df_gi16f < 40)
		gi16 = G_MAXINT16 / 2;
	else if (df_gi16f < 50)
		gi16 = 0;
	else {
		gi16 = rand() % G_MAXINT16;
		if ((rand() % 2) == 0)
			gi16++;
	}

	// makes sure to test negative numbers
	if ((rand() % 2) == 0)
		gi16 = (gi16 * -1) - 1;

	if (df_gi16f < USHRT_MAX)
		df_gi16f++;
	else
		df_gi16f = 0;

	return gi16;
}

/** @return Generated pseudo-random 16-bit unsigned integer value
*/
guint16 df_rand_guint16(void)
{
	guint16 gu16;

	if (df_gu16f < 20)
		gu16 = G_MAXUINT16;
	else if (df_gu16f < 40)
		gu16 = G_MAXUINT16 / 2;
	else if (df_gu16f < 50)
		gu16 = 0;
	else {
		gu16 = rand() % G_MAXUINT16;
		if ((rand() % 2) == 0)
			gu16++;
	}

	if (df_gu16f < USHRT_MAX)
		df_gu16f++;
	else
		df_gu16f = 0;

	return gu16;
}

/** @return Generated pseudo-random 32-bit integer value
*/
gint32 df_rand_gint32(void)
{
	gint32 gi32;

	if (df_gi32f < 20)
		gi32 = G_MAXINT32;
	else if (df_gi32f < 40)
		gi32 = G_MAXINT32 / 2;
	else if (df_gi32f < 50)
		gi32 = 0;
	else {
		gi32 = rand() % G_MAXINT32;
		if ((rand() % 2) == 0)
			gi32++;
	}

	// makes sure to test negative numbers
	if ((rand() % 2) == 0)
		gi32 = (gi32 * -1) - 1;

	if (df_gi32f < USHRT_MAX)
		df_gi32f++;
	else
		df_gi32f = 0;

	return gi32;
}

/** @return Generated pseudo-random 32-bit unsigned integer value
*/
guint32 df_rand_guint32(void)
{
	guint32 gu32;

	if (df_gu32f < 20)
		gu32 = G_MAXUINT32;
	else if (df_gu32f < 40)
		gu32 = G_MAXUINT32 / 2;
	else if (df_gu32f < 50)
		gu32 = 0;
	else {
		gu32 = random() % G_MAXUINT32;
		if ((rand() % 2) == 0)
			gu32++;
	}

	if (df_gu32f < USHRT_MAX)
		df_gu32f++;
	else
		df_gu32f = 0;

	return gu32;
}

/** @return Generated pseudo-random 64-bit (long) integer value
*/
gint64 df_rand_gint64(void)
{
	gint64 gi64;

	if (df_gi64f < 20)
		gi64 = G_MAXINT64;
	else if (df_gi64f < 40)
		gi64 = G_MAXINT64 / 2;
	else if (df_gi64f < 50)
		gi64 = 0;
	else {
		gi64 = random() % G_MAXINT64;
		if ((rand() % 2) == 0)
			gi64++;
	}

	// makes sure to test negative numbers
	if ((rand() % 2) == 0)
		gi64 = (gi64 * -1) - 1;

	if (df_gi64f < USHRT_MAX)
		df_gi64f++;
	else
		df_gi64f = 0;

	return gi64;
}

/** @return Generated pseudo-random 64-bit (long) unsigned integer value
*/
guint64 df_rand_guint64(void)
{
	guint64 gu64;

	if (df_gu64f < 20)
		gu64 = G_MAXUINT64;
	else if (df_gu64f < 40)
		gu64 = G_MAXUINT64 / 2;
	else if (df_gu64f < 50)
		gu64 = 0;
	else {
		gu64 = random() % G_MAXUINT64;
		if ((rand() % 2) == 0)
			gu64++;
	}

	if (df_gu64f < USHRT_MAX)
		df_gu64f++;
	else
		df_gu64f = 0;

	return gu64;
}

/** @return Generated pseudo-random double precision floating point number
	from interval <0, 1>
*/
inline double drand()
{
	return ((double) rand() / RAND_MAX);
}

/** @return Generated pseudo-random double precision floating point number
*/
gdouble df_rand_gdouble(void)
{
	gdouble gdou;

	if (df_gdouf < 20)
		gdou = G_MAXDOUBLE;
	else if (df_gdouf < 40)
		gdou = G_MAXDOUBLE / 2.0;
	else if (df_gdouf < 50)
		gdou = 0.0;
	else if (df_gdouf < 70)
		gdou = G_MINDOUBLE;
	else {
		gdou = (double) random();
		gdou += drand();
		if ((rand() % 2) == 0)
			gdou++;
	}

	if (gdou != 0.0 && (rand() % 2) == 0)
		gdou *= -1.0;

	if (df_gdouf < USHRT_MAX)
		df_gdouf++;
	else
		df_gdouf = 0;

	return gdou;
}

/** @function Generates pseudo-random string of size size.
	@param buf Pointer on buffer where will be stored generated string
	@param size Size of buffer
*/
static void df_rand_random_string(char *buf, int size)
{
	int i;
	int n = size - 1;		// number of generated characters

	for (i = 0; i < n; ++i)
		buf[i] = rand() % (127 - 32) + 32;	// only printable characters
	buf[i] = '\0';
}

/** @function Allocates memory for pseudo-random string of size counted
	by adding generated pseudo-random number from interval <0, CHAR_MAX>
	to df_str_len (this mechanism is responsible for generating bigger strings
	by every call of df_rand_string(). Then pseudo-random string is generated
	and stored int buf. Warning: buffer should be freed outside this module
	by callee of this function.
	@param buf Pointer on buffer where will be stored generated string
	@return 0 on success, -1 on error
*/
int df_rand_string(gchar **buf)
{
	// TODO: add %n (+ other fmt strings) and similar stuff
	df_str_len += (rand() % CHAR_MAX) + 1;

	*buf = malloc(sizeof(gchar) * df_str_len);
	if (*buf == NULL) {
		fprintf(stderr, "Unable to allocate memory for random string\n");
		return -1;
	}

	df_rand_random_string(*buf, df_str_len);

	return 0;
}

/** @function
*/
int df_rand_dbus_objpath_string(gchar **buf)
{
	*buf = 0;
	return 0;
}

/** @function
*/
int df_rand_dbus_signature_string(gchar **buf)
{
	*buf = 0;
	return 0;
}

/** @function
*/
int df_rand_GVariant(GVariant **var)
{
	*var = g_variant_new("s", "fooo");
	return 0;
}

/** @function
*/
int df_rand_unixFD(void)
{
	return 2;	// FD for stderr
}
