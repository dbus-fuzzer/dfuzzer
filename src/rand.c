/** @file rand.c *//*

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
#include <limits.h>
#include <time.h>

#include "rand.h"


static guint8 df_gu8;
static unsigned short df_gu8f;
static gboolean df_gb;
static unsigned short df_gbf;
static gint16 df_gi16;
static unsigned short df_gi16f;
static guint16 df_gu16;
static unsigned short df_gu16f;
static gint32 df_gi32;
static unsigned short df_gi32f;
static guint32 df_gu32;
static unsigned short df_gu32f;
static gint64 df_gi64;
static unsigned short df_gi64f;
static guint64 df_gu64;
static unsigned short df_gu64f;
static gdouble df_gdou;
static unsigned short df_gdouf;

// strings
static int df_str_len;


/** @function
*/
void df_rand_init(void)
{
	srand(time(NULL));		// for int rand()
	srandom(time(NULL));	// for long int random()

	df_gu8 = 0;
	df_gu8f = 0;
	df_gb = 0;
	df_gbf = 0;
	df_gi16 = 0;
	df_gi16f = 0;
	df_gu16 = 0;
	df_gu16f = 0;
	df_gi32 = 0;
	df_gi32f = 0;
	df_gu32 = 0;
	df_gu32f = 0;
	df_gi64 = 0;
	df_gi64f = 0;
	df_gu64 = 0;
	df_gu64f = 0;
	df_gdou = 0;
	df_gdouf = 0;

	df_str_len = 0;
}

/** @function
*/
guint8 df_rand_guint8(void)
{
	if (df_gu8f < 20)
		df_gu8 = G_MAXUINT8;
	else if (df_gu8f < 40)
		df_gu8 = G_MAXUINT8 / 2;
	else if (df_gu8f < 50)
		df_gu8 = 0;
	else {
		df_gu8 = rand() % G_MAXUINT8;
		if ((rand() % 2) == 0)
			df_gu8++;
	}

	if (df_gu8f < USHRT_MAX)
		df_gu8f++;
	else
		df_gu8f = 0;

	return df_gu8;
}

/** @function
*/
gboolean df_rand_gboolean(void)
{
	return ((gboolean) (rand() % 2));
}

/** @function
*/
gint16 df_rand_gint16(void)
{
	if (df_gi16f < 20)
		df_gi16 = G_MAXINT16;
	else if (df_gi16f < 40)
		df_gi16 = G_MAXINT16 / 2;
	else if (df_gi16f < 50)
		df_gi16 = 0;
	else {
		df_gi16 = rand() % G_MAXINT16;
		if ((rand() % 2) == 0)
			df_gi16++;
	}

	// makes sure to test negative numbers
	if ((rand() % 2) == 0)
		df_gi16 = (df_gi16 * -1) - 1;

	if (df_gi16f < USHRT_MAX)
		df_gi16f++;
	else
		df_gi16f = 0;

	return df_gi16;
}

/** @function
*/
guint16 df_rand_guint16(void)
{
	if (df_gu16f < 20)
		df_gu16 = G_MAXUINT16;
	else if (df_gu16f < 40)
		df_gu16 = G_MAXUINT16 / 2;
	else if (df_gu16f < 50)
		df_gu16 = 0;
	else {
		df_gu16 = rand() % G_MAXUINT16;
		if ((rand() % 2) == 0)
			df_gu16++;
	}

	if (df_gu16f < USHRT_MAX)
		df_gu16f++;
	else
		df_gu16f = 0;

	return df_gu16;
}

/** @function
*/
gint32 df_rand_gint32(void)
{
	if (df_gi32f < 20)
		df_gi32 = G_MAXINT32;
	else if (df_gi32f < 40)
		df_gi32 = G_MAXINT32 / 2;
	else if (df_gi32f < 50)
		df_gi32 = 0;
	else {
		df_gi32 = rand() % G_MAXINT32;
		if ((rand() % 2) == 0)
			df_gi32++;
	}

	// makes sure to test negative numbers
	if ((rand() % 2) == 0)
		df_gi32 = (df_gi32 * -1) - 1;

	if (df_gi32f < USHRT_MAX)
		df_gi32f++;
	else
		df_gi32f = 0;

	return df_gi32;
}

/** @function
*/
guint32 df_rand_guint32(void)
{
	if (df_gu32f < 20)
		df_gu32 = G_MAXUINT32;
	else if (df_gu32f < 40)
		df_gu32 = G_MAXUINT32 / 2;
	else if (df_gu32f < 50)
		df_gu32 = 0;
	else {
		df_gu32 = random() % G_MAXUINT32;
		if ((rand() % 2) == 0)
			df_gu32++;
	}

	if (df_gu32f < USHRT_MAX)
		df_gu32f++;
	else
		df_gu32f = 0;

	return df_gu32;
}

/** @function
*/
gint64 df_rand_gint64(void)
{
	if (df_gi64f < 20)
		df_gi64 = G_MAXINT64;
	else if (df_gi64f < 40)
		df_gi64 = G_MAXINT64 / 2;
	else if (df_gi64f < 50)
		df_gi64 = 0;
	else {
		df_gi64 = random() % G_MAXINT64;
		if ((rand() % 2) == 0)
			df_gi64++;
	}

	// makes sure to test negative numbers
	if ((rand() % 2) == 0)
		df_gi64 = (df_gi64 * -1) - 1;

	if (df_gi64f < USHRT_MAX)
		df_gi64f++;
	else
		df_gi64f = 0;

	return df_gi64;
}

/** @function
*/
guint64 df_rand_guint64(void)
{
	if (df_gu64f < 20)
		df_gu64 = G_MAXUINT64;
	else if (df_gu64f < 40)
		df_gu64 = G_MAXUINT64 / 2;
	else if (df_gu64f < 50)
		df_gu64 = 0;
	else {
		df_gu64 = random() % G_MAXUINT64;
		if ((rand() % 2) == 0)
			df_gu64++;
	}

	if (df_gu64f < USHRT_MAX)
		df_gu64f++;
	else
		df_gu64f = 0;

	return df_gu64;
}

/** @function
*/
inline double drand() { return ((double) rand() / RAND_MAX); }

/** @function
*/
gdouble df_rand_gdouble(void)
{
	if (df_gdouf < 20)
		df_gdou = G_MAXDOUBLE;
	else if (df_gdouf < 40)
		df_gdou = G_MAXDOUBLE / 2.0;
	else if (df_gdouf < 50)
		df_gdou = 0.0;
	else if (df_gdouf < 70)
		df_gdou = G_MINDOUBLE;
	else {
		df_gdou = (double) random();
		df_gdou += drand();
		if ((rand() % 2) == 0)
			df_gdou++;
	}

	if (df_gdou != 0.0 && (rand() % 2) == 0)
		df_gdou *= -1.0;

	if (df_gdouf < USHRT_MAX)
		df_gdouf++;
	else
		df_gdouf = 0;

	return df_gdou;
}

/** @function Generates pseudo-random string of size size.
	@param buf Pointer on buffer where random string will be stored
	@param size Size of buffer
*/
void df_rand_random_string(char *buf, int size)
{
	int i;
	int n = size - 1;		// number of generated characters

	for (i = 0; i < n; ++i)
		buf[i] = rand() % (127 - 32) + 32;	// only printable characters
	buf[i] = '\0';
}

/** @function
*/
int df_rand_string(gchar **buf)
{
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
