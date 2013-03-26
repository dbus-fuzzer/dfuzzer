/** @file rand.h *//*

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
#ifndef RAND_H
#define RAND_H

/** @function
*/
void df_rand_init(void);

/** @function
*/
guint8 df_rand_guint8(void);

/** @function
*/
gboolean df_rand_gboolean(void);

/** @function
*/
gint16 df_rand_gint16(void);

/** @function
*/
guint16 df_rand_guint16(void);

/** @function
*/
gint32 df_rand_gint32(void);

/** @function
*/
guint32 df_rand_guint32(void);

/** @function
*/
gint64 df_rand_gint64(void);

/** @function
*/
guint64 df_rand_guint64(void);

/** @function
*/
gdouble df_rand_gdouble(void);

/** @function Generates pseudo-random string of size size.
	@param buf Pointer on buffer where random string will be stored
	@param size Size of buffer
*/
void df_rand_random_string(char *buf, int size);

/** @function
*/
int df_rand_string(gchar **buf);

/** @function
*/
int df_rand_dbus_objpath_string(gchar **buf);

/** @function
*/
int df_rand_dbus_signature_string(gchar **buf);

/** @function
*/
int df_rand_GVariant(GVariant **var);

/** @function
*/
int df_rand_unixFD(void);

#endif
