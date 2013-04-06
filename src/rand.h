/** @file rand.h *//*

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
#ifndef RAND_H
#define RAND_H

/** @function Initializes global flag variables and seeds pseudo-random
	numbers generators.
*/
void df_rand_init(void);

/** @return Generated pseudo-random 8-bit unsigned integer value
*/
guint8 df_rand_guint8(void);

/** @return Generated pseudo-random boolean value
*/
gboolean df_rand_gboolean(void);

/** @return Generated pseudo-random 16-bit integer value
*/
gint16 df_rand_gint16(void);

/** @return Generated pseudo-random 16-bit unsigned integer value
*/
guint16 df_rand_guint16(void);

/** @return Generated pseudo-random 32-bit integer value
*/
gint32 df_rand_gint32(void);

/** @return Generated pseudo-random 32-bit unsigned integer value
*/
guint32 df_rand_guint32(void);

/** @return Generated pseudo-random 64-bit (long) integer value
*/
gint64 df_rand_gint64(void);

/** @return Generated pseudo-random 64-bit (long) unsigned integer value
*/
guint64 df_rand_guint64(void);

/** @return Generated pseudo-random double precision floating point number
	from interval <0, 1>
*/
inline double drand();

/** @return Generated pseudo-random double precision floating point number
*/
gdouble df_rand_gdouble(void);

/** @function Allocates memory for pseudo-random string of size counted
	by adding generated pseudo-random number from interval <0, CHAR_MAX>
	to df_str_len (this mechanism is responsible for generating bigger strings
	by every call of df_rand_string(). Then pseudo-random string is generated
	and stored int buf. Warning: buffer should be freed outside this module
	by callee of this function.
	@param buf Pointer on buffer where will be stored generated string
	@return 0 on success, -1 on error
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
