/** @file rand.h */
/*

	dfuzzer - tool for fuzzing processes communicating through D-Bus.
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

#define MINLEN 256				// minimal buffer size for generated strings
#define MAX_BUF_LEN 5000000		// maximum buffer size for generated strings,
								// default is cca 5 MB


/**
	@function Initializes global flag variables and seeds pseudo-random
	numbers generators.
	@param buf_size Maximum buffer size for generated strings (in Bytes)
*/
void df_rand_init(long buf_size);

/**
	@return Generated pseudo-random 8-bit unsigned integer value
*/
guint8 df_rand_guint8(void);

/**
	@return Generated pseudo-random boolean value
*/
gboolean df_rand_gboolean(void);

/**
	@return Generated pseudo-random 16-bit integer value
*/
gint16 df_rand_gint16(void);

/**
	@return Generated pseudo-random 16-bit unsigned integer value
*/
guint16 df_rand_guint16(void);

/**
	@return Generated pseudo-random 32-bit integer value
*/
gint32 df_rand_gint32(void);

/**
	@return Generated pseudo-random 32-bit unsigned integer value
*/
guint32 df_rand_guint32(void);

/**
	@return Generated pseudo-random 64-bit (long) integer value
*/
gint64 df_rand_gint64(void);

/**
	@return Generated pseudo-random 64-bit (long) unsigned integer value
*/
guint64 df_rand_guint64(void);

/**
	@return Generated pseudo-random double precision floating point number
	from interval <0, 1>
*/
inline double drand(void);

/**
	@return Generated pseudo-random double precision floating point number
*/
gdouble df_rand_gdouble(void);

/**
	@function Tells callee whether to continue testing according to current size
	of generated strings not to exceed df_buf_size length.
	@param fuzz_on_str_len If 1, fuzzing will be controlled by generated random
	strings lengths
	@return 1 when callee should continue, 0 otherwise
*/
int df_rand_continue(int fuzz_on_str_len);

/**
	@function Allocates memory for pseudo-random string of size counted
	by adding generated pseudo-random number from interval <0, CHAR_MAX>
	to df_str_len (this mechanism is responsible for generating bigger strings
	by every call of df_rand_string(). Then pseudo-random string is generated
	and stored int buf. Warning: buffer should be freed outside this module
	by callee of this function.
	@param buf Pointer on buffer where generated string will be stored
	@return 0 on success, -1 on error
*/
int df_rand_string(gchar **buf);

/**
	@function
*/
int df_rand_dbus_objpath_string(gchar **buf);

/**
	@function
*/
int df_rand_dbus_signature_string(gchar **buf);

/**
	@function
*/
int df_rand_GVariant(GVariant **var);

/**
	@function
*/
int df_rand_unixFD(void);

#endif
