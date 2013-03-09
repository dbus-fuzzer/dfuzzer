/** @file df_lib.c *//*

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "df_lib.h"

/** @function Displays an error message and exits with error code 1.
	@param message Error message which will be printed before exiting program.
*/
void df_error(char *message)
{
	char errmsg[MAXLEN];

	strcpy(errmsg, "Error ");
	strncat(errmsg, message, MAXLEN-6);
	perror(errmsg);
	exit(1);
}
