/** @file dfuzzer.h *//*

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
#ifndef DFUZZER_H
#define DFUZZER_H


/** Structure containing D-Bus name, object path and interface of application.
*/
struct fuzzing_target {		// names on D-Bus have the most MAXLEN characters
	char name[MAXLEN];
	char obj_path[MAXLEN];
	char interface[MAXLEN];
};


/** @function Parses program options and stores them into struct fuzzing_target.
	@param argc Count of options
	@param argv Pointer on strings containing options of program
*/
void df_parse_parameters(int argc, char **argv);

/** @function Prints help.
	@param name Name of program
*/
void df_print_help(char *name);

#endif
