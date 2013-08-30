#!/bin/bash
#
# Script removes escape sequences from ascii text files.
# Useful when creating log files with dfuzzer like this:
# $ ./dfuzzer -v -n bus_name 3>&1 1>&2 2>&3 | tee bus_name.log
#
# This file is part of dfuzzer.
# Copyright(C) 2013, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>
#

i=0
for file in $@; do
	if [[ ! -f $file ]]; then
		echo "$file: no such file!"
		i=$[i + 1]
		continue
	fi

	# remove '\r'
	sed -i 's/\x0D//g' $file

	# remove blank lines
	sed -i '/^\s*$/d' $file

	# remove escape sequences
	sed -i 's/\x1B\[[0-9]*m//g' $file
done


if [[ $# -eq $i ]]; then
	exit 1
fi

exit 0
