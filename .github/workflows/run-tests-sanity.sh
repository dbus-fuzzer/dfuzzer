#!/usr/bin/env bash

set -ex
set -o pipefail

# shellcheck source=.github/workflows/shared.sh
. "$(dirname "$0")"/shared.sh

ninja -C ./build test

# Test if we can list activatable dbus services as well
"${dfuzzer[@]}" -l | grep 'org.freedesktop.dfuzzerServer (activatable)'

set +e
# https://github.com/dbus-fuzzer/dfuzzer/issues/45
"${dfuzzer[@]}" -v -n org.freedesktop.dfuzzerServer
[[ $? == 2 ]] || exit 1
set -e

# Make sure we can process complex signatures without issues
"${dfuzzer[@]}" -s -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_complex_sig_1
"${dfuzzer[@]}" -s -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_complex_sig_2

# Crash on a specific string
"${dfuzzer[@]}" -s -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_crash_on_leeroy
cat >inputs.txt <<'EOF'
a string
also a string
probably a string
Leeroy Jenkins
you guessed it - also a string
no way this is a string as well
EOF
"${dfuzzer[@]}" -f inputs.txt -s -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_crash_on_leeroy && false
rm -f inputs.txt

# Test if we respect the org.freedesktop.DBus.Method.NoReply annotation
"${dfuzzer[@]}" -s -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_noreply && false
"${dfuzzer[@]}" -s -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_noreply_expected

# Test property handling
"${dfuzzer[@]}" -s -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -p crash_on_write && false
"${dfuzzer[@]}" -s -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -p read_only
"${dfuzzer[@]}" -s -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -p write_only

stop_test_server

# dfuzzer should return 0 by default when services it tests time out
# https://github.com/dbus-fuzzer/dfuzzer/pull/57#issuecomment-1112191073
"${dfuzzer[@]}" -s -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_hang

stop_test_server

"${dfuzzer[@]}" -e true -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_hello

set +e
"${dfuzzer[@]}" -e false -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_hello
[[ $? == 2 ]] || exit 1
set -e

stop_test_server

"${dfuzzer[@]}" -h
"${dfuzzer[@]}" -V
"${dfuzzer[@]}" --version
"${dfuzzer[@]}" -l
"${dfuzzer[@]}" -s -l
"${dfuzzer[@]}" --no-suppressions --list

exit 0
