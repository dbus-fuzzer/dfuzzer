#!/usr/bin/env bash

set -ex
set -o pipefail

# shellcheck source=.github/workflows/shared.sh
. "$(dirname "$0")"/shared.sh

# Make sure we can still test services, which cannot be auto-activated
sudo systemctl stop dfuzzer-test-server
rm /usr/share/dbus-1/system-services/org.freedesktop.dfuzzerServer.service
sudo systemctl reload dbus

set +e
"${dfuzzer[@]}" -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_hello
[[ $? == 4 ]] || exit 1
set -e

sudo systemctl start dfuzzer-test-server
"${dfuzzer[@]}" -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_hello
sudo systemctl stop dfuzzer-test-server

# CI specific suppressions for issues already fixed in upstream
# shellcheck disable=SC1004
sudo sed -i '/\[org.freedesktop.systemd1\]/a \
org.freedesktop.systemd1.Manager:Reexecute Fixed by https://github.com/systemd/systemd/pull/23328 \
org.freedesktop.systemd1.Manager:RefUnit \
org.freedesktop.systemd1.Manager:UnrefUnit \
Ref \
Unref \
' /etc/dfuzzer.conf

# Make the tests a bit faster in CI, since it takes a while to go through all systemd methods
dfuzzer+=("--max-iterations=10")

# Suppression file tests
# Test a long suppression file
perl -e 'print "[org.freedesktop.systemd1]\n"; print "Reboot destructive\n" x 250; print "Reboot\n" x 250' >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.systemd1.Manager -t Reboot
# Test various suppression definitions
printf "[org.freedesktop.systemd1]\nPing" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep -F "SKIP [M] Ping"
printf "[org.freedesktop.systemd1]\n::Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep -F "SKIP [M] Ping"
printf "[org.freedesktop.systemd1]\n/org/freedesktop/systemd1:org.freedesktop.DBus.Peer:Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep -F "SKIP [M] Ping"
printf "[org.freedesktop.systemd1]\n/org/freedesktop/systemd1::Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep -F "SKIP [M] Ping"
printf "[org.freedesktop.systemd1]\norg.freedesktop.DBus.Peer:Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep -F "SKIP [M] Ping"
printf "[org.freedesktop.systemd1]\n:" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep -F "SKIP [M] Ping"
printf "[org.freedesktop.systemd1]\n::" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep -F "SKIP [M] Ping"
printf "[org.freedesktop.systemd1]\naaaaaaa:Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep -F "PASS [M] Ping"
printf "[org.freedesktop.systemd1]\naaaaaaa::Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep -F "PASS [M] Ping"
printf "[org.freedesktop.systemd1]\n/org/freedesktop/systemd1:nope:Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep -F "PASS [M] Ping"
# Invalid definitions
printf "[org.freedesktop.systemd1]\n:::Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping && false
printf "[org.freedesktop.systemd1]\n:::" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping && false
# Cleanup
rm -f dfuzzer.conf

# Test a couple of error paths
"${dfuzzer[@]}" && false
"${dfuzzer[@]}" -v -n "$(perl -e 'print "x" x 256')" && false
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o "$(perl -e 'print "x" x 256')" && false
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o / -i "$(perl -e 'print "x" x 256')" && false
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -L "$(perl -e 'print "x" x 256')" && false
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -b 0 && false
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -x 0 && false
# Non-existent bus/object/interface/method/property objects
"${dfuzzer[@]}" -v -n aaaaaaaa && false
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o aaaaaaaaa && false
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i aaaaaaaaaa && false
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.systemd1.Manager -t bbbbbbb && false
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.systemd1.Manager -p ccccccc && false
# -t/--method= and -p/--property= are mutualy exclusive
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o / -i a -t method -p property && false
# Non-existent -f/--dictionary= path
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -f /a/b/c/d/e && false
for opt in "-y" "--min-iterations" "-x" "--max-iterations" "-I" "--iterations"; do
        # Number of iterations must be > 0 ...
        "${dfuzzer[@]}" -v -n org.freedesktop.systemd1 "$opt" 0 && false
        "${dfuzzer[@]}" -v -n org.freedesktop.systemd1 "$opt" -1 && false
        # ... must fit into guint64, i.e. < 2^64 -1 ...
        "${dfuzzer[@]}" -v -n org.freedesktop.systemd1 "$opt" 18446744073709551616 && false
        # ... and it should be a valid integer.
        "${dfuzzer[@]}" -v -n org.freedesktop.systemd1 "$opt" 10a && false
        "${dfuzzer[@]}" -v -n org.freedesktop.systemd1 "$opt" 10.1 && false
done
# min-iterations <= max-iterations
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 --max-iterations=1 --min-iterations=2 && false

# Check if we probe void methods
log_out="$(mktemp)"
sudo "${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.systemd1.Manager -t ListUnits |& tee "$log_out"
grep "PASS" "$log_out"
grep "SKIP" "$log_out" && false

# Going through all objects and their properties takes an ungodly amount of time
# in CI with Valgrind (2h+), so let's help it a little
bus_object=()
if [[ "$TYPE" == valgrind ]]; then
        bus_object=(-o /org/freedesktop/systemd1/unit/_2d_2eslice)
fi
# Test as an unprivileged user (short options)
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 "${bus_object[@]}"
# Test as root (long options + duplicate options)
sudo "${dfuzzer[@]}" --verbose --bus this.should.be.ignored --bus org.freedesktop.systemd1 "${bus_object[@]}"
# Test logdir
mkdir dfuzzer-logs
"${dfuzzer[@]}" --log-dir dfuzzer-logs -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.systemd1.Manager
# Test a non-existent bus
sudo "${dfuzzer[@]}" --log-dir "" --bus this.should.not.exist && false
# Test object & interface options
"${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --object / --interface org.freedesktop.DBus.Peer
sudo "${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --object / --interface org.freedesktop.DBus.Peer
# - duplicate object/interface paths
"${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --object xxx --object yyy --object / --interface org.freedesktop.DBus.Peer
"${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --object xxx --object yyy --object / --interface zzz --interface org.freedesktop.DBus.Peer
# - test error paths
"${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --object aaa && false
"${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --interface aaa && false

exit 0
