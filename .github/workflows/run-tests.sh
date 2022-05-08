#!/bin/bash

set -ex

dfuzzer=("dfuzzer")
if [[ "$TYPE" == valgrind ]]; then
        dfuzzer=("valgrind" "--leak-check=full" "--show-leak-kinds=definite" "--errors-for-leak-kinds=definite" "--error-exitcode=42" "dfuzzer")
fi

sudo systemctl daemon-reload

# Test if we can list activatable dbus services as well
"${dfuzzer[@]}" -l | grep 'org.freedesktop.dfuzzerServer (activatable)'

set +e
# https://github.com/matusmarhefka/dfuzzer/issues/45
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

sudo systemctl stop dfuzzer-test-server

# dfuzzer should return 0 by default when services it tests time out
# https://github.com/matusmarhefka/dfuzzer/pull/57#issuecomment-1112191073
"${dfuzzer[@]}" -s -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_hang

sudo systemctl stop dfuzzer-test-server

"${dfuzzer[@]}" -e true -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_hello

set +e
"${dfuzzer[@]}" -e false -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_hello
[[ $? == 2 ]] || exit 1
set -e

sudo systemctl stop dfuzzer-test-server

# Make sure we can still test services, which cannot be auto-activated
rm /usr/share/dbus-1/system-services/org.freedesktop.dfuzzerServer.service
sudo systemctl reload dbus
set +e
"${dfuzzer[@]}" -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_hello
[[ $? == 4 ]] || exit 1
set -e
sudo systemctl start dfuzzer-test-server
"${dfuzzer[@]}" -v -n org.freedesktop.dfuzzerServer -o /org/freedesktop/dfuzzerObject -i org.freedesktop.dfuzzerInterface -t df_hello
sudo systemctl stop dfuzzer-test-server

# Make the tests a bit faster in CI, since it takes a while to go through all systemd methods
dfuzzer+=("--max-iterations=10")

"${dfuzzer[@]}" -h
"${dfuzzer[@]}" -V
"${dfuzzer[@]}" --version
"${dfuzzer[@]}" -l
"${dfuzzer[@]}" -s -l
"${dfuzzer[@]}" --no-suppressions --list

# Suppression file tests
# Test a long suppression file
perl -e 'print "[org.freedesktop.systemd1]\n"; print "Reboot destructive\n" x 250; print "Reboot\n" x 250' >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.systemd1.Manager -t Reboot
# Test various suppression definitions
printf "[org.freedesktop.systemd1]\nPing" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep "SKIP Ping"
printf "[org.freedesktop.systemd1]\n::Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep "SKIP Ping"
printf "[org.freedesktop.systemd1]\n/org/freedesktop/systemd1:org.freedesktop.DBus.Peer:Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep "SKIP Ping"
printf "[org.freedesktop.systemd1]\n/org/freedesktop/systemd1::Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep "SKIP Ping"
printf "[org.freedesktop.systemd1]\norg.freedesktop.DBus.Peer:Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep "SKIP Ping"
printf "[org.freedesktop.systemd1]\n:" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep "SKIP Ping"
printf "[org.freedesktop.systemd1]\n::" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep "SKIP Ping"
printf "[org.freedesktop.systemd1]\naaaaaaa:Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep "PASS Ping"
printf "[org.freedesktop.systemd1]\naaaaaaa::Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep "PASS Ping"
printf "[org.freedesktop.systemd1]\n/org/freedesktop/systemd1:nope:Ping" >dfuzzer.conf
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.DBus.Peer -t Ping |& grep "PASS Ping"
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
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o aaaaaaaaa && false
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o / -i aaaaaaaaaa && false
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o / -i aaaaaaaaaa && false

# Check if we probe void methods
log_out="$(mktemp)"
sudo "${dfuzzer[@]}" -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.systemd1.Manager -t ListUnits |& tee "$log_out"
grep "PASS" "$log_out"
grep "SKIP" "$log_out" && false
# Test as an unprivileged user (short options)
"${dfuzzer[@]}" -v -n org.freedesktop.systemd1
# Test as root (long options + duplicate options)
sudo "${dfuzzer[@]}" --verbose --bus this.should.be.ignored --bus org.freedesktop.systemd1
# Test logdir
mkdir dfuzzer-logs
"${dfuzzer[@]}" --log-dir dfuzzer-logs -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.systemd1.Manager
# Test a non-existent bus
if sudo "${dfuzzer[@]}" --log-dir "" --bus this.should.not.exist; then false; fi
# Test object & interface options
"${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --object / --interface org.freedesktop.DBus.Peer
sudo "${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --object / --interface org.freedesktop.DBus.Peer
# - duplicate object/interface paths
"${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --object xxx --object yyy --object / --interface org.freedesktop.DBus.Peer
"${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --object xxx --object yyy --object / --interface zzz --interface org.freedesktop.DBus.Peer
# - test error paths
if "${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --object aaa; then false; fi
if "${dfuzzer[@]}" -v --bus org.freedesktop.systemd1 --interface aaa; then false; fi

sudo systemctl stop dfuzzer-test-server
