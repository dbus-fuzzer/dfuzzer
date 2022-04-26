#!/bin/bash

set -ex

dfuzzer=dfuzzer
if [[ "$TYPE" == valgrind ]]; then
    # leak-check=full should be brought back once https://github.com/matusmarhefka/dfuzzer/issues/45
    # is addressed properly. Until then let's use valgrind to make sure uninitizlized memory isn't
    # used anywhere.
    dfuzzer='valgrind --leak-check=no --show-leak-kinds=definite --errors-for-leak-kinds=definite --error-exitcode=1 dfuzzer'
fi

$dfuzzer -V
$dfuzzer --version
$dfuzzer -s -l
$dfuzzer --no-suppressions --list
# Test a long suppression file
perl -e 'print "[org.freedesktop.systemd1]\n"; print "Reboot destructive\n" x 250; print "Reboot\n" x 250' >dfuzzer.conf
$dfuzzer -v -n org.freedesktop.systemd1 -o /org/freedesktop/systemd1 -i org.freedesktop.systemd1.Manager -t Reboot
rm -f dfuzzer.conf
# Test as an unprivileged user (short options)
$dfuzzer -v -n org.freedesktop.systemd1
# Test as root (long options + duplicate options)
sudo $dfuzzer --verbose --bus this.should.be.ignored --bus org.freedesktop.systemd1
# Test logdir
mkdir dfuzzer-logs
$dfuzzer --log-dir dfuzzer-logs -v -n org.freedesktop.systemd1
# Test a non-existent bus
if sudo $dfuzzer --log-dir "" --bus this.should.not.exist; then false; fi
# Test object & interface options
$dfuzzer -v --bus org.freedesktop.systemd1 --object / --interface org.freedesktop.DBus.Peer
sudo $dfuzzer -v --bus org.freedesktop.systemd1 --object / --interface org.freedesktop.DBus.Peer
# - duplicate object/interface paths
$dfuzzer -v --bus org.freedesktop.systemd1 --object xxx --object yyy --object / --interface org.freedesktop.DBus.Peer
$dfuzzer -v --bus org.freedesktop.systemd1 --object xxx --object yyy --object / --interface zzz --interface org.freedesktop.DBus.Peer
# - test error paths
if $dfuzzer -v --bus org.freedesktop.systemd1 --object aaa; then false; fi
if $dfuzzer -v --bus org.freedesktop.systemd1 --interface aaa; then false; fi
