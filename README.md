dfuzzer
=======
[![Total alerts](https://img.shields.io/lgtm/alerts/g/dbus-fuzzer/dfuzzer.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/dbus-fuzzer/dfuzzer/alerts)
[![Coverage Status](https://coveralls.io/repos/github/dbus-fuzzer/dfuzzer/badge.svg)](https://coveralls.io/github/dbus-fuzzer/dfuzzer)
[![Coverity Scan Status](https://scan.coverity.com/projects/24889/badge.svg)](https://scan.coverity.com/projects/dfuzzer)

dfuzzer is a D-Bus fuzzer, a tool for fuzz testing processes communicating
through D-Bus. It can be used to test processes connected to both, the session
bus and the system bus daemon. The fuzzer works as a client, it first connects
to the bus daemon and then it traverses and fuzz tests all the methods and
properties provided by a D-Bus service.

Automatic installation (Fedora):
--------------

    sudo dnf install dfuzzer

Manual installation:
--------------
    $ git clone https://github.com/dbus-fuzzer/dfuzzer
    $ cd dfuzzer
    $ meson --buildtype=release build
    $ ninja -C ./build -v
    $ sudo ninja -C ./build install


Requirements:

    glib2-devel  (2.34 or higher)
    meson
    xsltproc
    docbook-style-xsl

Fedora:

    $ dnf install docbook-style-xsl glib2-devel libxslt meson

Debian:

    $ apt-get install docbook-xsl libglib2.0-dev xsltproc meson


Using valgrind with _GLib_:
--------------
    $ export G_SLICE=always-malloc G_DEBUG=gc-friendly
    $ valgrind --tool=memcheck --leak-check=full --leak-resolution=high --num-callers=20 ./app
