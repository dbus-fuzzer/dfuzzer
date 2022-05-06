dfuzzer
=======
[![Total alerts](https://img.shields.io/lgtm/alerts/g/matusmarhefka/dfuzzer.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/matusmarhefka/dfuzzer/alerts/)
[![Coverage Status](https://coveralls.io/repos/github/matusmarhefka/dfuzzer/badge.svg)](https://coveralls.io/github/matusmarhefka/dfuzzer)

dfuzzer is the D-Bus fuzzer, the tool for fuzz testing processes communicating
through D-Bus. It can be used to test processes connected to both, the session
bus and the system bus daemon. The fuzzer works as a client, it first connects
to the bus daemon and then it traverses and fuzz tests all the methods provided
by a D-Bus service.

Automatic installation (Fedora 21 and higher):
--------------

    sudo yum/dnf install dfuzzer

Manual installation:
--------------
    $ git clone https://github.com/matusmarhefka/dfuzzer
    $ cd dfuzzer
    $ meson --buildtype=release build
    $ ninja -C ./build -v
    $ sudo ninja -C ./build install


Requirements:

    glib2-devel  (2.34 or higher)
    meson

Fedora:

    $ dnf install glib2-devel meson

Debian:

    $ apt-get install libglib2.0-dev meson


Using valgrind with _GLib_:
--------------
    $ export G_SLICE=always-malloc G_DEBUG=gc-friendly
    $ valgrind --tool=memcheck --leak-check=full --leak-resolution=high --num-callers=20 ./app
