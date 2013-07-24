dfuzzer
=======

dfuzzer is D-Bus fuzzer, a tool for fuzz testing processes communicating through D-Bus.
It can be used to test processes connected to both, the session bus and the system
bus daemon.


Clone by:
--------------
    $ git clone https://github.com/matusmarhefka/dfuzzer.git


Requirements:
--------------

    glib2-devel-2.26 or higher
    libffi-devel-3.0 or higher

Fedora:

    $ sudo yum install glib2-devel libffi-devel


Using valgrind with _GLib_:
--------------
    $ export G_SLICE=always-malloc G_DEBUG=gc-friendly
    $ valgrind --tool=memcheck --leak-check=full --leak-resolution=high --num-callers=20 ./app
