dfuzzer
=======

D-Bus fuzzer - tool for fuzz testing processes communicating through D-Bus


Clone by:

    $ git clone https://github.com/matusmarhefka/dfuzzer.git


Dependencies (Fedora):

    $ sudo yum install glib2-devel libffi-devel


Using valgrind with _GLib_:

    $ export G_SLICE=always-malloc
    $ export G_DEBUG=gc-friendly
    $ valgrind --tool=memcheck --leak-check=full --leak-resolution=high --num-callers=20 ./app
