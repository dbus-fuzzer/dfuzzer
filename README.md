dfuzzer
=======

D-Bus fuzzer

clone by:
git clone https://github.com/matusmarhefka/dfuzzer.git


Using valgrind with GLib:
$ export G_SLICE=always-malloc
$ export G_DEBUG=gc-friendly
$ valgrind --tool=memcheck --leak-check=full --leak-resolution=high --num-callers=20 ./app
