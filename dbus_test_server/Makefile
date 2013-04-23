CC=gcc
CFLAGS=-Wall `pkg-config --cflags --libs gio-2.0`

all: server

server: dbus_test_server.c
	$(CC) $(CFLAGS) -o dbus_test_server dbus_test_server.c

.PHONY: clean
clean:
	rm -f dbus_test_server
