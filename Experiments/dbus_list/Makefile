CC=gcc
CFLAGS=-Wall `pkg-config --cflags --libs dbus-glib-1`
#`pkg-config --cflags --libs glib-2.0`
#`pkg-config --cflags --libs dbus-1`

all: dbus_list

dbus_list: dbus_list.c
	$(CC) $(CFLAGS) -o dbus_list dbus_list.c

.PHONY: clean
clean:
	rm -f dbus_list
