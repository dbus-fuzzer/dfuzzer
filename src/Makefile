#==============================================================================
# This file is part of dfuzzer.
# Copyright(C) 2014, 2015, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>
#==============================================================================

CC ?= gcc
# See: https://www.gnu.org/software/make/manual/make.html#Override-Directive
override CFLAGS += -Wall -O2 -D_FORTIFY_SOURCE=2 -fstack-protector --param=ssp-buffer-size=4 `pkg-config --cflags --libs gio-2.0` -g
OBJ = dfuzzer.o introspection.o fuzz.o rand.o util.o bus.o
TARGET = dfuzzer
all: dfuzzer
.PHONY: doc man clean install


makefile.dep:
	$(CC) -MM *.c >makefile.dep
$(TARGET): $(OBJ)
	$(CC) $(OBJ) $(CFLAGS) -o $(TARGET)

install: $(TARGET) man
	install -pm 0755 $(TARGET) /usr/bin/$(TARGET)
	install -pm 0644 dfuzzer.conf /etc/dfuzzer.conf
	install -pm 0644 ../man/dfuzzer.1.gz /usr/share/man/man1/dfuzzer.1.gz

doc:
	doxygen doxyfile

# .gz should be copied into /usr/share/man/man1
man:
	gzip -c ../man/dfuzzer.1 > ../man/dfuzzer.1.gz

clean:
	rm -f $(TARGET) $(OBJ) makefile.dep ../man/dfuzzer.1.gz
	rm -rf ../doc

-include makefile.dep
