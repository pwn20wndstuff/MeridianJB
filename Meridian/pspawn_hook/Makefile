TARGET  = pspawn_hook.dylib
OUTDIR ?= bin
PREFIX ?= /meridian
SRC     = $(wildcard *.c) $(wildcard *.m) $(wildcard mach/*.c)

CC      = xcrun -sdk iphoneos gcc -arch arm64e -arch arm64
LDID    = ldid
CFLAGS  = -dynamiclib -I./mach -I../substitute -framework Foundation

.PHONY: all install clean

all: $(OUTDIR)/$(TARGET)

install: all
	install -d "$(DESTDIR)$(PREFIX)"
	install $(OUTDIR)/$(TARGET) "$(DESTDIR)$(PREFIX)"

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): $(SRC) | $(OUTDIR)
	$(CC) $(CFLAGS) -install_name $(PREFIX)/$(TARGET) -o $@ $^
	$(LDID) -S $@

install: all

clean:
	rm -rf $(OUTDIR)
