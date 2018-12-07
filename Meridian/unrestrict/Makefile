TARGET  = Unrestrict.dylib
OUTDIR ?= bin
PREFIX ?= /Library/MobileSubstrate/ServerPlugins
SRC     = $(wildcard *.c helpers/*.c)

CC      = xcrun -sdk iphoneos gcc -arch arm64 -arch armv7 -arch armv7s
LDID    = ldid
CFLAGS  = -dynamiclib -I. -I./helpers -framework IOKit -framework CoreFoundation -Wno-deprecated-declarations

.PHONY: all install clean

all: $(OUTDIR)/$(TARGET)

install: all
	install -d "$(DESTDIR)$(PREFIX)"
	install $(OUTDIR)/$(TARGET) "$(DESTDIR)$(PREFIX)"

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): $(SRC) | $(OUTDIR)
	$(CC) $(CFLAGS) -install_name $(PREFIX)/$(TARGET) -o $@ $^ $(DEBUG)
	$(LDID) -S $@

install: all

clean:
	rm -rf $(OUTDIR)
