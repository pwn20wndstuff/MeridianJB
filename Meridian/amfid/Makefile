TARGET  = amfid_payload.dylib
OUTDIR ?= bin
PREFIX ?= /meridian
SRC     = $(wildcard *.c) $(wildcard *.m) $(wildcard */*.c) $(wildcard */*.m)

CC      = xcrun -sdk iphoneos gcc -arch arm64
LDID    = ldid
CFLAGS  = -dynamiclib -I. -I./helpers -framework Foundation -framework IOKit -lc++

.PHONY: all install clean

all: $(OUTDIR)/$(TARGET)

install: all
	install -d "$(DESTDIR)$(PREFIX)"
	install $(OUTDIR)/$(TARGET) "$(DESTDIR)$(PREFIX)"

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): $(SRC) | $(OUTDIR)
	$(CC) $(CFLAGS) -install_name "$(PREFIX)/$(TARGET)" -o $@ $^
	$(LDID) -S $@

install: all

clean:
	rm -rf $(OUTDIR)
