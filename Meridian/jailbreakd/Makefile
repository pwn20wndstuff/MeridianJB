TARGET  = jailbreakd
OUTDIR ?= bin
PREFIX ?= /meridian
SRC     = $(wildcard *.c) $(wildcard *.m) $(wildcard */*.c) $(wildcard */*.m)

CC      = xcrun -sdk iphoneos gcc -arch arm64 -arch arm64e
LDID    = ldid
CHMOD   = chmod
CFLAGS  = -I. -I./helpers -I./kernel_call -I./mach -framework Foundation -framework IOKit

.PHONY: all install clean

all: $(OUTDIR)/$(TARGET)

install: all
	install -d "$(DESTDIR)$(PREFIX)"
	install $(OUTDIR)/$(TARGET) "$(DESTDIR)$(PREFIX)"

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): $(SRC) | $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $^
	$(LDID) -Sentitlements.xml $@
	$(CHMOD) 755 $@

install: all

clean:
	rm -rf $(OUTDIR)
