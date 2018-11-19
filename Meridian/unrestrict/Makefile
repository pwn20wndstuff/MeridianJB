TARGET  = Unrestrict.dylib
OUTDIR ?= bin
SRC     = $(wildcard *.c helpers/*.c)

CC      = xcrun -sdk iphoneos gcc -arch arm64 -arch armv7 -arch armv7s
LDID    = ldid
CFLAGS  = -dynamiclib -I. -I./helpers -framework IOKit -framework CoreFoundation -Wno-deprecated-declarations

all: $(OUTDIR)/$(TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): $(SRC) | $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ $^ $(DEBUG)
	$(LDID) -S $@

install: all

clean:
	rm -rf $(OUTDIR)
