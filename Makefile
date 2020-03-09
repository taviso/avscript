CFLAGS  = -O3 -march=native -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -Iinclude -mstackrealign
CPPFLAGS=-DNDEBUG -D_GNU_SOURCE -Iloadlibrary -Iloadlibrary/intercept -Iloadlibrary/peloader
LDFLAGS = $(CFLAGS) -m32
LDLIBS  = loadlibrary/intercept/libdisasm.a -Wl,--whole-archive,loadlibrary/peloader/libpeloader.a,--no-whole-archive

.PHONY: clean peloader

TARGETS=avscript

all: $(TARGETS)

peloader:
	make -C loadlibrary all

# avscript requires libreadline-dev:i386
avscript: avscript.o loadlibrary/intercept/hook.o | peloader
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(LDFLAGS) -lreadline

clean:
	rm -f a.out core *.o core.* vgcore.* gmon.out avscript
	make -C loadlibrary clean
