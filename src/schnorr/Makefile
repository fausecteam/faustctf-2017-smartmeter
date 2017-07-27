src = $(wildcard *.c)
obj = $(src:.c=.o)
dep = $(obj:.o=.d)

LDFLAGS = -lcrypto -lssl -lbsd
CFLAGS=-Wall -Wmissing-declarations -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wcast-qual -Wsign-compare -I/home/malte/src/smartmeter/src/bjnfc/../root//include -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIC -O3 -B../obfuscator/

all: libschnorr.a libschnorr.so

libschnorr.a: $(obj)
	$(AR) rcs $@ $^

libschnorr.so: $(obj)
	$(CC) $(LDFLAGS) -shared -o $@ $^


-include $(dep)   # include all dep files in the makefile

# rule to generate a dep file by using the C preprocessor
# (see man cpp for details on the -MM and -MT options)
%.d: %.c
	@$(CPP) $(CFLAGS) $< -MM -MT $(@:.d=.o) >$@

.PHONY: clean
clean: cleandep
	rm -f $(obj) libschnorr.a libschnorr.so

.PHONY: cleandep
cleandep:
	rm -f $(dep)

.PHONY: install
install:
	install -d $(PREFIX)/include $(PREFIX)/lib/
	install schnorr.h $(PREFIX)/include/
	install libschnorr.so $(PREFIX)/lib/
	install libschnorr.a $(PREFIX)/lib/
