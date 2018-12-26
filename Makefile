CC=gcc
CFLAGS=-Ofast -m64 -Wall -Wno-unused-function -Wno-pointer-sign \
       -I. -Isecp256k1 -Isecp256k1/include -funsafe-loop-optimizations
LDFLAGS=$(CFLAGS)
LDLIBS=-lm -lssl -lpthread

OBJS=vanitygen.o base58.o

all: vanitygen

clean:
	rm -f vanitygen *.o

distclean: clean
	$(MAKE) -C secp256k1 distclean

vanitygen: $(OBJS)

$(OBJS): Makefile *.h secp256k1/src/libsecp256k1-config.h secp256k1/src/ecmult_static_context.h

secp256k1/src/libsecp256k1-config.h:
	(cd secp256k1;./autogen.sh;./configure)

secp256k1/src/ecmult_static_context.h:
	$(MAKE) -C secp256k1 src/ecmult_static_context.h
