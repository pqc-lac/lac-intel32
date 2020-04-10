OBJECTS = main.o test_correctness.o test_cpucycles.o test_speed.o \
          ake.o ke.o kem.o encrypt.o ecc.o bch.o bin-lwe.o rand.o rng.o
CFLAGS = -O3 -Wall -DNDEBUG
LDFLAGS = -lcrypto -lz

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	CFLAGS  += -I/usr/local/opt/openssl@1.1/include
    LDFLAGS += -L/usr/local/opt/openssl@1.1/lib
endif

lac : $(OBJECTS)
	gcc -o lac $(OBJECTS) $(LDFLAGS)

main.o: main.c test_correctness.h test_cpucycles.h test_speed.h api.h lac_param.h
	gcc -c main.c $(CFLAGS)

test_correctness.o: test_correctness.c api.h ecc.h rand.h lac_param.h
	gcc -c test_correctness.c $(CFLAGS)

test_cpucycles.o: test_cpucycles.c api.h rand.h ecc.h lac_param.h
	gcc -c test_cpucycles.c $(CFLAGS)

test_speed.o: test_speed.c api.h rand.h ecc.h lac_param.h
	gcc -c test_speed.c $(CFLAGS)

ake.o: ake.c api.h rand.h lac_param.h
	gcc -c ake.c $(CFLAGS)

ke.o: ke.c api.h rand.h lac_param.h
	gcc -c ke.c $(CFLAGS)

kem.o: kem.c api.h rand.h ecc.h bin-lwe.h lac_param.h
	gcc -c kem.c $(CFLAGS)

encrypt.o: encrypt.c api.h rand.h ecc.h bin-lwe.h lac_param.h 
	gcc -c encrypt.c $(CFLAGS)

ecc.o: ecc.c bch.h ecc.h lac_param.h bch128.h bch192.h bch256.h
	gcc -c ecc.c $(CFLAGS)

bch.o: bch.c bch.h lac_param.h
	gcc -c bch.c $(CFLAGS)

bin-lwe.o: bin-lwe.c lac_param.h rand.h bin-lwe.h 
	gcc -c bin-lwe.c $(CFLAGS)

rand.o: rand.c lac_param.h rand.h
	gcc -c rand.c $(CFLAGS) 

rng.o: rng.c rng.h
	gcc -c rng.c $(CFLAGS) 

clean:
	rm -f lac lac.exemak $(OBJECTS)
