HEADERS = aes.h api.h bch-light.h bch.h bch128.h bch192.h bch256.h bin-lwe.h ecc.h lac_param.h rand.h randombytes.h sha2.h test_correctness.h test_cpucycles.h test_speed.h
OBJECTS = aes.o ake.o bch.o bin-lwe.o ecc.o encrypt.o ke.o kem.o main.o rand.o randombytes.o sha2.o test_correctness.o test_cpucycles.o test_speed.o
CFLAGS = -O3 -Wall -march=native

lac : $(OBJECTS)
	gcc -o lac $(OBJECTS)

%.o: %.c $(HEADERS)
	gcc $(CFLAGS) -c $<

clean:
	rm -f lac $(OBJECTS)
