//test correctness of pke_dec
#include <stdint.h>

int test_pke_correctness();

//test kem fo correctness
int test_kem_fo_correctness();

//test  ke correctness
int test_ke_correctness();

//test  ke correctness
int test_ake_correctness();

//calculate error bit number
int error_bit_num(uint8_t *k1, uint8_t *k2, int num);

//print bytes
int print_bytes(uint8_t *buf, int len);