//random bytes
#include <stdint.h>

int random_bytes(uint8_t *r, unsigned int len);
//pseudo-random bytes
int pseudo_random_bytes(uint8_t *r, unsigned int len, const uint8_t *seed);
//hash
int hash(const uint8_t *in, unsigned int len_in, uint8_t * out);
//hash
int hash_to_k(const uint8_t *in, unsigned int len_in, uint8_t * out);
//generate seed
int gen_seed(uint8_t *in, unsigned int len_in, uint8_t * out);