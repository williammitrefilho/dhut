#include <sha.h>

#ifndef PRF_H

#define PRF_H

unsigned short sha384_prf(unsigned char *secret, unsigned short secret_len, unsigned char *label, unsigned short label_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out);
#endif