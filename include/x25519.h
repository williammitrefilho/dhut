#include <bm256.h>

#ifndef X25519_H

#define X25519_H

unsigned short bm_modx25519(unsigned long long number[4], unsigned long long overflow[4], unsigned long long out[4]);
unsigned short bm_elx25519(unsigned long long u[4], unsigned long long v2[4]);
unsigned short bm_el25519(const unsigned long long k[4], const unsigned long long u[4], unsigned long long out[4]);
unsigned short cswap(unsigned long long a[4], unsigned long long b[4], unsigned long long swap);
unsigned short bm_invx25519(unsigned long long n[4], unsigned long long result[4]);
unsigned short bm_subtrx25519(unsigned long long a[4], unsigned long long b[4], unsigned long long result[4]);
unsigned short bm_addx25519(const unsigned long long a[4], const unsigned long long b[4], unsigned long long result[4]);
unsigned short bm_multx25519(const unsigned long long a[4], const unsigned long long b[4], unsigned long long result[4]);

const unsigned long long bm_19[4];
const unsigned long long bm_x25519[4];
const unsigned long long bm_a24[4];
const unsigned long long bm_9[4];
const unsigned long long bm_x25519_a[4];
#endif