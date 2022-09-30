/* ========================================================================== */
/*                                                                            */
/*   Filename.c                                                               */
/*   (c) 2012 Author                                                          */
/*                                                                            */
/*   Description                                                              */
/*                                                                            */
/* ========================================================================== */

#ifndef BM256_H

#define BM256_H

#define bm_64bits 0xFFFFFFFFFFFFFFFF
#define bm_bit0   0x8000000000000000
#define bm_nbit0  0x7FFFFFFFFFFFFFFF
unsigned short bm_mult64(unsigned long long a, unsigned long long b, unsigned long long *pmain, unsigned long long *poverflow);
unsigned short bm_add64(unsigned long long a, unsigned long long b, unsigned long long *presult, unsigned long long *poverflow);
unsigned short bm_mult256(const unsigned long long a[4], const unsigned long long b[4], unsigned long long result[4], unsigned long long overflow[4]);
unsigned short bm_add256(const unsigned long long a[4], const unsigned long long b[4], unsigned long long result[4], unsigned long long *overflow);
unsigned short bm_emaior256(const unsigned long long a[4], const unsigned long long b[4]);
unsigned short bm_subtr256(const unsigned long long a[4], const unsigned long long b[4], unsigned long long r[4]);

#endif