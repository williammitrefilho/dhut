#ifndef B_P256_H
#define B_P256_H

#define b_mm b_mult_modp256
#define b_sm b_subtr_modp256
#define b_am b_add_modp256

unsigned char b_p256m1[64];
unsigned char b_p256[64];
unsigned char b_dif21631[4];
unsigned char b_zero[64];
unsigned char b_p256_a[64];
unsigned char b_p256_b[64];
unsigned char b_p256_gx[64];
unsigned char b_p256_gy[64];
unsigned char b_1[64];
unsigned char b_difp256[64];
unsigned char b_p256m1[64];
unsigned char b_p256[64];
unsigned char b_p256p1[64];


unsigned short b_random(unsigned char* out);
unsigned short b_subtr64(unsigned char* a, unsigned char*b, unsigned char* out);
unsigned short b_emaiorigual(unsigned char* a, unsigned char* b);
unsigned short b_zero64(unsigned char*a);
unsigned short b_add64(unsigned char* a, unsigned char*b, unsigned char*out);
unsigned short b_mult64(unsigned char* a, unsigned char* b, unsigned char*out);
unsigned short b_modp256(unsigned char* a, unsigned char* out);
unsigned short b_mult_modp256(unsigned char* a, unsigned char* b, unsigned char* out);
unsigned short b_subtr_modp256(unsigned char* a, unsigned char* b, unsigned char* out);
unsigned short b_add_modp256(unsigned char* a, unsigned char* b, unsigned char* out);
unsigned short b_lshift(unsigned char* a, unsigned short n);
unsigned short b_rshift(unsigned char* a, unsigned short n);
unsigned short b_div(unsigned char* a, unsigned char* b, unsigned char* r, unsigned char* m);
unsigned short b_invert(unsigned char* a, unsigned char* out);
unsigned short b_sqpt(unsigned char* x, unsigned char* y, unsigned char* z, unsigned char* outx, unsigned char* outy, unsigned char* outz);
unsigned short b_mpt(unsigned char* x1, unsigned char* y1, unsigned char* z1,
                        unsigned char* x2, unsigned char* y2, unsigned char* z2,
                            unsigned char* outx, unsigned char* outy, unsigned char* outz);
unsigned short bcswap(unsigned char swap, unsigned char* a, unsigned char* b);
unsigned char b_p256_gen_key(unsigned char* pk, unsigned char* gx, unsigned char* gy, unsigned char* x, unsigned char* y);
unsigned char b_p256_gen_key_pair(unsigned char* pk, unsigned char* x, unsigned char* y);
unsigned short b_p256_verify_pt(unsigned char x[64], unsigned char y[64]);
#endif // B_P256_H
