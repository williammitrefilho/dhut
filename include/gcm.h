#ifndef GCM_H

#define GCM_H

unsigned short u64to8(unsigned long long *in, unsigned short in_len, unsigned char *out);
unsigned short u8to64(unsigned char *in, unsigned short in_len, unsigned long long *out);
unsigned short u8to128(unsigned char *in, unsigned short in_len, unsigned long long *out);
unsigned short gcm_to_watch(const unsigned char* data, const unsigned short len, const unsigned short type, unsigned short* out);
unsigned short gcm_zero_watch(unsigned short* p, unsigned short len);
unsigned short gcm_mult(unsigned long long x[2], unsigned long long y[2], unsigned long long out[2]);
unsigned short gcm_ghash(unsigned long long key[2], unsigned long long *x, unsigned short xlen, unsigned long long out[2]);
unsigned short gcm_gctr_aes_256(unsigned long long icb[2], unsigned long long *x, unsigned short xlen, unsigned char key[32], unsigned long long *out);
unsigned short gcm_aes256_gcm(unsigned char* iv, unsigned short iv_len, unsigned char key[32], unsigned char* plaintext, unsigned short ptlen, unsigned char* aad, unsigned short aad_len, unsigned char *out, unsigned char *tag, unsigned short tag_len);
unsigned short gcm_aes_256_gcm_ad(unsigned char *iv, unsigned short iv_len, unsigned char key[32], unsigned char *ciphertext, unsigned short ctlen, unsigned char *aad, unsigned short aad_len, unsigned char *out, unsigned char *tag, unsigned short tag_len);

#define GCM1_BYTE 1
#define GCM1_ULLONG 2

#endif // GCM_H
