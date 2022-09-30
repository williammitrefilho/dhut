#include <string.h>
#ifndef SHA_H

#define SHA_H

unsigned long long sha_rotr64(unsigned short n, unsigned long long x);
unsigned long long sha_rotl64(unsigned short n, unsigned long long x);
unsigned long long sha_sha384_ch(unsigned long long x, unsigned long long y, unsigned long long z);
unsigned long long sha_sha384_maj(unsigned long long x, unsigned long long y, unsigned long long z);
unsigned long long sha384_bsig0(unsigned long long x);
unsigned long long sha384_bsig1(unsigned long long x);
unsigned long long sha384_ssig0(unsigned long long x);
unsigned long long sha384_ssig1(unsigned long long x);
unsigned short sha_sha384(unsigned char* msg, unsigned int msg_len, unsigned char *out);
unsigned short sha_sha384_p_hash(unsigned char *secret, unsigned short secret_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out);
unsigned short sha_sha384_prf2(unsigned char *secret, unsigned short secret_len, unsigned char *label, unsigned short label_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out);
unsigned short sha_sha384_hmac(unsigned char *key, unsigned short key_len, unsigned char *msg, unsigned short msg_len, unsigned char *out);
unsigned short sha_sha384_hkdf_expand(unsigned char *prk, unsigned short prk_len, unsigned char *info, unsigned short info_len, unsigned short l, unsigned char *out);
unsigned short sha_hkdf_sha384_expand_label(unsigned char secret[48], unsigned char *label, unsigned short label_len, unsigned char *context, unsigned short ctx_len, unsigned short length, unsigned char *out);


const unsigned long sha_sha1_f1(unsigned long b, unsigned long c, unsigned long d);
const unsigned long sha_sha1_f2(unsigned long b, unsigned long c, unsigned long d);
const unsigned long sha_sha1_f3(unsigned long b, unsigned long c, unsigned long d);
const unsigned long sha_sha1_f4(unsigned long b, unsigned long c, unsigned long d);
unsigned long sha_sha1_s(unsigned short n, unsigned long x);
unsigned short sha_sha1(unsigned char *msg, unsigned short msg_len, unsigned char out[20]);
unsigned short sha_sha1_hmac(unsigned char *key, unsigned short key_len, unsigned char *msg, unsigned short msg_len, unsigned char out[20]);
unsigned short sha_sha1_p_hash(unsigned char *secret, unsigned short secret_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out);
unsigned short sha_sha1_prf(unsigned char *secret, unsigned short secret_len, unsigned char *label, unsigned short label_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out);
unsigned short sha_sha1_tls12_compute_master_secret(unsigned char *pre_master_secret, unsigned short pre_master_secret_len, unsigned char client_hello_random[32], unsigned char server_hello_random[32], unsigned char out[48]);
unsigned short sha_sha1_tls12_aes256_derive_keys(unsigned char master_secret[48], unsigned char client_hello_random[32], unsigned char server_hello_random[32], unsigned char out_block[136]);

unsigned char* msgpad(unsigned char* msg, int m_len, int*p_len);
unsigned char* rshift(unsigned char* bytes, int b_len, int n);
unsigned char* lshift(unsigned char* bytes, int b_len, int n);
unsigned char *rotr(unsigned char*bytes, int b_len, int n);
unsigned char *rotl(unsigned char*bytes, int b_len, int n);
unsigned long sha256_ch(unsigned long x, unsigned long y, unsigned long z);
unsigned long sha256_maj(unsigned long x, unsigned long y, unsigned long z);
void btostr(unsigned char byte, unsigned char* str);
unsigned long u_rotr(unsigned long x, int n);
unsigned long u_rotl(unsigned long x, int n);
unsigned long sha256_bsig0(unsigned long x);
unsigned long sha256_bsig1(unsigned long x);
unsigned long sha256_ssig0(unsigned long x);
unsigned long sha256_ssig1(unsigned long x);
int sha256(unsigned char* msg, int msglen, unsigned long* hashout);
int sha256_b(unsigned char *msg, int msg_len, unsigned char out[32]);
unsigned short sha_sha256_hmac(unsigned char *key, unsigned short key_len, unsigned char *msg, unsigned short msg_len, unsigned char out[32]);
unsigned short sha_sha256_p_hash(unsigned char *secret, unsigned short secret_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out);
unsigned short sha_sha256_prf(unsigned char *secret, unsigned short secret_len, unsigned char *label, unsigned short label_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out);

#endif // SHA_H
