#ifndef AES_H

#define AES_H
#define aes_mm aes_multiply_mod

unsigned short aes_multiply(unsigned char a, unsigned char b);
unsigned short aes_sub_bytes(unsigned char in[4][4]);
unsigned short aes_inv_sub_bytes(unsigned char in[4][4]);
unsigned char aes_mod(unsigned short a);
unsigned char aes_multiply_mod(unsigned char a, unsigned char b);
unsigned short aes_shift_rows(unsigned char in[4][4]);
unsigned short aes_inv_shift_rows(unsigned char in[4][4]);
unsigned short aes_mix_columns(unsigned char a[4][4]);
unsigned short aes_inv_mix_columns(unsigned char a[4][4]);
unsigned short aes_rotword(unsigned char* a, unsigned char* out);
unsigned short aes_key_expansion(unsigned char* key, unsigned short key_len, unsigned char* out);
unsigned short aes_inv_key_expansion(unsigned char* key, unsigned short key_len, unsigned char* out);
unsigned short aes_encrypt(unsigned char *data, unsigned char *key, unsigned short key_len, unsigned char *out);
unsigned short aes_decrypt(unsigned char *data, unsigned char *key, unsigned short key_len, unsigned char *out);

#endif // AES_H
