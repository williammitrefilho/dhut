#include <aes.h>
#ifndef CBC_H

#define CBC_H

unsigned short cbc_aes256_cbc(unsigned char iv[16], unsigned char key[32], unsigned char *msg, unsigned short msg_len, unsigned char *out);
unsigned short cbc_aes256_cbc_decrypt(unsigned char iv[16], unsigned char key[32], unsigned char *msg, unsigned short msg_len, unsigned char *out);
#endif // CBC_H
