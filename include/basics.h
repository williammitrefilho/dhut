#ifndef BASICS_H

#define BASICS_H

const unsigned char hx_label[2];

unsigned char charval(unsigned char c);
unsigned short hex2bin(unsigned char* data, unsigned char* out, unsigned short *out_len);
unsigned short bin2hex(unsigned char *data, unsigned short data_len, unsigned char *out);
unsigned short printchars(unsigned char *data, unsigned short data_len);
unsigned short printhex(unsigned char *data, unsigned short data_len);

#endif