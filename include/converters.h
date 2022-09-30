#include <stdio.h>
#include <basics.h>

#ifndef CONVERTERS_H

#define CONVERTERS_H

unsigned short prlong(unsigned long long num[4]);
unsigned short prbytes(unsigned char bytes[32]);
unsigned short strtobytes(unsigned char str[64], unsigned char bytes[32]);
unsigned short btolongi(unsigned char bytes[32], unsigned long long out[4]);
unsigned short btolong(unsigned char bytes[32], unsigned long long out[4]);
unsigned short longtobi(unsigned long long num[4], unsigned char bytes[32]);
unsigned short x25519transform(unsigned char bytes[32]);
unsigned char ccharval(unsigned char x);

#endif