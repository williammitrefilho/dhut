#include <p256.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#define b_mm b_mult_modp256
#define b_sm b_subtr_modp256
#define b_am b_add_modp256

unsigned char b_dif21631[4] = {

    0x00, 0x00, 0x00, 0x1F
};

unsigned char b_zero[64] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char b_p256_a[64] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
};

unsigned char b_p256_b[64] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
    0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
    0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
};

unsigned char b_p256_gx[64] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
};

unsigned char b_p256_gy[64] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
};

unsigned char b_1[64] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

unsigned char b_difp256[64] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

unsigned char b_p256m1[64] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE
};


unsigned char b_p256[64] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

unsigned char b_p256p1[64] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

unsigned short b_random(unsigned char* out){
    
    srand(time(0));
    unsigned char aux[64];
    int r, i;
    for(i=0; i < 16; i++){

        r = rand()%0x10000;
        aux[2*i+32] = (r>>8)&255;
        aux[2*i+33] = r&255;
        aux[2*i] = 0;
        aux[2*i+1] = 0;
    }
    memcpy(out, aux, 64);
    return 0;
}

unsigned short b_subtr64(unsigned char* a, unsigned char*b, unsigned char* out){

    unsigned char aux[64];
    int i, c = 0, bm;
    for(i=63; i >= 0; i--){

        bm = a[i] - b[i] - c;
        c = bm < 0;
        bm += c*256;
        aux[i] = bm&255;
    }
    memcpy(out, aux, 64);
    return 0;
}

unsigned short b_emaiorigual(unsigned char* a, unsigned char* b){

    for(int i=0; i < 64; i++){

        if(a[i] > b[i])
            return 2;
        if(a[i] < b[i])
            return 1;
    }
    return 0;
}

unsigned short b_zero64(unsigned char*a){

    for(int i=0; i < 64; i++){

        a[i] = 0;
    }
    return 0;
}

unsigned short b_add64(unsigned char* a, unsigned char*b, unsigned char*out){

    unsigned char aux[64];
    int i, bm, c = 0, a1, b1;
    for(i=63; i >=0; i--){

        a1 = a[i]; b1=b[i];
        bm = c+a1+b1;
        aux[i] = bm&255;
        c = bm>>8;
    }
    memcpy(out, aux, 64);
    return 0;
}

unsigned short b_mult64(unsigned char* a, unsigned char* b, unsigned char*out){

    unsigned char aux[64];
    int i, j, idx;
    unsigned short bm, c;
    b_zero64(aux);
//    c = 0;
    for(i=63; i >= 32; i--){

        c = 0;
        idx = i;
        for(j=63; j>=32; j--){

            bm = aux[idx]+ a[i]*b[j] + c;
            aux[idx] = bm&255;
            c = bm>>8;
            idx--;
        }
        aux[idx] = c;
    }
    memcpy(out, aux, 64);
    return 0;
}

unsigned short b_modp256(unsigned char* a, unsigned char* out){

    unsigned char aux[64], m[64], s[64], z[64];
    int i;
    for(i=0; i < 32; i++){

        aux[i] = 0;
        z[i] = 0;
        z[i+32] = 0;
        aux[i+32] = 0;
        m[i] = 0;
        m[i+32] = a[i];
        s[i] = 0;
        s[i+32] = a[i+32];
    }
    int k=0;
    while(b_emaiorigual(m, z) == 2){

        k++;
        b_mult64(b_difp256, m, m);
/*        for(i=0; i <32; i++){

            m[i] = 0;
        }*/
        b_add64(m, s, aux);
        for(i=0; i < 32; i++){

            m[i] = 0;
            m[i+32] = aux[i];
            s[i] = 0;
            s[i+32] = aux[i+32];
        }
    }
    if(b_emaiorigual(s, b_p256) == 2){

        b_subtr64(s, b_p256, s);
    }
    b_add64(s, b_difp256, s);
    if(!s[31]){

        b_subtr64(s, b_difp256, s);
    }
    else{

        s[31] = 0;
    }
    memcpy(out, s, 64);
    return 0;
}

unsigned short b_mult_modp256(unsigned char* a, unsigned char* b, unsigned char* out){

    unsigned char aux[64];
    b_mult64(a, b, aux);
    b_modp256(aux, aux);
    memcpy(out, aux, 64);
    return 0;
}

unsigned short b_subtr_modp256(unsigned char* a, unsigned char* b, unsigned char* out){

    unsigned char a1[64], b1[64], aux[64];
    memcpy(a1, a, 64);
    memcpy(b1, b, 64);
    if(b_emaiorigual(a, b) == 1){

        b_add64(a1, b_p256, a1);
    }
    else{

        b_add64(a1, b_zero, a1);
    }
    b_subtr64(a1, b1, aux);
    memcpy(out, aux, 64);
    return 0;
}

unsigned short b_add_modp256(unsigned char* a, unsigned char* b, unsigned char* out){

    unsigned char aux[64];
    b_add64(a, b, aux);
    b_modp256(aux, aux);
    memcpy(out, aux, 64);
    return 0;
}

unsigned short b_lshift(unsigned char* a, unsigned short n){

    unsigned short bit = n%8, byte = (n-bit)/8, ns = 63-byte;
    unsigned char aux[64];
    int i;
    for(i=0; i < ns; i++){

        aux[i] = a[i+byte] << bit | a[i+byte+1] >> (8-bit);
    }
    aux[i] = a[i+byte] << bit;
    for(i=ns+1; i < 64; i++){

        aux[i] = 0;
    }
    memcpy(a, aux, 64);
    return 0;
}

unsigned short b_rshift(unsigned char* a, unsigned short n){

    unsigned short bit = n%8, byte = (n-bit)/8, ns = 63-byte;
    unsigned char aux[64];
    int i;
    for(i=63; i >= byte+1; i--){

        aux[i] = a[i-byte] >> bit | a[i-byte-1] << (8-bit);
    }
    aux[i] = a[i-byte] >> bit;
    for(i=0; i < byte; i++){

        aux[i] = 0;
    }
    memcpy(a, aux, 64);
    return 0;
}

unsigned short b_div(unsigned char* a, unsigned char* b, unsigned char* r, unsigned char* m){

    unsigned char a1[64], b1[64], r1[64];
    int i, j, bits = 0, c = 0;
    for(i=0; i < 64; i++){

        a1[i] = a[i];
        b1[i] = b[i];
        r1[i] = 0;
        for(j=7; j >= 0; j--){

            c += (b[i] >> j) & 1;
            bits += !c;
        }
    }
    b_lshift(b1, bits);
    for(i=0; i <= bits; i++){

        while(b_emaiorigual(a1, b1) != 1){

            b_subtr64(a1, b1, a1);
            b_add64(r1, b_1, r1);
        }

        b_lshift(r1, i < bits);
        b_rshift(b1, i < bits);
    }
    c = b1[0];
    memcpy(r, r1, 64);
    memcpy(m, a1, 64);
    return 0;
}

unsigned short b_invert(unsigned char* a, unsigned char* out){

    unsigned char a1[64], a2[64], a3[64], a4[64];
    for(int i=0; i < 64; i++){

        a1[i] = a[i];
        a2[i] = 0;
        a3[i] = 0;
        a4[i] = 0;
    }
    a2[63] = 1;

    int k = 0;
    while(b_emaiorigual(a1, b_1)){

        b_div(b_p256, a1, a3, a4);
        b_add64(a3, b_1, a3);
        b_mm(a1, a3, a1);
        b_mm(a2, a3, a2);
//        b_div(a2, b_p256, a4, a2);
//        b_div(a1, b_p256, a4, a1);
        b_div(a1, b_p256, a3, a1);
        k++;
    }
    memcpy(out, a2, 64);
    return 0;
}

unsigned short b_sqpt(unsigned char* x, unsigned char* y, unsigned char* z, unsigned char* outx, unsigned char* outy, unsigned char* outz){

    unsigned char x3[64], y3[64], z3[64], w[64], a[64], b[64];
//  w = 3* X1^2 - 3* Z1^2

    b_mm(x, x, w);
    b_am(w, w, a);
    b_am(w, a, w);

    b_mm(z, z, a);
    b_am(a, a, b);
    b_am(b, a, a);
    b_sm(w, a, w);

//  X3 = 2 * Y1 * Z1 * (w^2 - 8 * X1 * Y1^2 * Z1) mod p

    b_mm(y, y, a);
    b_mm(a, x, a);
    b_mm(a, z, a);
    b_am(a, a, x3);
    b_am(x3, a, x3);
    b_am(x3, a, x3);
    b_am(x3, a, x3);
    b_am(x3, a, x3);
    b_am(x3, a, x3);
    b_am(x3, a, x3);
    b_mm(w, w, a);
    b_sm(a, x3, x3);
    b_mm(x3, z, x3);
    b_mm(x3, y, x3);
    b_am(x3, x3, x3);

//  Y3 = 4 * Y1^2 * Z1 * (3 * w * X1 - 2 * Y1^2 * Z1) - w^3 mod p

    b_mm(w, x, a);
    b_am(a, a, y3);
    b_am(a, y3, y3);

    b_mm(y, y, b);
    b_mm(z, b, b);
    b_am(b, b, b);

    b_sm(y3, b, a);
    b_mm(a, z, a);
    b_mm(a, y, a);
    b_mm(a, y, a);

    b_am(a, a, y3);
    b_am(y3, a, y3);
    b_am(y3, a, y3);

    b_mm(w, w, a);
    b_mm(a, w, a);
    b_sm(y3, a, y3);

//  Z3 = 8 * (Y1 * Z1)^3 mod p

    b_mm(y, z, a);
    b_mm(a, a, b);
    b_mm(b, a, b);

    b_am(b, b, z3);
    b_am(z3, b, z3);
    b_am(z3, b, z3);
    b_am(z3, b, z3);
    b_am(z3, b, z3);
    b_am(z3, b, z3);
    b_am(z3, b, z3);

    memcpy(outx, x3, 64);
    memcpy(outy, y3, 64);
    memcpy(outz, z3, 64);

    return 0;
}

unsigned short b_mpt(unsigned char* x1, unsigned char* y1, unsigned char* z1,
                        unsigned char* x2, unsigned char* y2, unsigned char* z2,
                            unsigned char* outx, unsigned char* outy, unsigned char* outz){


    unsigned char x3[64], y3[64], z3[64], a[64], b[64], u[64], v[64], uu[64], vv[64];

//  u = Y2 * Z1 - Y1 * Z2

    b_mm(y1, z2, a);
    b_mm(y2, z1, u);
    b_sm(u, a, u);

//  v = X2 * Z1 - X1 * Z2

    b_mm(x1, z2, a);
    b_mm(x2, z1, v);
    b_sm(v, a, v);

//  X3 = v * (Z2 * (Z1 * u^2 - 2 * X1 * v^2) - v^3)

    b_mm(u, u, uu);
    b_mm(v, v, vv);

    b_mm(x1, vv, a);
    b_am(a, a, a);

    b_mm(z1, uu, x3);
    b_sm(x3, a, x3);
    b_mm(x3, z2, x3);
    b_mm(vv, v, a);
    b_sm(x3, a, x3);
    b_mm(x3, v, x3);

//  Y3 = Z2 * (3 * X1 * u * v^2 - Y1 * v^3 - Z1 * u^3) + u * v^3

    b_mm(uu, u, a);
    b_mm(z1, a, a);
    b_mm(vv, v, b);
    b_mm(y1, b, b);
    b_am(a, b, a);

    b_mm(u, vv, b);
    b_mm(x1, b, b);
    b_am(b, b, y3);
    b_am(y3, b, y3);

    b_sm(y3, a, y3);
    b_mm(y3, z2, y3);

    b_mm(vv, v, a);
    b_mm(a, u, a);
    b_am(y3, a, y3);

//  Z3 = v^3 * Z1 * Z2

    b_mm(vv, v, z3);
    b_mm(z1, z3, z3);
    b_mm(z2, z3, z3);

    memcpy(outx, x3, 64);
    memcpy(outy, y3, 64);
    memcpy(outz, z3, 64);

    return 0;
}

unsigned short bcswap(unsigned char swap, unsigned char* a, unsigned char* b){

    unsigned char mask = 0-swap, dummy[64];
    for(int i=0; i < 64; i++){

        dummy[i] = mask & (a[i] ^ b[i]);
        a[i] ^= dummy[i];
        b[i] ^= dummy[i];
    }
    return 0;
}

unsigned char b_p256_gen_key(unsigned char* pk, unsigned char* gx, unsigned char* gy, unsigned char* x, unsigned char* y){

    unsigned char x1[64], y1[64], z1[64], xb[64], yb[64], zb[64], a[64];
    int i, j;
    unsigned char k;

    memcpy(x1, gx, 64);
    memcpy(y1, gy, 64);

    memcpy(z1, b_1, 64);

    for(i=32; i < 64; i++){

        for(j=7; j >=0; j--){

            j -= (i==32 && j==7);
            k = (pk[i] >> j) & 1;

            b_sqpt(x1, y1, z1, x1, y1, z1);
            bcswap(!k, xb, x1);
            bcswap(!k, yb, y1);
            bcswap(!k, zb, z1);

            b_mpt(x1, y1, z1, gx, gy, b_1, x1, y1, z1);
            bcswap(!k, xb, x1);
            bcswap(!k, yb, y1);
            bcswap(!k, zb, z1);
        }
    }
    b_invert(z1, a);
    b_mm(x1, a, xb);
    b_mm(y1, a, yb);

    b_mm(z1, a, a);

    memcpy(x, xb, 64);
    memcpy(y, yb, 64);
    return 0;
}

unsigned char b_p256_gen_key_pair(unsigned char* pk, unsigned char* x, unsigned char* y){

    unsigned char x1[64], y1[64], z1[64], xb[64], yb[64], zb[64], a[64];
    int i, j;
    unsigned char k;

    memcpy(x1, b_p256_gx, 64);
    memcpy(y1, b_p256_gy, 64);
    memcpy(z1, b_1, 64);

    for(i=32; i < 64; i++){

        for(j=7; j >=0; j--){

            j -= (i==32 && j==7);
            k = (pk[i] >> j) & 1;

            b_sqpt(x1, y1, z1, x1, y1, z1);
            bcswap(!k, xb, x1);
            bcswap(!k, yb, y1);
            bcswap(!k, zb, z1);

            b_mpt(x1, y1, z1, b_p256_gx, b_p256_gy, b_1, x1, y1, z1);
            bcswap(!k, xb, x1);
            bcswap(!k, yb, y1);
            bcswap(!k, zb, z1);
        }
    }
    b_invert(z1, a);
    b_mm(x1, a, xb);
    b_mm(y1, a, yb);

    b_mm(z1, a, a);

    memcpy(x, xb, 64);
    memcpy(y, yb, 64);
    return 0;
}

unsigned short b_p256_verify_pt(unsigned char x[64], unsigned char y[64]){

    unsigned char z[64], z1[64];
    b_mm(x, x, z);
    b_mm(x, z, z);//x^3

    b_mm(x, b_p256_a, z1);//a*x;

    b_sm(z, z1, z);
    b_am(z, b_p256_b, z);

    b_mm(y, y, z1);

    return b_emaiorigual(z, z1);
}
