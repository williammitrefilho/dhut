#include <x25519.h>

const unsigned long long bm_19[4] = {0, 0, 0, 19};
const unsigned long long bm_x25519[4] = {
    
    0x7FFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFED
};
const unsigned long long bm_x25519_a[4] = {
    
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000076D06 
};

const unsigned long long bm_9[4] = {
    
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000009 
};

const unsigned long long bm_a24[4] = {
    
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x000000000001DB41    
};

unsigned short bm_modx25519(unsigned long long number[4], unsigned long long overflow[4], unsigned long long out[4]){
    
    unsigned long long reg[4] = {0, 0, 0, 0},
                        ovf[4] = {0, 0, 0, 0},
                        ovf1[4] = {0, 0, 0, 0},
                        num[4] = {number[0] & bm_nbit0, number[1], number[2], number[3]};
    
    reg[0] = (overflow[0] << 1) | ((overflow[1] & bm_bit0) >> 63);
    reg[1] = (overflow[1] << 1) | ((overflow[2] & bm_bit0) >> 63);
    reg[2] = (overflow[2] << 1) | ((overflow[3] & bm_bit0) >> 63);
    reg[3] = (overflow[3] << 1) | ((number[0] & bm_bit0) >> 63);
    int i = 1;
    while(reg[0] || reg[1] || reg[2] || reg[3]){

        bm_mult256(reg, bm_19, reg, ovf);
        
        bm_add256(reg, num, num, &ovf1[3]);
        
        bm_add256(ovf, ovf1, ovf, &ovf1[3]);
        reg[0] = (ovf[0] << 1) | ((ovf[1] & bm_bit0) >> 63);
        reg[1] = (ovf[1] << 1) | ((ovf[2] & bm_bit0) >> 63);
        reg[2] = (ovf[2] << 1) | ((ovf[3] & bm_bit0) >> 63);
        reg[3] = (ovf[3] << 1) | ((num[0] & bm_bit0) >> 63);
        num[0] &= bm_nbit0;

        bm_mult256(reg, bm_19, reg, ovf);
        
        bm_add256(reg, num, num, &ovf1[3]);
        bm_add256(ovf, ovf1, ovf, &ovf1[3]);
        
        reg[0] = (ovf[0] << 1) | ((ovf[1] & bm_bit0) >> 63);
        reg[1] = (ovf[1] << 1) | ((ovf[2] & bm_bit0) >> 63);
        reg[2] = (ovf[2] << 1) | ((ovf[3] & bm_bit0) >> 63);
        reg[3] = (ovf[3] << 1) | ((num[0] & bm_bit0) >> 63);
        
        num[0] &= bm_nbit0;
    }
    
    if(bm_emaior256(bm_x25519, num) == 1){
        
        bm_subtr256(num, bm_x25519, num);
    }
    out[0] = num[0];
    out[1] = num[1];
    out[2] = num[2];
    out[3] = num[3];
    return 0;
}

unsigned short bm_multx25519(const unsigned long long a[4], const unsigned long long b[4], unsigned long long result[4]){
    
    unsigned long long num[4], ovf[4];
    bm_mult256(a, b, num, ovf);
    
    bm_modx25519(num, ovf, result);
    
    return 0;
}

unsigned short bm_addx25519(const unsigned long long a[4], const unsigned long long b[4], unsigned long long result[4]){
    
    unsigned long long num[4], ovf[4] = {0, 0, 0, 0};
    bm_add256(a, b, num, &ovf[3]);
    bm_modx25519(num, ovf, result);
    
    return 0;   
}

unsigned short bm_subtrx25519(unsigned long long a[4], unsigned long long b[4], unsigned long long result[4]){
    
    if(bm_emaior256(a, b) == 1){
        
        bm_subtr256(b, a, result);
        bm_subtr256(bm_x25519, result, result);  
    }
    else{
        
        bm_subtr256(a, b, result);
    }
    
    return 0;
}

unsigned short bm_elx25519(unsigned long long u[4], unsigned long long v2[4]){
    
    unsigned long long op1[4], op2[4];
    
    bm_multx25519(u, u, op1);
    bm_multx25519(op1, bm_x25519, op2);
    
    bm_multx25519(u, op1, op1);
    
    bm_addx25519(u, op1, op1);
    bm_addx25519(op2, op1, op1);
    
    v2[0] = op1[0];
    v2[1] = op1[1];
    v2[2] = op1[2];
    v2[3] = op1[3];
    
    return 0;
}

unsigned short cswap(unsigned long long a[4], unsigned long long b[4], unsigned long long swap){
    
    unsigned long long dummy, mask = 0;
    mask -= swap;
    for(int i = 0; i < 4; i++){
        
        dummy = mask & (a[i] ^ b[i]);
        a[i] ^= dummy;
        b[i] ^= dummy;
    }
    
    return 0;
}

unsigned short bm_el25519(const unsigned long long k[4], const unsigned long long u[4], unsigned long long out[4]){
    
    unsigned long long x_1[4] = {u[0], u[1], u[2], u[3]},
                        x_2[4] = {0, 0, 0, 1},
                        z_2[4] = {0, 0, 0, 0},
                        x_3[4] = {u[0], u[1], u[2], u[3]},
                        z_3[4] = {0, 0, 0, 1},
                        swap = 0,
                        k_t, a[4], aa[4], b[4], bb[4], c[4], d[4], da[4], cb[4], e[4];
                        
    for(int i = 1; i < 256; i++){
        
        k_t = (k[i/64] >> (63 - (i%64))) & 1;
        swap ^= k_t;
//        printf("%d ", k_t);
        
        cswap(x_2, x_3, swap);
        cswap(z_2, z_3, swap);
        swap = k_t;
        
        bm_addx25519(x_2, z_2, a);
        bm_multx25519(a, a, aa);
        
        bm_subtrx25519(x_2, z_2, b);
        bm_multx25519(b, b, bb);
        
        bm_subtrx25519(aa, bb, e);
        bm_addx25519(x_3, z_3, c);
        bm_subtrx25519(x_3, z_3, d);
        
        bm_multx25519(d, a, da);
        bm_multx25519(c, b, cb);
        
        bm_addx25519(da, cb, x_3);
        bm_multx25519(x_3, x_3, x_3);
        bm_subtrx25519(da, cb, z_3);
        bm_multx25519(z_3, z_3, z_3);
        bm_multx25519(z_3, x_1, z_3);
        
        bm_multx25519(aa, bb, x_2);
        
        bm_multx25519(bm_a24, e, z_2);
        bm_addx25519(z_2, aa, z_2);
        bm_multx25519(z_2, e, z_2);
    }
    
    cswap(x_2, x_3, swap);
    cswap(z_2, z_3, swap);
    
    bm_invx25519(z_2, z_2);
    bm_multx25519(z_2, x_2, out);
    
    return 0;
}

unsigned short bm_invx25519(unsigned long long n[4], unsigned long long result[4]){
    
    unsigned long long a1[4], a2[4], a3[4], a4[4];
    bm_multx25519(n, n, a1); // 2
    
    bm_multx25519(n, a1, a2); // 3 (2^2 - 1)
    
    bm_multx25519(a1, a1, a1); // 2^2
    bm_multx25519(a1, a1, a1); // 2^3
    bm_multx25519(a1, n, a1); // 2^3 + 1
    bm_multx25519(a1, n, a1); // 2^3 + 2
    bm_multx25519(a1, n, a1); // 2^3 + 3 -- guardar!
    
    bm_multx25519(a2, a2, a4); // 2^3 - 2^1
    bm_multx25519(a4, a4, a4); // 2^4 - 2^2

    bm_multx25519(a2, a4, a4); // 2^4 - 1
    
    for(int i = 4; i < 250; i+=2){
        
        bm_multx25519(a4, a4, a4);
        bm_multx25519(a4, a4, a4);
        bm_multx25519(a2, a4, a4); // 2^250 - 1
    }
    
    for(int i = 250; i < 255; i++){
        
        bm_multx25519(a4, a4, a4);// 2^255 - 2^5
    }

    bm_multx25519(a4, a1, a4); // 2^255 - 2^5 + 2^3 + 3 = 2^255 - 21
    
    result[0] = a4[0];
    result[1] = a4[1];
    result[2] = a4[2];
    result[3] = a4[3];
    
    return 0;
}