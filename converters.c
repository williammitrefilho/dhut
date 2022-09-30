#include <converters.h>

unsigned char ccharval(unsigned char x){
    
    return ((x - 48)*(x >= 0x30 && x <= 0x39))
            |((x - 55)*(x >= 0x41 && x <= 0x46))
            |((x - 87)*(x >= 0x61 && x <= 102)); 
}

unsigned short prlong(unsigned long long num[4]){
    
    printf("%016llX %016llX %016llX %016llX\n", num[0], num[1], num[2], num[3]);
    return 0;    
}

unsigned short prbytes(unsigned char bytes[32]){
    
    for(int i = 0; i < 32; i++){
        
        printf("%02X", bytes[i]);
        if(i/8 == 7){
            
            printf(" ");
        }
    }
    printf("\n");
    return 0;
}

unsigned short strtobytes(unsigned char str[64], unsigned char bytes[32]){
    
    for(int i = 0; i < 32; i++){
        
        bytes[i] = (ccharval(str[2*i]) << 4) | (ccharval(str[2*i+1]));
    }
    
    return 0;
}

unsigned short btolongi(unsigned char bytes[32], unsigned long long out[4]){
    
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    
    unsigned long long comb;
    
    for(int i = 0; i < 32; i++){
        comb = bytes[i];
        comb <<= 8*(i%8);
        out[3 - i/8] |= comb;
    }
    
    return 0;

}

unsigned short btolong(unsigned char bytes[32], unsigned long long out[4]){
    
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    
    unsigned long long comb;
    
    for(int i = 0; i < 32; i++){
        out[i/8] <<= 8;
        out[i/8] |= bytes[i];
    }
    
    return 0;
}

unsigned short longtobi(unsigned long long num[4], unsigned char bytes[32]){
    
    for(int i = 3; i >= 0; i--){
        
        for(int j = 0; j < 8; j++){
            
            bytes[8*(3-i) + j] = (num[i] >> (8*j)) & 0xFF;
        }
    }
    
    return 0;
}

unsigned short x25519transform(unsigned char bytes[32]){
    
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    
    return 0;
}