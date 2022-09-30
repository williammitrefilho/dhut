#include <tlsbase.h>
#include <basics.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    
    if(argc < 3){
        
        printf("erro falso\n");
        return 1;
    }

    unsigned char bytes[32];
    unsigned long long k[4], u[4], u1[4];
    
    printf("k:\n%s\n", argv[1]);
    strtobytes(argv[1], bytes);
    x25519transform(bytes);
    btolongi(bytes, k);
    prlong(k);
    
    printf("u:\n%s\n", argv[2]);
    strtobytes(argv[2], bytes);
    btolongi(bytes, u);   
    prlong(u);
    
    bm_el25519(k, u, u1);
    prlong(u1);
    longtobi(u1, bytes);
    printbhex(bytes, 32);
    
    return 0;
}
