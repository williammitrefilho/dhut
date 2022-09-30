#include <prf.h>
#include <stdio.h>
#include <basics.h>

unsigned short sha384_prf(unsigned char *secret, unsigned short secret_len, unsigned char *label, unsigned short label_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out){
    
    unsigned short n_blocks = len/48 + (len%48 > 0), a_label_seed_len = 48+label_len+seed_len;
    unsigned char a_label_seed[a_label_seed_len], *a = a_label_seed, *plabel = a_label_seed, *pseed = a_label_seed, keys[48*n_blocks], *pkeys = keys;
    plabel += 48;
    pseed += 48 + label_len;
    
    memcpy(plabel, label, label_len);
    memcpy(pseed, seed, seed_len);
//    printf("initial state0(%d):\n", a_label_seed_len);printbhex(a_label_seed, a_label_seed_len);printf("\n");
    sha_sha384_hmac(secret, secret_len, plabel, label_len + seed_len, a_label_seed);
//    printf("initial state1(%d):\n", a_label_seed_len);printbhex(a_label_seed, a_label_seed_len);printf("\n");
    
    for(int i = 0; i < n_blocks; i++){
        
        sha_sha384_hmac(secret, secret_len, a_label_seed, a_label_seed_len, pkeys);
        pkeys += 48;
        sha_sha384_hmac(secret, secret_len, a_label_seed, 48, a_label_seed);
//        printf("next state(%d):\n", a_label_seed_len);printbhex(a_label_seed, a_label_seed_len);printf("\n");
    }
    memcpy(out, keys, len);
    return 0;
}