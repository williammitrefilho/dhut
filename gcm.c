#include <aes.h>

#define GCM1_BYTE 1
#define GCM1_ULLONG 2

const unsigned long long gcm_r[2] = {
    0xE100000000000000,
    0x0000000000000000
};

const unsigned char gcm_0[16] = {

    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};

unsigned short u64to8(unsigned long long *in, unsigned short in_len, unsigned char *out){

    unsigned short out_len = in_len*8;
    for(int i=0; i < in_len; i++){

        for(int j=0; j < 8; j++){

            out[8*i+j] = (in[i] >> (8*(7-j)))& 0xff;
        }
    }
    return 0;
}

unsigned short u8to64(unsigned char *in, unsigned short in_len, unsigned long long *out){

    unsigned short out_len = in_len/8 + (in_len%8 > 0);
    unsigned long long test;
    for(int i=0; i < out_len; i++){

        out[i] = 0;
        test = 0;
        for(int j=0; j < 8; j++){

            if((8*i + j) == in_len)
                break;

            test = in[8*i+j];
            test = test << (8*(7-j));
            out[i] |= test;
            test = out[i];
            test = 0;
        }
    }
    test = out[0];
    return 0;
}

unsigned short u8to128(unsigned char *in, unsigned short in_len, unsigned long long *out){

    unsigned short out_len = in_len/8 + (in_len%8 > 0);
    unsigned long long test;
    for(int i=0; i < out_len; i++){

        out[i] = 0;
        test = 0;
        for(int j=0; j < 8; j++){

            if((8*i + j) == in_len)
                break;

            test = in[8*i+j];
            test = test << (8*(7-j));
            out[i] |= test;
            test = out[i];
            test = 0;
        }
    }
    if(out_len%2){
        
        out[out_len] = 0;
    }
    test = out[0];
    return 0;
}

unsigned short gcm_to_watch(const unsigned char* data, const unsigned short len, const unsigned short type, unsigned short* out){

    unsigned short test;
    if(type == GCM1_BYTE){

        for(int i=0; i < len; i++){

            out[i] = data[i];
        }
    }
    else if(type == GCM1_ULLONG){

        unsigned long long data_i;
        unsigned long long *ldata = (unsigned long long*)data;
        for(int i=0; i < len; i++){

            for(int j = 0; j < 8; j++){

                data_i = ldata[i];
                test = (ldata[i] >> (8*(7-j))) & 0xff;
                out[8*i+j] = test;
            }
        }
    }
    return 0;
}

unsigned short gcm_zero_watch(unsigned short* p, unsigned short len){

    for(int i=0; i < len; i++){

        p[i] = 0;
    }
    return 0;
}

unsigned short gcm_mult(unsigned long long x[2], unsigned long long y[2], unsigned long long out[2]){

    unsigned long long z[2] = {
        0, 0
    }, v[2] = {

        y[0],
        y[1]
    }, va;
    unsigned short w, xi, ik, lv;
    for(int i=0; i < 128; i++){

        ik =(i/64) > 0;
        w = i%64;
        xi = (x[ik] >> (63-w))&1;
        va = 0 - xi;

        z[0] = z[0]^(v[0]&va);
        z[1] = z[1]^(v[1]&va);

        lv = v[1] & 1;
        v[1] = (v[1] >> 1) | ((v[0]&1) << 63);
        v[0] = v[0] >> 1;

        va = 0 - lv;

        v[0] ^= gcm_r[0]&va;
        v[1] ^= gcm_r[1]&va;
        xi = 0;
    }
    out[0] = z[0];
    out[1] = z[1];
    return 0;
}

unsigned short gcm_ghash(unsigned long long key[2], unsigned long long *x, unsigned short xlen, unsigned long long out[2]){

    unsigned long long y[2] = {0, 0};
    for(int i=0; i < xlen; i++){

        y[0] = y[0]^x[2*i];
        y[1] = y[1]^x[2*i+1];

        gcm_mult(y, key, y);
    }

    out[0] = y[0];
    out[1] = y[1];

    return 0;
}

unsigned short gcm_gctr_aes_256(unsigned long long icb[2], unsigned long long *x, unsigned short xlen, unsigned char key[32], unsigned long long *out){

    int n = xlen/2 + xlen%2;
    unsigned long long cb[2*n], aux[2], aux_f[2*n], acb[2];
    unsigned short byte_watch[64];
    gcm_zero_watch(byte_watch, 64);

    unsigned char aes_blk[16];
    cb[0] = icb[0];
    cb[1] = icb[1];

    for(int i=2; i < 2*n; i+=2){

        cb[i] = cb[i-2];
        cb[i+1] = ((cb[i-1] + 1) & 0x00000000ffffffff) | (cb[i-1] & 0xffffffff00000000);
    }
    for(int i=0; i < 2*n-2; i+=2){

        aux[0] = x[i];
        aux[1] = x[i+1];

        acb[0] = cb[i];
        acb[1] = cb[i+1];

        u64to8(acb, 2, aes_blk);

        aes_encrypt(aes_blk, key, 8, aes_blk);
        u8to64(aes_blk, 16, aux);

        aux_f[i] = aux[0]^x[i];
        aux_f[i+1] = aux[1]^x[i+1];
    }
    aux[0] = x[2*n-2];
    aux[1] = x[2*n-1];

    acb[0] = cb[2*n-2];
    acb[1] = cb[2*n-1];
    u64to8(acb, 2, aes_blk);

    aes_encrypt(aes_blk, key, 8, aes_blk);

    u8to64(aes_blk, 16, aux);

    aux_f[2*n-2] = aux[0]^x[2*n-2];
    aux_f[2*n-1] = aux[1]^x[2*n-1];

    for(int i=0; i < 2*n; i+= 2){

        out[i] = aux_f[i];
        out[i+1] = aux_f[i+1];
    }

    return 0;
}

unsigned short gcm_aes256_gcm(unsigned char* iv, unsigned short iv_len, unsigned char key[32], unsigned char* plaintext, unsigned short ptlen, unsigned char* aad, unsigned short aad_len, unsigned char *out, unsigned char *tag, unsigned short tag_len){

    unsigned long long lh[2], j0[2];
    unsigned char h[16];
    unsigned short byte_watch[64];
    gcm_zero_watch(byte_watch, 64);
    aes_encrypt(gcm_0, key, 8, h);
    u8to64(h, 16, lh);
    gcm_to_watch(lh, 2, GCM1_ULLONG, byte_watch);
    if(iv_len == 12){

        for(int i=0; i < 2; i++){

            j0[i] = 0;
            unsigned long long _t;
            for(int j=0; j < 8; j++){

                if((8*i+j) == iv_len)
                    break;

                _t = iv[8*i+j];
                j0[i] |= _t << (8*(7-j));
            }
        }
        j0[1] |= 1;
    }
    else{

        unsigned short ls = (iv_len/16 + (iv_len%16 > 0))*2 + 2;
        unsigned long long lls[ls];
        for(int i=0; i < ls-1; i++){

            lls[i] = 0;
            for(int j=0; j < 8; j++){

                if((8*i+j) == iv_len)
                    break;
                lls[i] |= iv[8*i + j] << (7-j);
            }
        }
        lls[ls-1] = iv_len*8;
        gcm_ghash(lh, lls, ls, j0);
    }
    unsigned long long j0_1 = j0[1];
    j0[1] = ((j0[1] + 1) & 0xffffffff) | (j0[1] & 0xffffffff00000000);
    unsigned short ctlen = (ptlen/16 + (ptlen%16 > 0))*2;
    unsigned long long c[ctlen];
    c[ctlen-1] = 0;
    c[ctlen-2] = 0;
    u8to64(plaintext, ptlen, c);
    gcm_gctr_aes_256(j0, c, ctlen, key, c);
    j0[1] = j0_1;
    unsigned short paad = (aad_len/16 + (aad_len%16 > 0))*2, slen = ctlen+paad + 2;
    unsigned long long s[slen], *pct = s;
    pct += paad;
    u8to128(aad, aad_len, s);
    u64to8(c, ctlen, out);
    u8to128(out, ptlen, pct);
/*    for(int i = paad; i < slen - 2; i++){

        s[i] = c[i - paad];
    }*/
    s[slen - 2] = aad_len*8;
    s[slen - 1] = ptlen*8;

    gcm_ghash(lh, s, slen/2, s);
    gcm_gctr_aes_256(j0, s, slen, key, s);
    unsigned char bs[8*slen];
    u64to8(s, slen, bs);
    if(tag){
        
        memcpy(tag, bs, tag_len);
    }
    return 0;
}

unsigned short gcm_aes_256_gcm_ad(unsigned char *iv, unsigned short iv_len, unsigned char key[32], unsigned char *ciphertext, unsigned short ctlen, unsigned char *aad, unsigned short aad_len, unsigned char *out, unsigned char *tag, unsigned short tag_len){

    unsigned long long lh[2], j0[2];
    unsigned char h[16];
    unsigned short byte_watch[64];
    gcm_zero_watch(byte_watch, 64);
    aes_encrypt(gcm_0, key, 8, h);
    u8to64(h, 16, lh);
    gcm_to_watch(lh, 2, GCM1_ULLONG, byte_watch);
    if(iv_len == 12){

        for(int i=0; i < 2; i++){

            j0[i] = 0;
            unsigned long long _t;
            for(int j=0; j < 8; j++){

                if((8*i+j) == iv_len)
                    break;

                _t = iv[8*i+j];
                j0[i] |= _t << (8*(7-j));
            }
        }
        j0[1] |= 1;
    }
    else{

        unsigned short ls = (iv_len/16 + (iv_len%16 > 0))*2 + 2;
        unsigned long long lls[ls];
        for(int i=0; i < ls-1; i++){

            lls[i] = 0;
            for(int j=0; j < 8; j++){

                if((8*i+j) == iv_len)
                    break;
                lls[i] |= iv[8*i + j] << (7-j);
            }
        }
        lls[ls-1] = iv_len*8;
        gcm_ghash(lh, lls, ls, j0);
    }
    unsigned short lct_len = ((ctlen/16) + (ctlen%16 > 0))*2;
    unsigned short paad = (aad_len/16 + (aad_len%16 > 0))*2, slen = lct_len+paad + 2;
    unsigned long long s[slen];
    unsigned long long lct[lct_len];
    for(int i=0; i < lct_len; i++){

        lct[i] = 0;
    }
    u8to64(ciphertext, ctlen, lct);
    u8to64(aad, aad_len, s);
    for(int i = paad; i < slen - 2; i++){

        s[i] = lct[i - paad];
    }
    s[slen - 2] = aad_len*8;
    s[slen - 1] = ctlen*8;
    gcm_ghash(lh, s, slen/2, s);
    gcm_gctr_aes_256(j0, s, slen, key, s);

    unsigned long long j0_1 = j0[1];
    j0[1] = ((j0[1] + 1) & 0xffffffff) | (j0[1] & 0xffffffff00000000);
    gcm_gctr_aes_256(j0, lct, lct_len, key, lct);
    for(int i=0; i < lct_len; i++){

        for(int j=0; j < 8; j++){

            if((8*i + j) == ctlen)
                break;

            out[8*i + j] = (lct[i] >> (8*(7 - j))) & 0xff;
        }
    }
    j0[1] = j0_1;
    unsigned char bs[8*slen];
    u64to8(s, slen, bs);
    if(tag){
        
        memcpy(tag, bs, tag_len);
    }
    return 0;
}
