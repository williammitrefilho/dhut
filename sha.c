#include <stdio.h>
#include <stdlib.h>
#include <sha.h>

#define sha256_lmask 0xffffffff

unsigned long int sha256_k[64] = {

      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
      0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
      0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
      0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
      0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
      0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
      0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
      0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

unsigned long sha256_h0[8] = {

     0x6a09e667,
     0xbb67ae85,
     0x3c6ef372,
     0xa54ff53a,
     0x510e527f,
     0x9b05688c,
     0x1f83d9ab,
     0x5be0cd19
};

unsigned char* msgpad(unsigned char* msg, int m_len, int*p_len){

    int pm_len = m_len + 1;
    int bitlen = m_len*8;
    while(pm_len%64 != 56){

        pm_len++;
    }
    unsigned char* padded_msg = (unsigned char*) malloc(pm_len+8);
    for(int i=0; i < m_len; i++){

        padded_msg[i] = msg[i];
    }
    padded_msg[m_len] = 0x80;
    m_len++;

    for(int i= m_len; i < pm_len; i++){

        padded_msg[i] = 0x00;
    }
    m_len--;
    unsigned short int d;
    for(int i=0; i < 4; i++){

        padded_msg[pm_len+i] = 0x00;
    }
    for(int i=0; i < 4; i++){

        d = (bitlen >> (8*i)) & 255;
        padded_msg[pm_len+7-i] = d;

    }
    *p_len = pm_len+8;
    return padded_msg;
}

unsigned char* rshift(unsigned char* bytes, int b_len, int n){

    if(n > 7)
        n = 7;

    if(n < 1)
        n = 1;

    int n_len = b_len - 1;
    unsigned char k;
    int bits = ((1 << n) -1) << (8-n);
    for(int i=0; i < n_len; i++){

        k = bytes[i];
        bytes[i] = (bytes[i] << n) | ((bytes[i+1] & bits) >> (8-n));
        k = bytes[i];
        k = bytes[i];
    }
    bytes[n_len] = bytes[n_len] << n;

    return bytes;
}

unsigned char* lshift(unsigned char* bytes, int b_len, int n){

    if(n > 7)
        n = 7;

    if(n < 1)
        n = 1;

    int n_len = b_len - 1;
    unsigned char k;
    int bits = (1 << n) -1;
    for(int i=b_len; i > 0; i--){

        k = bytes[i];
        bytes[i] = (bytes[i] >> n) | ((bytes[i-1] & bits) << (8-n));
        k = bytes[i];
        k = bytes[i];
    }
    bytes[0] = bytes[0] >> n;

    return bytes;
}

unsigned char *rotr(unsigned char*bytes, int b_len, int n){

    if(n < 1)
        n = 1;

    if(n > (8*b_len-1))
        n = 8*b_len-1;

    unsigned char* aux = (unsigned char*)malloc(b_len);
    for(int i=0; i < b_len; i++){

        aux[i] = bytes[i];
    }

    int c_n = 8*b_len - n;

    for(int i=0; i < n; i++){

        lshift(bytes, b_len, 1);
    }
    for(int i=0; i < c_n; i++){

        rshift(aux, b_len, 1);
    }
    for(int i=0; i < b_len; i++){

        bytes[i] = bytes[i] | aux[i];
    }
    free(aux);
    return bytes;
}

unsigned char *rotl(unsigned char*bytes, int b_len, int n){

    if(n < 1)
        n = 1;

    if(n > (8*b_len-1))
        n = 8*b_len-1;

    unsigned char* aux = (unsigned char*)malloc(b_len);
    for(int i=0; i < b_len; i++){

        aux[i] = bytes[i];
    }

    int c_n = 8*b_len - n;

    for(int i=0; i < n; i++){

        rshift(bytes, b_len, 1);
    }
    for(int i=0; i < c_n; i++){

        lshift(aux, b_len, 1);
    }
    for(int i=0; i < b_len; i++){

        bytes[i] = bytes[i] | aux[i];
    }
    free(aux);
    return bytes;
}

unsigned long sha256_ch(unsigned long x, unsigned long y, unsigned long z){

    return (x&y)^((~x)&z);
}

unsigned long sha256_maj(unsigned long x, unsigned long y, unsigned long z){

    return (x&y)^(x&z)^(y&z);
}

void btostr(unsigned char byte, unsigned char* str){

    for(int i=0; i < 8; i++){

        str[i] = 0x30;
    }
    str[8] = 0x00;
    for(int i=7; i >= 0; i--){

        if(byte & (1<<i))
            str[7-i] = 0x31;
    }
}

unsigned long u_rotr(unsigned long x, int n){

    if(n < 1)
        n = 1;

    if(n > 31)
        n = 31;

    return (x>>n)|(x<<(32-n));
}

unsigned long u_rotl(unsigned long x, int n){

    if(n < 1)
        n = 1;

    if(n > 31)
        n = 31;

    return (x<<n)|(x>>(32-n));
}

unsigned long sha256_bsig0(unsigned long x){

    return u_rotr(x, 2)^u_rotr(x, 13)^u_rotr(x, 22);
}

unsigned long sha256_bsig1(unsigned long x){

    return u_rotr(x, 6)^u_rotr(x, 11)^u_rotr(x, 25);
}

unsigned long sha256_ssig0(unsigned long x){

    return u_rotr(x, 7)^u_rotr(x, 18)^(x>>3);
}

unsigned long sha256_ssig1(unsigned long x){

    return u_rotr(x, 17)^u_rotr(x, 19)^(x>>10);
}

int sha256(unsigned char* msg, int msglen, unsigned long* hashout){

    int pm_len, ibmsg = 0;
    unsigned char* padded_msg = msgpad(msg, msglen, &pm_len);
    int n_blocks= pm_len/64;
    unsigned long blocks[n_blocks][16];
    unsigned long db;
    for(int i=0; i < n_blocks; i++){

        for(int j=0; j < 16; j++){

            blocks[i][j] = 0;
            for(int k=0; k < 4; k++){

                db = (padded_msg[ibmsg] << ((3-k)*8));
                blocks[i][j] |= db;
                db = blocks[i][j];

                ibmsg++;
            }
        }
    }
    db = 0;
    free(padded_msg);
    unsigned long sha256_h[8];
    for(int j=0; j < 8; j++){

        db = sha256_h0[j];
        sha256_h[j] = sha256_h0[j];
    }
    for(int i=0; i < n_blocks; i++){


        unsigned long wt[64];
        for(int j=0; j < 16; j++){

            wt[j] = blocks[i][j];
        }
        for(int j = 16; j < 64; j++){

            wt[j] = sha256_ssig1(wt[j-2])+wt[j-7]+sha256_ssig0(wt[j-15])+wt[j-16];
        }

        unsigned long a, b, c, d, e, f, g, h, t1, t2;
        a = sha256_h[0];
        b = sha256_h[1];
        c = sha256_h[2];
        d = sha256_h[3];
        e = sha256_h[4];
        f = sha256_h[5];
        g = sha256_h[6];
        h = sha256_h[7];
        for(int j=0; j < 64; j++){

            t1 = h + sha256_bsig1(e) + sha256_ch(e, f, g) + sha256_k[j] + wt[j];
            t2 = sha256_bsig0(a) + sha256_maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
            db = a;
        }
        sha256_h[0] = sha256_h[0]+a;
        sha256_h[1] = sha256_h[1]+b;
        sha256_h[2] = sha256_h[2]+c;
        sha256_h[3] = sha256_h[3]+d;
        sha256_h[4] = sha256_h[4]+e;
        sha256_h[5] = sha256_h[5]+f;
        sha256_h[6] = sha256_h[6]+g;
        sha256_h[7] = sha256_h[7]+h;

        for(int j=0; j < 8; j++){

            db = sha256_h[j];
            db = 1;
        }
    }
    for(int i=0; i < 8; i++){

        hashout[i] = sha256_h[i];
    }
    db = 7;
    return 0;
}

int sha256_b(unsigned char *msg, int msg_len, unsigned char out[32]){

    unsigned long hash[8];
    sha256(msg, msg_len, hash);
    for(int i = 0; i < 8; i++){

        for(int j = 0; j < 4; j++){

            out[4*i + j] = (hash[i] >> 8*(3-j)) & 0xff;
        }
    }
    return 0;
}

unsigned short sha_sha256_hmac(unsigned char *key, unsigned short key_len, unsigned char *msg, unsigned short msg_len, unsigned char out[32]){

    unsigned char state[64+msg_len+32], *pstate = state;
    for(int i=0; i < key_len; i++){

        state[i] = key[i] ^0x36;
    }
    for(int i = key_len; i < 64; i++){

        state[i] = 0x36;
    }
    for(int i=64; i < (64+msg_len); i++){

        state[i] = msg[i-64];
    }
    pstate += 64;
    sha256_b(state, 64+msg_len, pstate);

    for(int i = 0; i < 64; i++){

        state[i] ^= 0x36;
        state[i] ^= 0x5C;
    }

    sha256_b(state, 96, out);

    return 0;
}

unsigned short sha_sha256_p_hash(unsigned char *secret, unsigned short secret_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out){

    unsigned short n = (len/32) + (len%32 > 0), concat_len = 32+seed_len;
    unsigned char a[32*n], *pa = a, *pa2 = a, concat[concat_len], filename[15];
    sha_sha256_hmac(secret, secret_len, seed, seed_len, pa);
//    sprintf(filename, "a_schedule-%03d.bn", len);
    for(int i = 1; i < n; i++){

        pa2 += 32;
        sha_sha256_hmac(secret, secret_len, pa, 32, pa2);
        pa += 32;
    }
/*    FILE* arquivo = fopen(filename, "wb");
    fwrite(a, 1, 32*n, arquivo);
    fclose(arquivo);
    sprintf(filename, "seed-%03d.bn", len);
    arquivo = fopen(filename, "wb");
    fwrite(seed, 1, seed_len, arquivo);
    fclose(arquivo);
    sprintf(filename, "secret-%03d.bn", len);
    arquivo = fopen(filename, "wb");
    fwrite(secret, 1, secret_len, arquivo);
    fclose(arquivo);*/
    pa = a;
    pa2 = a;
    for(int i = 0; i < n; i++){

        for(int j = 0; j < 32; j++){

            concat[j] = pa[j];
        }
        for(int j = 32; j < concat_len; j++){

            concat[j] = seed[j-32];
        }
        sha_sha256_hmac(secret, secret_len, concat, concat_len, pa);
        pa += 32;
    }
    for(int i = 0; i < len; i++){

        out[i] = a[i];
    }
    return 0;
}

unsigned short sha_sha256_prf(unsigned char *secret, unsigned short secret_len, unsigned char *label, unsigned short label_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out){

    unsigned short labelseed_len = label_len+seed_len;
    unsigned char labelseed[labelseed_len];

    for(int i = 0; i < label_len; i++){

        labelseed[i] = label[i];
    }
    for(int i = label_len; i < labelseed_len; i++){

        labelseed[i] = seed[i - label_len];
    }
    sha_sha256_p_hash(secret, secret_len, labelseed, labelseed_len, len, out);
    return 0;
}

unsigned char* lbtostr(unsigned long num){

    unsigned char* strn = (unsigned char*)malloc(33);
    for(int i=31; i >= 0; i--){

        strn[31-i] = 0x30 | ((num & (1<<i))>>i);
    }
    strn[32] = 0x00;
    return strn;
}

const unsigned long sha_sha1_k[4] = {

    0x5A827999,
    0x6ED9EBA1,
    0x8F1BBCDC,
    0xCA62C1D6
};

const unsigned long sha_sha1_h[5] = {

    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0
};

const unsigned long sha_sha1_f1(unsigned long b, unsigned long c, unsigned long d){

    return (b&c) | ((~b) & d);
}
const unsigned long sha_sha1_f2(unsigned long b, unsigned long c, unsigned long d){

    return b^c^d;
}
const unsigned long sha_sha1_f3(unsigned long b, unsigned long c, unsigned long d){

    return (b&c)^(b&d)^(c&d);
}
const unsigned long sha_sha1_f4(unsigned long b, unsigned long c, unsigned long d){

    return b^c^d;
}
unsigned long sha_sha1_s(unsigned short n, unsigned long x){

    return (x << n) | (x >> (32-n));
}

unsigned short sha_sha1(unsigned char *msg, unsigned short msg_len, unsigned char out[20]){

    int nb = (msg_len/64) + ((msg_len%64) > 0) + ((msg_len%64) > 55);
    unsigned long blocks[16*nb];
    for(int i=0; i < 16*nb; i++){

        blocks[i] = 0;
        for(int j=0; j < 4; j++){

            blocks[i] <<= 8;
            if((4*i + j) < msg_len){

                blocks[i] |= msg[4*i + j];
            }
            else if((4*i + j) == msg_len){

                blocks[i] |= 0x80;
            }
        }
    }
    unsigned long long msglen = 8*msg_len;
    blocks[16*nb - 2] = msglen >> 32;
    blocks[16*nb - 1] = msglen & 0xffffffff;

    unsigned long h[5], w[80], a, b, c, d, e, tmp, t1;
    h[0] = sha_sha1_h[0];
    h[1] = sha_sha1_h[1];
    h[2] = sha_sha1_h[2];
    h[3] = sha_sha1_h[3];
    h[4] = sha_sha1_h[4];

    for(int i=0; i < nb; i++){

        for(int j=0; j < 16; j++){

            w[j] = blocks[16*i + j];
        }
        for(int j=16; j < 80; j++){

            w[j] = sha_sha1_s(1, w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]);
        }
        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];

        for(int j=0; j < 80; j++){

            if((j/20) == 0){

                t1 = sha_sha1_f1(b, c, d);
            }
            else if((j/20) == 1){

                t1 = sha_sha1_f2(b, c, d);
            }
            else if((j/20) == 2){

                t1 = sha_sha1_f3(b, c, d);
            }
            else{

                t1 = sha_sha1_f4(b, c, d);
            }
            tmp = sha_sha1_s(5, a) + t1 + e + w[j] + sha_sha1_k[j/20];
            e = d;
            d = c;
            c = sha_sha1_s(30, b);
            b = a;
            a = tmp;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
    }
    for(int i=0; i < 5; i++){

        for(int j = 0; j < 4; j++){

            out[4*i + j] = h[i] >> 8*(3-j);
        }
    }
    return 0;
}

unsigned short sha_sha1_hmac(unsigned char *key, unsigned short key_len, unsigned char *msg, unsigned short msg_len, unsigned char out[20]){

    unsigned char state[64+msg_len+20], *pstate = state;
    for(int i=0; i < key_len; i++){

        state[i] = key[i] ^0x36;
    }
    for(int i = key_len; i < 64; i++){

        state[i] = 0x36;
    }
    for(int i=64; i < (64+msg_len); i++){

        state[i] = msg[i-64];
    }
    pstate += 64;
    sha_sha1(state, 64+msg_len, pstate);

    for(int i = 0; i < 64; i++){

        state[i] ^= 0x36;
        state[i] ^= 0x5C;
    }

    sha_sha1(state, 84, out);

    return 0;
}

unsigned short sha_sha1_p_hash(unsigned char *secret, unsigned short secret_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out){

    unsigned short n = (len/20) + (len%20 > 0), concat_len = 20+seed_len;
    unsigned char a[20*n], *pa = a, *pa2 = a, concat[concat_len], filename[15];
    sha_sha1_hmac(secret, secret_len, seed, seed_len, pa);
    sprintf(filename, "a_schedule-%03d.bn", len);
    for(int i = 1; i < n; i++){

        pa2 += 20;
        sha_sha1_hmac(secret, secret_len, pa, 20, pa2);
        pa += 20;
    }
    FILE* arquivo = fopen(filename, "wb");
    fwrite(a, 1, 20*n, arquivo);
    fclose(arquivo);
    pa = a;
    pa2 = a;
    for(int i = 0; i < n; i++){

        for(int j = 0; j < 20; j++){

            concat[j] = pa[j];
        }
        for(int j = 20; j < concat_len; j++){

            concat[j] = seed[j-20];
        }
        sha_sha1_hmac(secret, secret_len, concat, concat_len, pa);
        pa += 20;
    }
    for(int i = 0; i < len; i++){

        out[i] = a[i];
    }
    return 0;
}

unsigned short sha_sha1_prf(unsigned char *secret, unsigned short secret_len, unsigned char *label, unsigned short label_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out){

    unsigned short labelseed_len = label_len+seed_len;
    unsigned char labelseed[labelseed_len];

    for(int i = 0; i < label_len; i++){

        labelseed[i] = label[i];
    }
    for(int i = label_len; i < labelseed_len; i++){

        labelseed[i] = seed[i - label_len];
    }
    sha_sha1_p_hash(secret, secret_len, labelseed, labelseed_len, len, out);
    return 0;
}

unsigned short sha_sha1_tls12_compute_master_secret(unsigned char *pre_master_secret, unsigned short pre_master_secret_len, unsigned char client_hello_random[32], unsigned char server_hello_random[32], unsigned char out[48]){

    unsigned char seed[64], label[] = "master secret";
    for(int i = 0; i < 32; i++){

        seed[i] = client_hello_random[i];
        seed[i+32] = server_hello_random[i];
    }
    sha_sha1_prf(pre_master_secret, pre_master_secret_len, label, sizeof(label) - 1, seed, 64, 48, out);
    return 0;
}

unsigned short sha_sha1_tls12_aes256_derive_keys(unsigned char master_secret[48], unsigned char client_hello_random[32], unsigned char server_hello_random[32], unsigned char out_block[136]){

    unsigned char label[] = "key expansion", seed[64];
    for(int i = 0; i < 32; i++){

        seed[i] = client_hello_random[i];
        seed[i+32] = server_hello_random[i];
    }
    sha_sha1_prf(master_secret, 48, label, sizeof(label) - 1, seed, 64, 136, out_block);
    return 0;
}

const unsigned char sha_sha384_ipad[128] = {

    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,

    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
    0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
};

const unsigned char sha_sha384_opad[128] = {

    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,

    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
    0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C
};

const unsigned long long sha_sha384_init[8] = {

    0xcbbb9d5dc1059ed8,
    0x629a292a367cd507,
    0x9159015a3070dd17,
    0x152fecd8f70e5939,
    0x67332667ffc00b31,
    0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7,
    0x47b5481dbefa4fa4
};

const unsigned long long sha_sha384_words[80] = {

    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

unsigned long long sha_rotr64(unsigned short n, unsigned long long x){

    return (x>>n) | (x << (64-n));
}

unsigned long long sha_rotl64(unsigned short n, unsigned long long x){

    return (x<<n) | (x >> (64-n));
}

unsigned long long sha_sha384_ch(unsigned long long x, unsigned long long y, unsigned long long z){

    return (x & y) ^ ((~x) & z);
}

unsigned long long sha_sha384_maj(unsigned long long x, unsigned long long y, unsigned long long z){

    return (x & y) ^ (x & z) ^ (y & z);
}

unsigned long long sha384_bsig0(unsigned long long x){

    return sha_rotr64(28, x) ^ sha_rotr64(34, x) ^ sha_rotr64(39, x);
}

unsigned long long sha384_bsig1(unsigned long long x){

    return sha_rotr64(14, x) ^ sha_rotr64(18, x) ^ sha_rotr64(41, x);
}

unsigned long long sha384_ssig0(unsigned long long x){

    return sha_rotr64(1, x) ^ sha_rotr64(8, x) ^ (x>>7);
}

unsigned long long sha384_ssig1(unsigned long long x){

    return sha_rotr64(19, x) ^ sha_rotr64(61, x) ^ (x>>6);
}

unsigned short sha_sha384(unsigned char* msg, unsigned int msg_len, unsigned char *out){

    unsigned int w_msg_len = (msg_len/128) + (msg_len%128 > 0) + (msg_len == 0) + (msg_len%128 > 112);
    unsigned int b_msg_len = msg_len*8, pos;
    unsigned long long w_msg[w_msg_len*16], hh[8];
    for(int i=0; i < w_msg_len; i++){

        for(int j=0; j < 16; j++){
        
            w_msg[16*i+j] = 0;
            for(int k=0; k < 8; k++){

                w_msg[16*i + j] <<= 8;
                pos = 128*i + 8*j + k;
//                printf("%d ", pos);
                if(pos < msg_len){

                    w_msg[16*i + j] |= msg[pos];
                }
                else if(pos == msg_len){

                    w_msg[16*i + j] |= 0x80;
                }
            }
        }
    }
    int wpos = msg_len/8, bpos = msg_len%8;
//    printf("wpos:%d, bpos:%d\n", wpos, bpos);
    w_msg[16*w_msg_len - 1] = b_msg_len;
    for(int i = 0; i < 16*w_msg_len; i++){
        
//        printf("%016llX\n", w_msg[i]);
    }

    unsigned long long wt[80];
    unsigned long long a, b, c, d, e, f, g, h, t1, t2;

    hh[0] = sha_sha384_init[0];
    hh[1] = sha_sha384_init[1];
    hh[2] = sha_sha384_init[2];
    hh[3] = sha_sha384_init[3];
    hh[4] = sha_sha384_init[4];
    hh[5] = sha_sha384_init[5];
    hh[6] = sha_sha384_init[6];
    hh[7] = sha_sha384_init[7];

    for(int i=0; i < w_msg_len; i++){

        for(int j=0; j < 16; j++){

            wt[j] = w_msg[16*i + j];
        }
        for(int j=16; j < 80; j++){

            wt[j] = sha384_ssig1(wt[j-2]) + wt[j-7] + sha384_ssig0(wt[j-15]) + wt[j-16];
        }

        a = hh[0];
        b = hh[1];
        c = hh[2];
        d = hh[3];
        e = hh[4];
        f = hh[5];
        g = hh[6];
        h = hh[7];

        for(int j = 0; j < 80; j++){

            t1 = h + sha384_bsig1(e) + sha_sha384_ch(e, f, g) + sha_sha384_words[j] + wt[j];
            t2 = sha384_bsig0(a) + sha_sha384_maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1+t2;
        }

        hh[0] += a;
        hh[1] += b;
        hh[2] += c;
        hh[3] += d;
        hh[4] += e;
        hh[5] += f;
        hh[6] += g;
        hh[7] += h;
    }
    for(int i=0; i < 6; i++){

        for(int j=0; j < 8; j++){

            out[8*i+j] = (hh[i] >> (8*(7-j))) & 0xff;
        }
    }
    return 0;
}

unsigned short sha_sha384_hmac(unsigned char *key, unsigned short key_len, unsigned char *msg, unsigned short msg_len, unsigned char *out){

    unsigned char state[128 + msg_len + 48], *pstate = state;
    pstate += 128;
    for(int i=0; i < key_len; i++){

        state[i] = key[i] ^ 0x36;
    }
    for(int i = key_len; i < 128; i++){

        state[i] = 0x36;
    }
    for(int i=0; i < msg_len; i++){

        state[128+i] = msg[i];
    }
    sha_sha384(state, 128+msg_len, pstate);
    for(int i=0; i < 128; i++){

        state[i] ^= 0x36;
        state[i] ^= 0x5C;
    }
    
    sha_sha384(state, 176, state);
    for(int i=0; i < 48; i++){

        out[i] = state[i];
    }

    return 0;
}

unsigned short sha_sha384_p_hash(unsigned char *secret, unsigned short secret_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out){

    unsigned short n = (len/48) + (len%48 > 0), concat_len = 48+seed_len;
    unsigned char a[48*n], *pa = a, *pa2 = a, concat[concat_len];
    sha_sha384_hmac(secret, secret_len, seed, seed_len, pa);

    for(int i = 1; i < n; i++){

        pa2 += 48;
        sha_sha256_hmac(secret, secret_len, pa, 48, pa2);
        pa += 48;
    }

    pa = a;
    pa2 = a;
    for(int i = 0; i < n; i++){

        for(int j = 0; j < 48; j++){

            concat[j] = pa[j];
        }
        for(int j = 48; j < concat_len; j++){

            concat[j] = seed[j-32];
        }
        sha_sha256_hmac(secret, secret_len, concat, concat_len, pa);
        pa += 48;
    }
    for(int i = 0; i < len; i++){

        out[i] = a[i];
    }
    return 0;
}

unsigned short sha_sha384_prf2(unsigned char *secret, unsigned short secret_len, unsigned char *label, unsigned short label_len, unsigned char *seed, unsigned short seed_len, unsigned short len, unsigned char *out){

    unsigned short labelseed_len = label_len+seed_len;
    unsigned char labelseed[labelseed_len];

    for(int i = 0; i < label_len; i++){

        labelseed[i] = label[i];
    }
    for(int i = label_len; i < labelseed_len; i++){

        labelseed[i] = seed[i - label_len];
    }
    sha_sha384_p_hash(secret, secret_len, labelseed, labelseed_len, len, out);
    return 0;
}

unsigned short sha_sha384_hkdf_expand(unsigned char *prk, unsigned short prk_len, unsigned char *info, unsigned short info_len, unsigned short l, unsigned char *out){

    unsigned short n = (l/48) + (l%48 > 0), concat_len = prk_len+48+info_len+1;
    unsigned char t[48*(n+1)], *pt = t;
    unsigned char concat[concat_len];
    for(int i=0; i < 48; i++){

        t[i] = 0;
    }
    for(int i=1; i <= n; i++){

        for(int j=0; j < (48*(i > 1)); j++){

            concat[j] = t[48*(i-1)+ j];
        }
        for(int j=(48*(i > 1)); j < (48*(i > 1))+info_len; j++){

            concat[j] = info[j -(48*(i > 1))];
        }
        concat[(48*(i > 1))+info_len] = i;
        pt += 48*i;
        sha_sha384_hmac(prk, prk_len, concat, (48*(i > 1))+info_len+1, pt);
        pt -= 48*i;
    }
    FILE* arq = fopen("secret_expand_t.bn", "wb");
    fwrite(prk, 1, prk_len, arq);
    fwrite(t, 1, 48*(n+1), arq);
    fclose(arq);
    for(int i=48; i < 48+l; i++){

        out[i-48] = t[i];
    }
    return 0;
}

unsigned short sha_hkdf_sha384_expand_label(unsigned char secret[48], unsigned char *label, unsigned short label_len, unsigned char *context, unsigned short ctx_len, unsigned short length, unsigned char *out){

    unsigned short hkdf_label_len = 1+6+label_len+1+ctx_len;
    unsigned char hkdf_label[2+hkdf_label_len];

    hkdf_label[0] = length >> 8;
    hkdf_label[1] = length & 0xff;
    hkdf_label[2] = (label_len+6) & 0xff;
    hkdf_label[3] = 't';
    hkdf_label[4] = 'l';
    hkdf_label[5] = 's';
    hkdf_label[6] = '1';
    hkdf_label[7] = '3';
    hkdf_label[8] = ' ';

    for(int i=0; i < label_len; i++){

        hkdf_label[i+9] = label[i];
    }
    hkdf_label[9+label_len] = ctx_len;
    for(int i=0; i < ctx_len; i++){

        hkdf_label[10+label_len+i] = context[i];
    }
    sha_sha384_hkdf_expand(secret, 48, hkdf_label, hkdf_label_len+2, length, out);
    FILE* arq = fopen("hkdf_label.bn", "wb");
    fwrite(hkdf_label, 1, hkdf_label_len+2, arq);
    fclose(arq);
    return 0;
}