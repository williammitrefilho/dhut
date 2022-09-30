/* ========================================================================== */
/*                                                                            */
/*   Filename.c                                                               */
/*   (c) 2012 Author                                                          */
/*                                                                            */
/*   Description                                                              */
/*                                                                            */
/* ========================================================================== */
#include <sha.h>
#include <basics.h>
#include <stdio.h>

void main()
{
    unsigned char transcript_hash[48], master_secret[48], label[16] = "client_finished", a[48];
    FILE *arq = fopen("key_material/transcript_hash.bn", "rb");
    fread(transcript_hash, 1, 48, arq);
    fclose(arq);
    
    arq = fopen("key_material/master_secret.bn", "rb");
    fread(master_secret, 1, 48, arq);
    fclose(arq);
    
    arq = fopen("tstate-client_finished", "rb");
    unsigned short state1_len = 0;
    fseek(arq, 0, SEEK_END);
    state1_len = ftell(arq);
    fseek(arq, 0, SEEK_SET);
    unsigned char state1[state1_len];
    fread(state1, 1, state1_len, arq);
    fclose(arq);
    
    printhex(state1, state1_len);
    printf("\n\n");

    printhex(transcript_hash, 48);
    printf("\n\n");
    
    printhex(master_secret, 48);
    printf("\n\n");
    
    unsigned char ctx[128+state1_len+48], *pctx = ctx;
    pctx += 128;
    for(int i = 0; i < 48; i++){
        
        ctx[i] = master_secret[i] ^ 0x36;
    }
    for(int i = 48; i < 128; i++){
    
        ctx[i] = 0x36;    
    }
    for(int i = 0; i < state1_len; i++){
        
        ctx[i+128] = state1[i];
    }
    sha_sha384(ctx, 128+state1_len, pctx);
    for(int i = 0; i < 128; i++){
        
        ctx[i] ^= 0x36;
        ctx[i] ^= 0x5C;
    }
    sha_sha384(ctx, 176, ctx);
    printf("finished:\n");printhex(ctx, 48);printf("\n");
    
    unsigned char block1[48];
    
    sha_sha384_prf2(master_secret, 48, label, 15, transcript_hash, 48, 48, block1);
    printf("parallel:\n");printhex(block1, 48);printf("\n");
}