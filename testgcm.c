/* ========================================================================== */
/*                                                                            */
/*   Filename.c                                                               */
/*   (c) 2012 Author                                                          */
/*                                                                            */
/*   Description                                                              */
/*                                                                            */
/* ========================================================================== */

#include <basics.h>
#include <stdio.h>
#include <gcm.h>

void main()
{
    
    unsigned char message[] = "GET / HTTP/1.1\r\nHost: gerio.app\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.82 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-US,en;q=0.9,pt-BR;q=0.8,pt;q=0.7\r\n\r\n";
    //q=0.7\r\n\r\n
    unsigned short msg_len = sizeof(message) - 1, keys_len = 0, ad_len = 12+1, ct_len = 0, nonce_len;
    FILE *arq = fopen("key_material/key_block.bn", "rb");
    fseek(arq, 0, SEEK_END);
    keys_len = ftell(arq);
    fseek(arq, 0, SEEK_SET);
    unsigned short keys[keys_len];
    fread(keys, 1, keys_len, arq);
    fclose(arq);
    
    ct_len = msg_len;//16*(msg_len/16 + (msg_len%16 > 0));
    unsigned char ct[ct_len];
    unsigned char ad[12+1] = {
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                                0x17, 0x03, 0x03, 0x01, 0xd9     
                            };
    
    arq = fopen("key_material/nonce.bn", "rb");
    fseek(arq, 0, SEEK_END);
    nonce_len = ftell(arq);
    fseek(arq, 0, SEEK_SET);
    unsigned short nonce[nonce_len];
    fread(nonce, 1, nonce_len, arq);
    fclose(arq);
    
    unsigned char *client_write_key = keys, *client_write_iv = keys, iv[12], *nonce_explicit = iv;
    nonce_explicit += 4;
    client_write_iv += 64;
    memcpy(iv, client_write_iv, 4);
    memcpy(nonce_explicit, nonce, 8);
    printf("nonce_explicit(%d):%d\n", nonce_len - 1, nonce_explicit[nonce_len - 1]);
    nonce_explicit[nonce_len - 1] ++;
    printf("nonce_explicit(%d):%d\n", nonce_len - 1, nonce_explicit[nonce_len - 1]);
    printf("client_write_key:\n");printhex(client_write_key, 32);printf("\n");
    unsigned char tag[16];
    gcm_aes256_gcm(iv, 12, client_write_key, message, msg_len, ad, ad_len, ct, tag, 16);
    printf("ciphertext:\n");printhex(ct, ct_len);printf("\n");
    printf("tag:\n");printhex(tag, 16);printf("\n");
    printf("iv(%d):\n", nonce_len);printhex(iv, 12);printf("\n");
    gcm_aes_256_gcm_ad(iv, 12, client_write_key, ct, ct_len, ad, ad_len, ct, tag, 16);
    printf("de-ciphertext:\n");printhex(ct, ct_len);printf("\n");
}