#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <p256.h>
#include <sha.h>
#include <cbc.h>
#include <tlsbase.h>
#include <time.h>
#include <basics.h>
#include <x25519.h>

unsigned short tls_last_error = 0;

unsigned char label_extended_master_secret[23] = "extended master secret";
unsigned char label_key_expansion[14] = "key expansion";
unsigned char label_client_finished[16] = "client finished";
unsigned char tls_client_random[64];

unsigned char b_change_cipher_spec[6] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};

unsigned short tls_free_cipher_spec(TLSCipherSpec *spec){
    
    free(spec->master_secret);
    free(spec->ecdhe_private_key);
    free(spec->client_write_mac_key);
    free(spec->server_write_mac_key);
    free(spec->client_write_key);
    free(spec->server_write_key);
    free(spec);
    if(spec->other_params){
        printf("freeing op\n");
        free(spec->other_params);
        printf("freed\n");
    }
    
    return 0;
}

TLSClient* tls_connect(unsigned char *server_name, unsigned char *port){
    
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(!s){
        
        printf("erro socket:%d\n", (int)GetLastError());
        return 0;
    }
    struct addrinfo *pResult, hints;
    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    int r = getaddrinfo((char*)server_name, (char*)port, &hints, &pResult);
    if(r){
        
        printf("erro:%d\n", r);
        return 0;
    }
    
    r = connect(s, pResult->ai_addr, pResult->ai_addrlen);
    if(r){
        
        printf("erro connect:%d\n", r);
        return 0;    
    }
    
    TLSClient *client = (TLSClient*)malloc(sizeof(TLSClient));
    client->last_hello_msg = 0x00;
    client->messages = (TLSMessage**)malloc(10*sizeof(TLSMessage*));
    client->socket = s;
    client->transcript_len = 0;
    client->transcript = 0;
    client->session_id_len = 0;
    client->currentSpec = 0;
    client->nextSpec = 0;
    client->n_messages = 0;
    client->application_data = 0;
    client->application_data_len = 0;
    client->certificate_needed = 0;
    client->verify_data = 0;
    
    return client;            
}

unsigned short tls_set_ecdhe_private_key(TLSClient *client, unsigned char *ecdhe_private_key, unsigned short ecdhe_private_key_len){
    
    if(client->nextSpec){
        
        tls_free_cipher_spec(client->nextSpec);
    }

    client->nextSpec = (TLSCipherSpec*)malloc(sizeof(TLSCipherSpec));

    client->nextSpec->ecdhe_private_key = (unsigned char*)malloc(ecdhe_private_key_len);
    client->nextSpec->ecdhe_private_key_len = ecdhe_private_key_len;
    memcpy(client->nextSpec->ecdhe_private_key, ecdhe_private_key, client->nextSpec->ecdhe_private_key_len);
    
    client->nextSpec->master_secret = 0;
    client->nextSpec->master_secret_len = 0;
    
    client->nextSpec->client_write_mac_key = 0;
    client->nextSpec->server_write_mac_key = 0;
    client->nextSpec->client_write_mac_key_len = 0;
    client->nextSpec->server_write_mac_key_len = 0;
    
    client->nextSpec->client_write_key = 0;
    client->nextSpec->server_write_key = 0;
    client->nextSpec->client_write_key_len = 0;
    client->nextSpec->server_write_key_len = 0;
    client->nextSpec->seq_number = 0;
    client->nextSpec->other_params = 0;
    for(int i = 0; i < client->n_messages; i++){
        
        if(client->messages[i]->type == TLSM_SERVER_HELLO){
            
            TLSServerHelloParams *params = (TLSServerHelloParams*)client->messages[i]->params;
            client->nextSpec->cipher_suite = params->cipher_suite;
            break;
        }
    }
    
    return 0;
}

void printbhex(unsigned char *data, unsigned short len){
    
    for(int i = 0; i < len; i++){
    
        if(i%16 == 0)
            printf("\n");
            
        printf("%02X", data[i]);    
    }
}

unsigned short tls_free_client_messages(TLSClient *client){
    
    for(int i = 0; i < client->n_messages; i++){
        
        TLSMessage* message = client->messages[i];
            
        if(message->type == 0x01){
            
            TLSClientHelloParams *params = (TLSClientHelloParams*)message->params;
            for(int j = 0; j < params->n_extensions; j++){
            
                if(params->extensions[j]->data_len){

                    free(params->extensions[j]->data);
                }
            }
            if(params->cipher_suites)
                free(params->cipher_suites);
            
            free(params->extensions);
            free(params);
        }
        else if(message->type == 0x02){

            TLSServerHelloParams *params = (TLSServerHelloParams*)message->params;
            for(int j = 0; j < params->n_extensions; j++){
                
//                    printf("    extension type:%04X\n", params->extensions[j]->type);
                if(params->extensions[j]->data_len){
                    
                    free(params->extensions[j]->data);
                }
            }
            free(params->extensions);
            free(params);
        }
        else if(message->type == 0x0B){
            
            TLSCertificateParams *params = (TLSCertificateParams*)message->params;

            free_entity_list(params->certificates);
            free(params);
        }
        else if(message->type == 0x0C){
            
            TLSServerKeyExchangeParams *params = (TLSServerKeyExchangeParams*)message->params;
            free(params->key_data);
            free(params);
        }
        else if(message->type == 0x10){
            
            TLSClientKeyExchangeParams *params = (TLSClientKeyExchangeParams*)message->params;
            free(params->key_data);
            free(params); 
        }
    }
    client->n_messages = 0;
    return 0;
}

unsigned short tls_free_client(TLSClient* client){
    
    closesocket(client->socket);
    
    tls_free_client_messages(client);
    if(client->currentSpec){
        
        tls_free_cipher_spec(client->currentSpec);
    }
    if(client->nextSpec){
        
        tls_free_cipher_spec(client->nextSpec);
    }
    if(client->transcript){
        
        free(client->transcript);
    }
    free(client->messages);
    free(client);
    return 0;
}

unsigned short tls_build_client_hello(TLSMessage *clientHello, unsigned char *out, unsigned short *out_len){
    
    if(clientHello->type != TLSM_CLIENT_HELLO){
        
        return 1;
    }
    TLSClientHelloParams *params = (TLSClientHelloParams*)clientHello->params;
    
    if(!out){
        
        unsigned short t_len = 1 + 3 + 2 + 32 + 1 + 32 + 2 + 2*params->n_cipher_suites + 2 + 2;
//        printf("tlen1:%d\n", t_len);
        for(int i = 0; i < params->n_extensions; i++){
            
//            printf("type: %04X, data_len:%d\n", params->extensions[i]->type, params->extensions[i]->data_len);
            t_len += 2 + 2 + params->extensions[i]->data_len;
        }
//        printf("tlen2:%d\n", t_len);
        t_len += 4;
        t_len += 256 - (t_len%256);
        *out_len = t_len;
        
        return 0;
    }
    unsigned short idx = 0;
    out[idx++] = clientHello->type;
    
    unsigned short idx2 = idx;
    
    idx += 3;
    
    out[idx++] = 0x03; out[idx++] = 0x03;
    for(int i = 0; i < 32; i++){
        
        out[idx++] = params->random[i];
    }
    out[idx++] = 0x20;
    for(int i = 0; i < 32; i++){
        
        out[idx++] = params->session_id[i];
    }
    unsigned short idx1 = idx;
    idx += 2;
    for(int i = 0; i < params->n_cipher_suites; i++){

        out[idx++] = params->cipher_suites[i] >> 8;
        out[idx++] = params->cipher_suites[i] & 0xFF;
    }
    unsigned short cipher_suites_len = idx - idx1 - 2;
    out[idx1++] = cipher_suites_len >> 8;
    out[idx1++] = cipher_suites_len & 0xFF;
    
    out[idx++] = 0x01;
    out[idx++] = 0x00;
    
    idx1 = idx;
    idx += 2;
    
    for(int i = 0; i < params->n_extensions; i++){
    
        TLSHelloExtension* extension = params->extensions[i];
        out[idx++] = (extension->type >> 8) & 0xFF;
        out[idx++] = extension->type & 0xFF;
        out[idx++] = (extension->data_len >> 8) & 0xFF;
        out[idx++] = extension->data_len & 0xFF;
        
        for(int j = 0; j < extension->data_len; j++){
            
            out[idx++] = extension->data[j];
        }
    }
    
    out[idx++] = 0x00; out[idx++] = 0x15;
    unsigned short padding_len = 256 - ((idx+2)%256);
    out[idx++] = padding_len >> 8;
    out[idx++] = padding_len & 0xFF;
    for(int i = 0; i < padding_len; i++){
        
        out[idx++] = 0x00;
    }
    unsigned short extensions_len = idx - idx1 - 2;
    out[idx1++] = extensions_len >> 8;
    out[idx1++] = extensions_len & 0xFF;
    
    unsigned int hello_len = idx - idx2 - 3;
    out[idx2++] = hello_len >> 16;
    out[idx2++] = hello_len >> 8;
    out[idx2++] = hello_len & 0xFF;
    
    return 0;
}

unsigned short tls_build_client_key_exchange(TLSMessage *clientKeyExchange, unsigned char *out, unsigned short *out_len){

    TLSClientKeyExchangeParams *params = (TLSClientKeyExchangeParams*)clientKeyExchange->params;
    unsigned int clen = 1+params->key_data_len;
    unsigned short tlen = 1+3+clen;
    
    if(!out){
        
        *out_len = tlen;
        return 0;
    }
    out[0] = 0x10;
    out[1] = (clen >> 16) & 0xFF;
    out[2] = (clen >> 8) & 0xFF;
    out[3] = clen & 0xFF;
    out[4] = params->key_data_len;
    for(int i = 0; i < params->key_data_len; i++){
        
        out[5+i] = params->key_data[i];
    }
    return 0;
}

unsigned short tls_build_finished(TLSMessage *finished, unsigned char *out, unsigned short *out_len){
    
    *out_len = 16;
    if(!out){
            
        return 0;
    }
    unsigned char *verify_data = (unsigned char*)finished->params;

    out[0] = 0x14; out[1] = 0x00; out[2] = 0x00; out[3] = 0x0C;
    for(int i = 0; i < 12; i++){
        
        out[4+i] = verify_data[i];    
    }
    return 0;
}

unsigned short tls_compute_secrets(TLSClient *client){
    
    unsigned char type = client->messages[client->n_messages - 1]->type;
    printf("type:%02X\n",  type);
//    return 1;

    TLSServerKeyExchangeParams *skeParams = 0;
    TLSClientKeyExchangeParams *ckeParams = 0;
    TLSServerHelloParams *shParams = 0;
    for(int i = 0; i < client->n_messages; i++){
        
        if(client->messages[i]->type == TLSM_SERVER_KEY_EXCHANGE){
            
            skeParams = (TLSServerKeyExchangeParams*)client->messages[i]->params;
        }
        if(client->messages[i]->type == TLSM_CLIENT_KEY_EXCHANGE){
            
            ckeParams = (TLSClientKeyExchangeParams*)client->messages[i]->params;
        }
        if(client->messages[i]->type == TLSM_SERVER_HELLO){
            
            shParams = (TLSServerHelloParams*)client->messages[i]->params;
        }
    }
    printf("skeParams:%d, ckeParams:%d, nextSpec:%d\n", skeParams, ckeParams, client->nextSpec);
    unsigned char px[64], py[64], spx[64], spy[64], privateKey[64], *pre_master_secret = px;
    if(skeParams->ecdhe_group == TLS_ECDHE_P256){
        printf("cke key:\n");printbhex(ckeParams->key_data, 64);printf("\n");
        printf("ske key:\n");printbhex(skeParams->key_data, 64);printf("\n");
        for(int i = 0; i < 32; i++){
            
            px[i] = 0x00; py[i] = 0x00; spx[i] = 0x00; spy[i] = 0x00; privateKey[i] = 0x00;
            px[32+i] = ckeParams->key_data[i]; py[32+i] = ckeParams->key_data[32+i];
            spx[32+i] = skeParams->key_data[i]; spy[32+i] = skeParams->key_data[32+i];
            privateKey[32+i] = client->nextSpec->ecdhe_private_key[i];
        }
        printf("verifying key...\n");
    /*    if(b_p256_verify_pt(px, py)){
            
            printf("erro ponto cke\n");
        }
        if(b_p256_verify_pt(spx, spy)){
            
            printf("erro ponto ske\n");
        }*/
        printf("generating key...\n");
        b_p256_gen_key(privateKey, spx, spy, px, py);
        pre_master_secret += 32;
    }
    else if(skeParams->ecdhe_group == TLS_ECDHE_X25519){
        
        printf("cke key:\n");printbhex(ckeParams->key_data, 32);printf("\n");
        printf("ske key:\n");printbhex(skeParams->key_data, 32);printf("\n");
        for(int i = 0; i < 32; i++){

            px[i] = ckeParams->key_data[i]; py[i] = ckeParams->key_data[i];
            spx[i] = skeParams->key_data[i]; spy[i] = skeParams->key_data[i];
            privateKey[i] = client->nextSpec->ecdhe_private_key[i];
        }
        printf("verifying key...\n");
    /*    if(b_p256_verify_pt(px, py)){
            
            printf("erro ponto cke\n");
        }
        if(b_p256_verify_pt(spx, spy)){
            
            printf("erro ponto ske\n");
        }*/
        printf("generating key...\n");
        unsigned long long k[4], u[4], u1[4];
        btolongi(privateKey, k);
        btolongi(spx, u);
        
        bm_el25519(k, u, u1);
        longtobi(u1, px);
    }
    if(shParams->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA){
        
        unsigned char transcript_hash[32];
        sha256_b(client->transcript, client->transcript_len, transcript_hash);
        FILE *arq = fopen("transcript-t.bn", "wb");
        fwrite(client->transcript, 1, client->transcript_len, arq);
        fclose(arq);
        printf("premaster:\n");printbhex(pre_master_secret, 32);printf("\n");
        
        printf("transcript hash:\n");printbhex(transcript_hash, 32);printf("\n");
        client->nextSpec->master_secret = (unsigned char*)malloc(48);
        sha_sha256_prf(pre_master_secret, 32, label_extended_master_secret, sizeof(label_extended_master_secret) - 1, transcript_hash, 32, 48, client->nextSpec->master_secret);
        printf("master secret:\n");printbhex(client->nextSpec->master_secret, 48);printf("\n");
    
        client->nextSpec->master_secret_len = 48;
        
        unsigned char key_block[104],
                        *client_write_mac_key = key_block,
                        *server_write_mac_key = key_block,
                        *client_write_key = key_block,
                        *server_write_key = key_block,
                        server_client_random[64];
    
        server_write_mac_key += 20;
        client_write_key += 40;
        server_write_key += 72;
        
        TLSClientHelloParams *clientHelloParams = (TLSClientHelloParams*)client->messages[0]->params;
        TLSServerHelloParams *serverHelloParams = (TLSServerHelloParams*)client->messages[1]->params;
        
        for(int i = 0; i < 32; i++){
            
            server_client_random[i] = serverHelloParams->random[i];
            server_client_random[32+i] = clientHelloParams->random[i];
        }
        
        sha_sha256_prf(client->nextSpec->master_secret, 48, label_key_expansion, sizeof(label_key_expansion) - 1, server_client_random, 64, 104, key_block);
        printf("key block:\n");printbhex(key_block, 104);printf("\n");
        
        arq = fopen("key_material/key_block.bn", "wb");
        fwrite(key_block, 1, 104, arq);
        fclose(arq);
        arq = fopen("key_material/server_client_random.bn", "wb");
        fwrite(server_client_random, 1, 64, arq);
        fclose(arq);
        
        client->nextSpec->client_write_mac_key = (unsigned char*)malloc(20);
        memcpy(client->nextSpec->client_write_mac_key, client_write_mac_key, 20);
        client->nextSpec->client_write_mac_key_len = 20;
    //    printf("mac key:\n");printbhex(client->nextSpec->client_write_mac_key, client->nextSpec->client_write_mac_key_len);printf("\n");
        
        client->nextSpec->server_write_mac_key = (unsigned char*)malloc(20);
        memcpy(client->nextSpec->server_write_mac_key, server_write_mac_key, 20);
        client->nextSpec->server_write_mac_key_len = 20;
        
        client->nextSpec->client_write_key = (unsigned char*)malloc(32);
        memcpy(client->nextSpec->client_write_key, client_write_key, 32);
        client->nextSpec->client_write_key_len = 32;
        
        client->nextSpec->server_write_key = (unsigned char*)malloc(32);
        memcpy(client->nextSpec->server_write_key, server_write_key, 32);
        client->nextSpec->server_write_key_len = 32;
    }
    else if(shParams->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384){
        
        unsigned char transcript_hash[48];
        sha_sha384(client->transcript, client->transcript_len, transcript_hash);
        FILE *arq = fopen("transcripts/transcript-t.bn", "wb");
        fwrite(client->transcript, 1, client->transcript_len, arq);
        fclose(arq);
        printf("premaster:\n");printbhex(pre_master_secret, 32);printf("\n");
        
        printf("transcript hash:\n");printbhex(transcript_hash, 48);printf("\n");
        client->nextSpec->master_secret = (unsigned char*)malloc(48);
        sha384_prf(pre_master_secret, 32, "extended master secret", 22, transcript_hash, 48, 48, client->nextSpec->master_secret);
        printf("master secret:\n");printbhex(client->nextSpec->master_secret, 48);printf("\n");
        
        arq = fopen("key_material/pre_master_secret.bn", "wb");
        fwrite(pre_master_secret, 1, 32, arq);
        fclose(arq);
        
        arq = fopen("key_material/transcript_hash.bn", "wb");
        fwrite(transcript_hash, 1, 48, arq);
        fclose(arq);
        
        arq = fopen("key_material/master_secret.bn", "wb");
        fwrite(client->nextSpec->master_secret, 1, 48, arq);
        fclose(arq);
    
        client->nextSpec->master_secret_len = 48;
        
        unsigned char key_block[72],
                        *client_write_mac_key = key_block,
                        *server_write_mac_key = key_block,
                        *client_write_key = key_block,
                        *server_write_key = key_block,
                        *client_write_iv = key_block,
                        *server_write_iv = key_block,
                        server_client_random[64];

        server_write_key += 32;
        client_write_iv += 64;
        server_write_iv += 68;
        
        TLSClientHelloParams *clientHelloParams = (TLSClientHelloParams*)client->messages[0]->params;
        TLSServerHelloParams *serverHelloParams = (TLSServerHelloParams*)client->messages[1]->params;
        
        for(int i = 0; i < 32; i++){
            
            server_client_random[i] = serverHelloParams->random[i];
            server_client_random[32+i] = clientHelloParams->random[i];
        }
        
        sha384_prf(client->nextSpec->master_secret, 48, "key expansion", 14 - 1, server_client_random, 64, 72, key_block);
        printf("key block:\n");printbhex(key_block, 72);printf("\n");
        
        arq = fopen("key_material/key_block.bn", "wb");
        fwrite(key_block, 1, 72, arq);
        fclose(arq);
        arq = fopen("key_material/server_client_random.bn", "wb");
        fwrite(server_client_random, 1, 64, arq);
        fclose(arq);
        
        client->nextSpec->client_write_key = (unsigned char*)malloc(32);
        memcpy(client->nextSpec->client_write_key, client_write_key, 32);
        client->nextSpec->client_write_key_len = 32;
        
        client->nextSpec->server_write_key = (unsigned char*)malloc(32);
        memcpy(client->nextSpec->server_write_key, server_write_key, 32);
        client->nextSpec->server_write_key_len = 32;
        
        client->nextSpec->client_write_iv = (unsigned char*)malloc(4);
        memcpy(client->nextSpec->client_write_iv, client_write_iv, 4);
        client->nextSpec->client_write_iv_len = 4;
        
        client->nextSpec->server_write_iv = (unsigned char*)malloc(4);
        memcpy(client->nextSpec->server_write_iv, server_write_iv, 4);
        client->nextSpec->server_write_iv_len = 4;
        srand(time(0));
        unsigned char *c_nonce = (unsigned char*)malloc(8);
        for(int i = 0; i < 4; i++){
            
            int rn = rand();
            unsigned short rn16 = rn % 0x10000;
            c_nonce[2*i] = rn16 >> 8;
            c_nonce[2*i+1] = rn16 & 0xFF;
        }
        client->nextSpec->other_params = c_nonce;
    }

    return 0;
}

TLSHelloExtension* tls_extension(unsigned short type, unsigned char *data, unsigned short data_len){
    
    TLSHelloExtension *extension = (TLSHelloExtension*)malloc(sizeof(TLSHelloExtension));
    extension->type = type;
    extension->data_len = data_len;
    if(!extension->data_len){
        
        extension->data = 0;
        return extension;
    }
    extension->data = (unsigned char*)malloc(extension->data_len);
    memcpy(extension->data, data, extension->data_len);
    
    return extension;
}

TLSMessage* tls_parse_server_hello(unsigned char *data, unsigned short data_len){

    TLSServerHelloParams *params = (TLSServerHelloParams*)malloc(sizeof(TLSServerHelloParams));
    params->version = (data[0] << 8) | data[1];
    
    for(int i = 0; i < 32; i++){
        
        params->random[i] = data[2+i];
    }
    params->session_id_len = data[34];
    for(int i = 0; i < params->session_id_len; i++){
        
        params->session_id[i] = data[35+i];
    }
    unsigned short idx = 35+params->session_id_len;
    params->cipher_suite = (data[idx] << 8) | data[idx+1];
    idx += 2;
    params->compression_method = data[idx++];
    unsigned short extensions_len = (data[idx] << 8) | data[idx+1];
    idx += 2;
    params->n_extensions = 0;
    TLSHelloExtension *extensions[15];
    
    for(int i = 0; i < extensions_len; i++){
        if(params->n_extensions == 15)
            break;
            
        unsigned short start = idx+i, extension_type = (data[start] << 8) | data[start+1],
                        extension_len = (data[start+2] << 8) | data[start+3];
        
        unsigned char *data;
        if(extension_len){
         
            data = (unsigned char*)malloc(extension_len);
            for(int j = 0; j < extension_len; j++){
            
                data[j] = data[start+4+j];
            }
        }
        else{
            data = 0;
        }
        
        TLSHelloExtension *extension = tls_extension(extension_type, data, extension_len);
        
        i += 3+extension->data_len;
        extensions[params->n_extensions++] = extension;
    }
    params->extensions = (TLSHelloExtension**)malloc(params->n_extensions*sizeof(TLSHelloExtension*));
    for(int i = 0; i < params->n_extensions; i++){
        
        params->extensions[i] = extensions[i];
    }
    
    TLSMessage* serverHello = (TLSMessage*)malloc(sizeof(TLSMessage));
    serverHello->type = 0x02;
    serverHello->params = params;
    
    return serverHello;
}

TLSMessage* tls_parse_certificate_message(unsigned char *data, unsigned short data_len){
    
    
    unsigned int list_len = (data[0] << 16) | (data[1] << 8) | data[2], idx = 0;
    
    printf("cert list length:%d\n", list_len);
    TLSCertificateParams *params = (TLSCertificateParams*)malloc(sizeof(TLSCertificateParams));
    params->certificates = (BerEntityList*)malloc(sizeof(BerEntityList));
    params->certificates->n_entities = 0;
    params->certificates->entities = (BerEntity**)malloc(10*sizeof(BerEntity*));
    
    unsigned char *pdata = data;
    pdata += 3;
    idx += 3;
    while(idx < data_len){
        
        unsigned int cert_len = (data[idx] << 16) | (data[idx+1] << 8) | data[idx+2];
        idx += 3;
        pdata += 3;
        BerEntityList *cCertificate = ber_decode(pdata, cert_len, 0);
        BerEntity *certificate = cCertificate->entities[0];
        free(cCertificate->entities);
        free(cCertificate);
        params->certificates->entities[params->certificates->n_entities++] = certificate;
        idx += cert_len;
        pdata += cert_len;
    }

    TLSMessage *certificate = (TLSMessage*)malloc(sizeof(TLSMessage));
    certificate->type = 0x0B;
    certificate->params = params;
    return certificate;
}

TLSMessage* tls_parse_server_key_exchange(unsigned char *data, unsigned short data_len){
    
    if(data[0] != 0x03){
        
        printf("erro no named curve:%d\n", data[0]);
        return 0;
    }
    unsigned short curve = (data[1] << 8) | data[2];
    if(curve != TLS_ECDHE_P256 && curve != TLS_ECDHE_X25519){
        
        printf("erro curva errada:%04X\n", curve);
        return 0;
    }
    TLSServerKeyExchangeParams *params = (TLSServerKeyExchangeParams*)malloc(sizeof(TLSServerKeyExchangeParams));
    if(curve == TLS_ECDHE_P256){
        params->key_data = (unsigned char*)malloc(64);
        params->ecdhe_group = curve;
        params->key_data_len = 64;
        for(int i = 0; i < 32; i++){
            
            params->key_data[i] = data[5+i];
            params->key_data[32+i] = data[37+i]; 
        }
    }
    else if(curve == TLS_ECDHE_X25519){
        
        params->key_data = (unsigned char*)malloc(32);
        params->ecdhe_group = curve;
        params->key_data_len = 32;
        for(int i = 0; i < 32; i++){
            
            params->key_data[i] = data[4+i];
        }    
    }
    TLSMessage *serverKeyExchange = (TLSMessage*)malloc(sizeof(TLSMessage));
    serverKeyExchange->type = 0x0C;
    serverKeyExchange->params = params;
    return serverKeyExchange;
}

TLSMessage* tls_client_hello(const unsigned char server_name[], const unsigned char port[]){
    
    unsigned short server_name_len = 0;
    while(server_name_len < 65535 && server_name[server_name_len] != 0x00){
        
        server_name_len++;
    }
    printf("serverNameLen:%d\n", server_name_len);
    
    unsigned char server_name_data[2 + 1 + 2 + server_name_len];
    
    TLSClientHelloParams *params = (TLSClientHelloParams*)malloc(sizeof(TLSClientHelloParams));
    srand(time(0));
    b_random(tls_client_random);
    printf("rand: %d, %d, %d\n", rand()%0x10000, rand()%0x10000, rand()%0x10000);
    for(int i = 0; i < 16; i++){
        
        int num = rand()%0x10000;
        params->random[2*i] = num & 0xFF;
        params->random[2*i+1] = (num >> 8) & 0xFF;
    }
    for(int i = 0; i < 16; i++){
        
        int num = rand()%0x10000;
        params->session_id[2*i] = num & 0xFF;
        params->session_id[2*i+1] = (num >> 8) & 0xFF;
    }
//    memcpy(params->random, tls_client_random, 32);
    params->n_extensions = 0;
    
    params->n_cipher_suites = 3;
    unsigned short cipher_suites[3] = {
        
        0x2A2A, 0xC014, 0xC030
    };
    params->cipher_suites = (unsigned short*)malloc(6);
    memcpy(params->cipher_suites, cipher_suites, 6);
    
    TLSHelloExtension *extensions[15]; 
    
    server_name_data[0] = (1 + 2 + server_name_len) >> 8;
    server_name_data[1] = (1 + 2 + server_name_len) & 0xFF;
    
    server_name_data[2] = 0x00;

    server_name_data[3] = server_name_len >> 8;
    server_name_data[4] = server_name_len & 0xFF;
    
    for(int i = 0; i < server_name_len; i++){
        
        server_name_data[5+i] = server_name[i];
    }
    
    TLSHelloExtension *reserved = tls_extension(0x2A2A, 0, 0);
    extensions[params->n_extensions++] = reserved;
    
    TLSHelloExtension *server_name_ext = tls_extension(0x0000, server_name_data, 5 + server_name_len);
    extensions[params->n_extensions++] = server_name_ext;
    
    TLSHelloExtension *extended_master_secret = tls_extension(0x0017, 0, 0);
    extensions[params->n_extensions++] = extended_master_secret;
    
    unsigned char renegotiation_info_data = 0x00;
    TLSHelloExtension *renegotiation_info = tls_extension(0xFF01, &renegotiation_info_data, 1);
    extensions[params->n_extensions++] = renegotiation_info;
    
    unsigned char supported_groups_extension_data[10] = {0x00, 0x08, 0x7A, 0x7A, 0x00, 0x17, 0x00, 0x18, 0x00, 0x1D};
    TLSHelloExtension *supported_groups = tls_extension(0x000A, supported_groups_extension_data, 10);
    extensions[params->n_extensions++] = supported_groups;
    
    unsigned char ec_point_formats_extension_data[2] = {0x01, 0x00};
    TLSHelloExtension *ec_point_formats = tls_extension(0x000B, ec_point_formats_extension_data, 2);
    extensions[params->n_extensions++] = ec_point_formats;
    
    unsigned char application_layer_protocol_negotiation_data[11] = {0x00, 0x09, /*0x02, 0x68, 0x32,*/ 0x08, 0x68, 0x74, 0x74, 0x70, 0x2F, 0x31, 0x2E, 0x31};
    TLSHelloExtension *application_layer_protocol_negotiation = tls_extension(0x0010, application_layer_protocol_negotiation_data, 11);
    extensions[params->n_extensions++] = application_layer_protocol_negotiation;
    
    unsigned char status_request_data[5] = {0x01, 0x00, 0x00, 0x00, 0x00};
    TLSHelloExtension *status_request = tls_extension(0x0005, status_request_data, 5);
    extensions[params->n_extensions++] = status_request;
    
    unsigned char signature_algorithms_data[18] = {0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
                                                    0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01};
    TLSHelloExtension *signature_algorithms = tls_extension(0x000D, signature_algorithms_data, 18);
    extensions[params->n_extensions++] = signature_algorithms;

    TLSHelloExtension *signed_certificate_timestamp = tls_extension(0x0012, 0, 0);
    extensions[params->n_extensions++] = signed_certificate_timestamp;

    unsigned char compress_certificate_data[3] = {0x02, 0x00, 0x02};
    TLSHelloExtension *compress_certificate = tls_extension(0x001B, compress_certificate_data, 3);
    extensions[params->n_extensions++] = compress_certificate; 
    
    unsigned char reserved1_data = 0x00;
    TLSHelloExtension *reserved1 = tls_extension(0x4A4A, &reserved1_data, 1);
    extensions[params->n_extensions++] = reserved1;
    
    params->extensions = (TLSHelloExtension**)malloc(params->n_extensions*sizeof(TLSHelloExtension*));
    for(int i = 0; i < params->n_extensions; i++){
        
        params->extensions[i] = extensions[i];
    }
    
    TLSMessage *clientHello = (TLSMessage*)malloc(sizeof(TLSMessage));
    clientHello->type = TLSM_CLIENT_HELLO;
    clientHello->params = params;
    
    return clientHello;
}

TLSMessage* tls_client_key_exchange(unsigned char px[64], unsigned char py[64]){
    
    TLSMessage *cke = (TLSMessage*)malloc(sizeof(TLSMessage));
    cke->type = TLSM_CLIENT_KEY_EXCHANGE;
    TLSClientKeyExchangeParams *params = (TLSClientKeyExchangeParams*)malloc(sizeof(TLSClientKeyExchangeParams));
    params->key_data_len = 65;
    params->key_data = (unsigned char*)malloc(65);
    params->key_data[0] = 0x04;
    for(int i = 0; i < 32; i++){
        
        params->key_data[1+i] = px[32+i];
        params->key_data[33+i] = py[32+i];
    }
    cke->params = params;
    return cke;
}

TLSMessage* tls_finished(TLSClient *client){

    printf("allocating...\n");
    unsigned char *verify_data = (unsigned char*)malloc(12), transcript_hash[48];
    printf("master_secret(%d):", client->currentSpec);printbhex(client->currentSpec->master_secret, client->currentSpec->master_secret_len);printf("\n");
    printf("hashing...\n");
    if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
        sha256_b(client->transcript, client->transcript_len, transcript_hash);
    if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        sha_sha384(client->transcript, client->transcript_len, transcript_hash);
    
    printf("sha:");printbhex(transcript_hash, 48);printf("\n");
    if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
        sha_sha256_prf(client->currentSpec->master_secret, client->currentSpec->master_secret_len, label_client_finished, 15, transcript_hash, 32, 12, verify_data);
    if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        sha384_prf(client->currentSpec->master_secret, client->currentSpec->master_secret_len, label_client_finished, 15, transcript_hash, 48, 12, verify_data);
    
    printf("verify data:\n");printbhex(verify_data, 12);printf("\n");
    FILE *arq = fopen("key_material/verify_data.bn", "wb");
    fwrite(verify_data, 1, 12, arq);
    fclose(arq);
//    printf("mac key");printbhex(client->currentSpec->client_write_mac_key, client->currentSpec->client_write_mac_key_len);printf("\n");    
    TLSMessage *finished = (TLSMessage*)malloc(sizeof(TLSMessage));
    finished->type = TLSM_FINISHED;

    finished->params = verify_data;
    if(client->verify_data)
        free(client->verify_data);
    
    client->verify_data = verify_data;

    return finished;
}

TLSMessage* tls_get_message(TLSClient *client, unsigned char message_type){
    
    for(int i = 0; i < client->n_messages; i++){
        printf("m%d\n", i);
        if(client->messages[i]->type == message_type){
            
            printf("match\n"); 
            return client->messages[i];
        }
    }
    return 0;
}

unsigned short tls_send_message(TLSClient *client, TLSMessage *message){

    if(message->type != TLSM_CLIENT_HELLO && message->type != TLSM_CLIENT_KEY_EXCHANGE && message->type != TLSM_FINISHED && message->type != TLSM_CERTIFICATE && message->type != TLSM_CERTIFICATE_VERIFY)
        return 1;
        
    client->last_hello_msg = message->type;
    client->last_sent_handshake_msg = message->type;

    unsigned short ch_len = 0;
    unsigned char *ch_record, *ch_data;
    if(message->type == TLSM_CLIENT_HELLO){

        TLSMessage *clientHello = message;
        
        printf("clientHello:\n  type:%d\n", clientHello->type);
        TLSClientHelloParams *params = (TLSClientHelloParams*)clientHello->params;
/*        printf("  extensions(%d):\n", params->n_extensions);
        for(int i = 0; i < params->n_extensions; i++){
            
            printf("  %04X (%d):\n", params->extensions[i]->type, params->extensions[i]->data_len);
            printbhex(params->extensions[i]->data, params->extensions[i]->data_len);
            printf("\n\n");
        }*/
        printf("trlen:%d\n", client->transcript_len);
        if(client->transcript_len > 0){
            
            free(client->transcript);
            client->transcript_len = 0;    
        }
        printf("trlen:%d\n", client->transcript_len);
        tls_free_client_messages(client);
        printf("trlen2:%d\n", client->transcript_len);
        tls_build_client_hello(message, 0, &ch_len);
        ch_record = (unsigned char*)malloc(ch_len+5);
        ch_data = ch_record;
        ch_data += 5;
        tls_build_client_hello(message, ch_data, &ch_len);
    }
    else if(message->type == TLSM_CLIENT_KEY_EXCHANGE){
        
        printf("client KE\n");       
        tls_build_client_key_exchange(message, 0, &ch_len);
//        printf("clientHello length:%d\n", ch_len);
        ch_record = (unsigned char*)malloc(ch_len+5);
        ch_data = ch_record;
        ch_data += 5;
        tls_build_client_key_exchange(message, ch_data, &ch_len);
    }
    else if(message->type == TLSM_FINISHED){
        
        tls_build_finished(message, 0, &ch_len);
        ch_record = (unsigned char*)malloc(ch_len+5);
        ch_data = ch_record;
        ch_data += 5;
        tls_build_finished(message, ch_data, &ch_len);
    }
    else if(message->type == TLSM_CERTIFICATE){
        
        printf("cert message\n");
        TLSCertificateParams *params = (TLSCertificateParams*)message->params;
        unsigned int list_len = 3;
        for(int i = 0; i < params->certificates->n_entities; i++){
            
            printf("certificado %d\n", i+1);
            BerEntity *certificate = params->certificates->entities[i];
            list_len += 3 + 4 + certificate->dataLen;
            printf("cert dataLen:%d\n", certificate->dataLen);
        }
        printf("cert listLen:%d\n", list_len);
        unsigned char cert_list[list_len], *plist = cert_list;
        list_len -= 3;
        plist[0] = (list_len >> 16) & 0xFF;
        plist[1] = (list_len >> 8) & 0xFF;
        plist[2] = list_len >> 0 & 0xFF;
        plist += 3;

        for(int i = 0; i < params->certificates->n_entities; i++){
            
            BerEntity *certificate = params->certificates->entities[i];
            unsigned int len = 4 + certificate->dataLen;
            plist[0] = (len >> 16) & 0xFF;
            plist[1] = (len >> 8) & 0xFF;
            plist[2] = len >> 0 & 0xFF;
            plist += 3;
            
            plist[0] = 0x30;
            plist[1] = 0x82;
            plist[2] = (certificate->dataLen >> 8) & 0xFF;
            plist[3] = certificate->dataLen & 0xFF;
            
            plist += 4;
            memcpy(plist, certificate->pData, certificate->dataLen);
            plist += certificate->dataLen; 
        }
        list_len += 3;
        ch_len = 4 + list_len;
        ch_record = (unsigned char*)malloc(5+ch_len);
        ch_data = ch_record;
        ch_data += 5;
        
        unsigned char *pch = ch_record;
        pch[0] = 0x16;
        pch[1] = 0x03;pch[2] = 0x03;
        pch[3] = (ch_len >> 8) & 0xFF;
        pch[4] = ch_len & 0xFF;
        
        pch += 5;
        pch[0] = TLSM_CERTIFICATE;
        pch[1] = (list_len >> 16) & 0xFF;
        pch[2] = (list_len >> 8) & 0xFF;
        pch[3] = list_len & 0xFF;
        pch += 4;
        memcpy(pch, cert_list, list_len);
        pch -= 9;
    }
    else if(message->type == TLSM_CERTIFICATE_VERIFY){
        
        TLSSignature *signature = (TLSSignature*)message->params;
        unsigned short idx = 0;
        unsigned int ct_len = 2 + 2 + signature->signature_len;
        ch_len = 4 + ct_len;
        ch_record = (unsigned char*)malloc(5+ch_len);
        ch_data = ch_record;
        ch_data += 5;
        
        unsigned char *pch = ch_record;
        pch[0] = 0x16;
        pch[1] = 0x03;pch[2] = 0x03;
        pch[3] = (ch_len >> 8) & 0xFF;
        pch[4] = ch_len & 0xFF;
        
        pch += 5;
        pch[0] = TLSM_CERTIFICATE_VERIFY;
        pch[1] = (ct_len >> 16) & 0xFF;
        pch[2] = (ct_len >> 8) & 0xFF;
        pch[3] = ct_len & 0xFF;
        pch += 4;
        pch[0] = signature->hash_algo;
        pch[1] = signature->signature_algo;
        pch[2] = (signature->signature_len >> 8) & 0xFF;
        pch[3] = signature->signature_len & 0xFF;
        pch += 4;
        memcpy(pch, signature->signature, signature->signature_len);
    }
    client->messages[client->n_messages++] = message;
    if(client->currentSpec){
        
        if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA){
            
            unsigned short mac_ctx_len = 8+5+ch_len;
            unsigned char mac_ctx[mac_ctx_len];
            for(int i = 0; i < 8; i++){
                
                mac_ctx[i] = (client->currentSpec->seq_number >> 8*(7 - i)) & 0xFF;
            }
            unsigned char iv[16];
            srand(time(0));
            for(int i = 0; i < 8; i++){
                
                int rn = rand();
                unsigned short rn16 = rn % 0x10000;
                iv[2*i] = rn16 >> 8;
                iv[2*i+1] = rn16 & 0xFF;
            }
            client->currentSpec->seq_number++;
            mac_ctx[8] = 0x16;
            mac_ctx[9] = 0x03; mac_ctx[10] = 0x03;
            mac_ctx[11] = (ch_len >> 8) & 0xFF;
            mac_ctx[12] = ch_len & 0xFF;
            for(int i = 0; i < ch_len; i++){
                
                mac_ctx[8+5+i] = ch_data[i];
            }
//            printf("mac_ctx:\n");printbhex(mac_ctx, 8+5+ch_len);printf("\n");
            unsigned char mac[client->currentSpec->client_write_mac_key_len];
//            printf("key:\n");printbhex(client->currentSpec->client_write_mac_key, client->currentSpec->client_write_mac_key_len);printf("\n");
            sha_sha1_hmac(client->currentSpec->client_write_mac_key, client->currentSpec->client_write_mac_key_len, mac_ctx, mac_ctx_len, mac);    
//            printf("mac:\n");printbhex(mac, client->currentSpec->client_write_mac_key_len);printf("\n");
            
            unsigned short cbc_block_len1 = ch_len + client->currentSpec->client_write_mac_key_len + 1, padding_len = 16 - (cbc_block_len1%16);
            unsigned char cbc_block[cbc_block_len1 + padding_len], *pblock = cbc_block, ciphered[16+cbc_block_len1 + padding_len], *pciphered = ciphered;
            memcpy(pblock, ch_data, ch_len);
            pblock += ch_len;
            memcpy(pblock, mac, client->currentSpec->client_write_mac_key_len);
            pblock += client->currentSpec->client_write_mac_key_len;
            for(int i = 0; i < padding_len+1; i++){
                
                pblock[i] = padding_len & 0xFF;
            }
            FILE *arq = fopen("key_material/iv.bn", "wb");
            fwrite(iv, 1, 16, arq);
            fclose(arq);
            memcpy(pciphered, iv, 16);
            pciphered += 16;
//            printf("cbc block:\n");printbhex(cbc_block, cbc_block_len1+padding_len);printf("\n");
//            printf("cbc key:\n");printbhex(client->currentSpec->client_write_key, client->currentSpec->client_write_key_len);printf("\n");
            cbc_aes256_cbc(iv, client->currentSpec->client_write_key, cbc_block, cbc_block_len1+padding_len, pciphered);
//            printf("ciphered:\n");printbhex(ciphered, 16+cbc_block_len1+padding_len);printf("\n");
            unsigned short cip_len = 16+cbc_block_len1+padding_len;
            unsigned char cip_record[5+cip_len], *pcip = cip_record;
            pcip += 5;
            memcpy(pcip, ciphered, 16+cbc_block_len1+padding_len);
            cip_record[0] = 0x16;
            cip_record[1] = 0x03; cip_record[2] = 0x03;
            cip_record[3] = (cip_len >> 8) & 0xFF;
            cip_record[4] = cip_len & 0xFF;
            
//            printbhex(cip_record, cip_len+5);
            send(client->socket, (char*)cip_record, cip_len+5, 0);
        }
        else if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384){
            
            unsigned char ad[12+1];
            for(int i = 0; i < 8; i++){
                
                ad[i] = (client->currentSpec->seq_number >> 8*(7 - i)) & 0xFF;
            } 
            ad[8] = 0x16;
            ad[9] = 0x03; ad[10] = 0x03;
            ad[11] = (ch_len >> 8) & 0xFF;
            ad[12] = ch_len & 0xFF;
            
            unsigned char *nonce = (unsigned char*)client->currentSpec->other_params, iv[12];
            memcpy(iv, client->currentSpec->client_write_iv, 4);
            unsigned short cip_len = ch_len, rec_len = cip_len+8+16;
            unsigned char output[5+8+cip_len+16];
            unsigned char *cip = output, *tag = output;
            cip += 5+8;
            tag += 5+8+cip_len;
            output[0] = 0x16;
            output[1] = 0x03; output[2] = 0x03;
            
            output[3] = (rec_len >> 8) & 0xFF;
            output[4] = rec_len & 0xFF;
            for(int i = 0; i < 8; i++){
                
                output[5+i] = nonce[i];
                iv[4+i] = nonce[i];
            }
            FILE *arq = fopen("key_material/ad.bn", "wb");
            fwrite(ad, 1, 12+1, arq);
            fclose(arq);
            
            arq = fopen("key_material/nonce.bn", "wb");
            fwrite(nonce, 1, 8, arq);
            fclose(arq);
            
            arq = fopen("key_material/ch.bn", "wb");
            fwrite(ch_data, 1, ch_len, arq);
            fclose(arq);
            
//            printf("iv:\n");printbhex(iv, 12);printf("\n");
            gcm_aes256_gcm(iv, 12, client->currentSpec->client_write_key, ch_data, ch_len, ad, 12+1, cip, tag, 16);
//            printf("record(%d, %d):\n", cip_len, ch_len);printbhex(output, 5+8+cip_len+16);printf("\n");
            send(client->socket, (char*)output, 5+8+cip_len+16, 0);
        }
    }
    else{

        ch_record[0] = 0x16; ch_record[1] = 0x03; ch_record[2] = 0x03;
        ch_record[3] = (ch_len >> 8) & 0xFF;
        ch_record[4] = ch_len & 0xFF;
        
//        printbhex(ch_record, ch_len+5);
        send(client->socket, (char*)ch_record, ch_len+5, 0);
    }
    
    printf("\n");
    unsigned char *new_transcript = (unsigned char*)malloc(client->transcript_len + ch_len);
    FILE *arq = fopen("transcripts/last_sent_message.bn", "wb");
    fwrite(ch_record, 1, ch_len+5, arq);
    fclose(arq);
    if(client->transcript_len > 0){
        
        memcpy(new_transcript, client->transcript, client->transcript_len);
        free(client->transcript);
    }
        
    new_transcript += client->transcript_len;
    memcpy(new_transcript, ch_data, ch_len);
    new_transcript -= client->transcript_len;
    
    client->transcript = new_transcript;
    client->transcript_len += ch_len;
    free(ch_record);
    return 0;
}

unsigned short tls_send_change_cipher_spec(TLSClient *client){
    
    if(!client->currentSpec){
        printf("enviar css plaintext\n");
        send(client->socket, b_change_cipher_spec, sizeof(b_change_cipher_spec), 0);
    }
    else{
        
        unsigned short mac_ctx_len = 8+5+1, padding_len = 10;
        unsigned char mac_ctx[mac_ctx_len];
        for(int i = 0; i < 8; i++){
            
            mac_ctx[i] = (client->currentSpec->seq_number >> 8*(7 - i)) & 0xFF;
        }
        mac_ctx[8] = 0x14;
        mac_ctx[9] = 0x03; mac_ctx[10] = 0x03;
        mac_ctx[11] = 0x00;
        mac_ctx[12] = 0x01;
        mac_ctx[13] = 0x01;
        
        printf("mac ctx:\n");printbhex(mac_ctx, mac_ctx_len);printf("\n");
        
        unsigned char cbc_block[53], *pblock = cbc_block, piv[64], *iv = piv;
        pblock[0] = 0x14;
        pblock[1] = 0x03;pblock[2] = 0x03;
        pblock[3] = 0x00;pblock[4] = 0x30;
        pblock += 5;
        srand(time(0));
        b_random(iv);
        iv += 32;
        printf("css iv:\n");printbhex(iv, 16);printf("\n");
        memcpy(pblock, iv, 16);
        pblock += 16;
        pblock[0] = 0x01;
        pblock++;
        sha_sha1_hmac(client->currentSpec->client_write_mac_key, client->currentSpec->client_write_mac_key_len, mac_ctx, mac_ctx_len, pblock);
        printf("mac:\n");printbhex(pblock, 20);printf("\n");
        pblock += 20;
        for(int i = 0; i < padding_len+1; i++){
            
            pblock[i] = padding_len;
        }
        pblock -= 21;
        printf("css cbc block:\n");printbhex(pblock, 32);printf("\n");
        printf("css record:\n");printbhex(cbc_block, 53);printf("\n");
        cbc_aes256_cbc(iv, client->currentSpec->client_write_key, pblock, 32, pblock);
        send(client->socket, cbc_block, 53, 0);
    }
    if(client->currentSpec){
        
        tls_free_cipher_spec(client->currentSpec);
    }
    printf("currentSpec:%d, nextSpec:%d\n", client->currentSpec, client->nextSpec);
    client->currentSpec = client->nextSpec;
    client->nextSpec = 0;
    
    return 0;    
}

unsigned short tls_send_application_data(TLSClient *client, unsigned char *data, unsigned short data_len){
    
    if(client->currentSpec){
        
        unsigned short mac_ctx_len = 8+5+data_len;
        unsigned char mac_ctx[mac_ctx_len];
        for(int i = 0; i < 8; i++){
            
            mac_ctx[i] = (client->currentSpec->seq_number >> 8*(7 - i)) & 0xFF;
        }
        client->currentSpec->seq_number++;
        
        if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA){
            
            mac_ctx[8] = 0x17;
            mac_ctx[9] = 0x03; mac_ctx[10] = 0x03;
            mac_ctx[11] = (data_len >> 8) & 0xFF;
            mac_ctx[12] = data_len & 0xFF;
            for(int i = 0; i < data_len; i++){
                
                mac_ctx[8+5+i] = data[i];
            }
            printf("mac_ctx:\n");printbhex(mac_ctx, 8+5+data_len);printf("\n");
            unsigned char mac[client->currentSpec->client_write_mac_key_len];
            printf("key:\n");printbhex(client->currentSpec->client_write_mac_key, client->currentSpec->client_write_mac_key_len);printf("\n");
            sha_sha1_hmac(client->currentSpec->client_write_mac_key, client->currentSpec->client_write_mac_key_len, mac_ctx, mac_ctx_len, mac);
            printf("mac:\n");printbhex(mac, client->currentSpec->client_write_mac_key_len);printf("\n");
            
            unsigned short cbc_block_len1 = data_len + client->currentSpec->client_write_mac_key_len + 1, padding_len = 16 - (cbc_block_len1%16);
            unsigned char cbc_block[cbc_block_len1 + padding_len], *pblock = cbc_block, ciphered[16+cbc_block_len1 + padding_len], *pciphered = ciphered, randnum[64], *iv = randnum;
            iv += 32;
            b_random(randnum);
            memcpy(pblock, data, data_len);
            pblock += data_len;
            memcpy(pblock, mac, client->currentSpec->client_write_mac_key_len);
            pblock += client->currentSpec->client_write_mac_key_len;
            for(int i = 0; i < padding_len+1; i++){
                
                pblock[i] = padding_len & 0xFF;
            }
            FILE *arq = fopen("iv.bn", "wb");
            fwrite(iv, 1, 16, arq);
            fclose(arq);
            memcpy(pciphered, iv, 16);
            pciphered += 16;
            printf("cbc block:\n");printbhex(cbc_block, cbc_block_len1+padding_len);printf("\n");
            printf("cbc key:\n");printbhex(client->currentSpec->client_write_key, client->currentSpec->client_write_key_len);printf("\n");
            cbc_aes256_cbc(iv, client->currentSpec->client_write_key, cbc_block, cbc_block_len1+padding_len, pciphered);
            printf("ciphered:\n");printbhex(ciphered, 16+cbc_block_len1+padding_len);printf("\n");
            unsigned short cip_len = 16+cbc_block_len1+padding_len;
            unsigned char cip_record[5+cip_len], *pcip = cip_record;
            pcip += 5;
            memcpy(pcip, ciphered, 16+cbc_block_len1+padding_len);
            cip_record[0] = 0x17;
            cip_record[1] = 0x03; cip_record[2] = 0x03;
            cip_record[3] = (cip_len >> 8) & 0xFF;
            cip_record[4] = cip_len & 0xFF;
            
            printbhex(cip_record, cip_len+5);
            send(client->socket, (char*)cip_record, cip_len+5, 0);
        }
        else if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384){
            
            unsigned short ciphertext_len = data_len + 16, record_len = ciphertext_len + 5 + 8, content_len = ciphertext_len+8;
            unsigned char *nonce = (unsigned char*)client->currentSpec->other_params, iv[12], aad[8+5], *pnonce = iv, record[record_len], *ciphertext = record, *ptag = record, *prnonce = record;
            ptag += record_len - 16;
            ciphertext += 5 + 8;
            pnonce += 4;
            prnonce += 5;
            nonce[7]++;
            memcpy(pnonce, nonce, 8);
            memcpy(iv, client->currentSpec->client_write_iv, 4);
            for(int i = 0; i < 8; i++){
            
                aad[i] = (client->currentSpec->seq_number >> (8*(7-i))) & 0xFF;
            }
            aad[8] = 0x17;
            aad[9] = 0x03; aad[10] = 0x03;
            aad[11] = (data_len >> 8) & 0xFF;
            aad[12] = data_len & 0xFF;
            
            record[0] = 0x17;
            record[1] = 0x03; record[2] = 0x03;
            record[3] = (content_len >> 8) & 0xFF;
            record[4] = content_len & 0xFF;
            
            memcpy(prnonce, nonce, 8);
            printf("iv:\n");printbhex(iv, 12);printf("\n");
            
            printf("aad:\n");printbhex(aad, 8+5);printf("\n");
            gcm_aes256_gcm(iv, 12, client->currentSpec->client_write_key, data, data_len, aad, 8+5, ciphertext, ptag, 16);
            printf("tag:\n");printbhex(ptag, 16);printf("\n");
//            printf("record:\n");printbhex(record, record_len);printf("\n");
            
            send(client->socket, (char*)record, record_len, 0);
        }
    }
    else{
        
        unsigned char ch_record[5];
        ch_record[0] = 0x17; ch_record[1] = 0x03; ch_record[2] = 0x03;
        ch_record[3] = (data_len >> 8) & 0xFF;
        ch_record[4] = data_len & 0xFF;
        
        printbhex(ch_record, data_len+5);
        send(client->socket, (char*)ch_record, 5, 0);
        send(client->socket, (char*)data, data_len, 0);
    }
    return 0;    
}

unsigned short tls_receive_application_data(TLSClient *client){
    
    printf("receiveing...\n");
    unsigned char hdr[5];
    int r = recv(client->socket, (char*)hdr, 5, MSG_WAITALL);
    if(r == SOCKET_ERROR){
        
        printf("socket error:%d\n", WSAGetLastError());
        return 1;
    }
    printf("hdrapprec\n");printbhex(hdr, 5);printf("\n");
    if(hdr[0] == 0x00){
        
        printf("erro recebimento.\n");
        return 1;
    }
    unsigned short recv_l = (hdr[3] << 8) | hdr[4], recv_len = recv_l;
    printf("apprecv_len:%d\n", recv_l);
    unsigned char recv_ct[recv_l], *recv_content = recv_ct;
    recv(client->socket, (char*)recv_ct, recv_l, MSG_WAITALL);
//    printbhex(recv_content, recv_len);
    printf("\n");
        
    if(client->currentSpec){
        
        if(recv_l == 0){
            
            printf("erro recebimento 2\n");
            return 1;
        }
        if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA){
            recv_len = recv_l - 16;
            recv_content += 16;
            unsigned char *iv = recv_ct;
            cbc_aes256_cbc_decrypt(iv, client->currentSpec->server_write_key, recv_content, recv_len, recv_content);
//            printf("decrypted:\n");printbhex(recv_content, recv_len);printf("\n");
            unsigned char padding_len = recv_content[recv_len - 1];
            recv_len -= 20 + padding_len + 1;
        }
        else if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384){
            
//            printf("record:\n");printbhex(recv_content, recv_len);printf("\n");
            
            unsigned char *nonce_explicit = recv_content,
                            *tag = recv_content,
                            *ciphertext = recv_content;

            tag += recv_len - 16;
            ciphertext += 8;
            printf("nonce_explicit:\n");printbhex(nonce_explicit, 8);printf("\n");
            printf("tag:\n");printbhex(tag, 16);printf("\n");
            unsigned char iv[12], decrypted[recv_len - 24], *pnonce = iv;
            pnonce += 4;
            memcpy(iv, client->currentSpec->server_write_iv, 4);
            memcpy(pnonce, nonce_explicit, 8);
            printf("iv:\n");printbhex(iv, 12);printf("\n");
            unsigned short dec_len = recv_len - 24;
            unsigned char aad[5+8], vtag[16];
            for(int i = 0; i < 8; i++){
            
                aad[i] = (client->currentSpec->seq_number >> (8*(7-i))) & 0xFF;
            }
            aad[8] = 0x17;
            aad[9] = 0x03; aad[10] = 0x03;
            aad[11] = (dec_len >> 8) & 0xFF;
            aad[12] = dec_len & 0xFF;
            printf("aad:\n");printbhex(aad, 5+8);printf("\n");
            gcm_aes_256_gcm_ad(iv, 12, client->currentSpec->server_write_key, ciphertext, recv_len - 24, aad, 5+8, decrypted, vtag, 16);
//            printf("decrypted:\n");printbhex(decrypted, recv_len - 24);printf("\n");
            printf("tag:\n");printbhex(vtag, 16);printf("\n");
            
//            gcm_aes_256_gcm_ad(iv, 12, client->currentSpec->server_write_key, ciphertext, recv_len - 24, aad, 4, decrypted);
//            printf("decrypted:\n");printbhex(decrypted, recv_len - 24);printf("\n");
            recv_len -= 24;
            memcpy(recv_content, decrypted, recv_len);
        }
    }
    if(hdr[0] == 0x15){
        
        printf("alert:\n");printbhex(recv_ct, recv_l);printf("\n");
        return 1;
    }
    if(hdr[0] == 0x16 && recv_content[0] == 0x00){
        
        return 2;
    }
    if(client->application_data){
        
        printf("freeing:(%c)...\n", client->application_data[0]);
        free(client->application_data);
        printf("freed\n");
    }
    client->application_data = (unsigned char*)malloc(recv_len+1);
    client->application_data[recv_len] = 0x00;
    client->application_data_len = recv_len;
    printf("mem copying...\n");
    memcpy(client->application_data, recv_content, recv_len);
    printf("mem copied\n");
    return 0;
}

unsigned short tls_receive_messages(TLSClient *client){
    
    unsigned char hdr[5];
    int r = recv(client->socket, (char*)hdr, 5, MSG_WAITALL);
    if(r == SOCKET_ERROR){
        
        printf("socket error:%d\n", WSAGetLastError());
        return 1;
    }
    
    printf("hdrrec\n");printbhex(hdr, 5);printf("\n");
    unsigned short recv_l = (hdr[3] << 8) | hdr[4], recv_len = recv_l;
    printf("recv_len:%d\n", recv_l);
    unsigned char recv_ct[recv_l], *recv_content = recv_ct;
    recv(client->socket, (char*)recv_ct, recv_l, MSG_WAITALL);
//    printbhex(recv_content, recv_len);
    printf("\n");
    
    if(hdr[0] != 0x14 && hdr[0] != 0x15 && client->currentSpec){
        
        if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA){
            recv_len = recv_l - 16;
            recv_content += 16;
            unsigned char *iv = recv_ct;
            cbc_aes256_cbc_decrypt(iv, client->currentSpec->server_write_key, recv_content, recv_len, recv_content);
//            printf("decrypted:\n");printbhex(recv_content, recv_len);printf("\n");
            unsigned char padding_len = recv_content[recv_len - 1];
            recv_len -= 20 + padding_len + 1;
        }
        else if(client->currentSpec->cipher_suite == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384){
            
//            printf("record:\n");printbhex(recv_content, recv_len);printf("\n");
            
            unsigned char *nonce_explicit = recv_content,
                            *tag = recv_content,
                            *ciphertext = recv_content;

            tag += recv_len - 16;
            ciphertext += 8;
            printf("nonce_explicit:\n");printbhex(nonce_explicit, 8);printf("\n");
            printf("tag:\n");printbhex(tag, 16);printf("\n");
            unsigned char iv[12], decrypted[recv_len - 24], *pnonce = iv;
            pnonce += 4;
            memcpy(iv, client->currentSpec->server_write_iv, 4);
            memcpy(pnonce, nonce_explicit, 8);
            printf("iv:\n");printbhex(iv, 12);printf("\n");
            unsigned short dec_len = recv_len - 24;
            unsigned char aad[5+8], vtag[16];
            for(int i = 0; i < 8; i++){
            
                aad[i] = (client->currentSpec->seq_number >> (8*(7-i))) & 0xFF;
            }
            aad[8] = 0x16;
            aad[9] = 0x03; aad[10] = 0x03;
            aad[11] = (dec_len >> 8) & 0xFF;
            aad[12] = dec_len & 0xFF;
            printf("aad:\n");printbhex(aad, 5+8);printf("\n");
            gcm_aes_256_gcm_ad(iv, 12, client->currentSpec->server_write_key, ciphertext, recv_len - 24, aad, 5+8, decrypted, vtag, 16);
//            printf("decrypted:\n");printbhex(decrypted, recv_len - 24);printf("\n");
            printf("tag:\n");printbhex(vtag, 16);printf("\n");
            recv_len -= 24;
            memcpy(recv_content, decrypted, recv_len);
        }
    }
    
    unsigned char *psh = recv_content;
    unsigned short idx = 0;
    
    unsigned char *new_transcript = (unsigned char*)malloc(client->transcript_len + recv_len);
    
    if(client->transcript_len > 0){
        
        memcpy(new_transcript, client->transcript, client->transcript_len);
        free(client->transcript);
    }
        
    new_transcript += client->transcript_len;
    memcpy(new_transcript, recv_content, recv_len);
    new_transcript -= client->transcript_len;

    client->transcript = new_transcript;
    client->transcript_len += recv_len;
    
    if(hdr[0] == 0x16){
        
        client->last_received_handshake_msg = psh[0];
        while(idx < recv_len){
            
            if(client->last_hello_msg == 0x01){
                
                if(psh[0] != 0x02){
                    
                    printf("erro:%d\n", recv_content[0]);
                    return 1;
                }
                printf("sh\n");
                unsigned int len = (psh[1] << 16) | (psh[2] << 8) | psh[3];
                psh += 4;
                TLSMessage *serverHello = tls_parse_server_hello(psh, len);
                TLSServerHelloParams *params = (TLSServerHelloParams*)serverHello->params;
//                printf("version:%04X\n", params->version);
//                printf("random:\n");
                printbhex(params->random, 32);printf("\n");
//                printf("session_id_length:%d\n", params->session_id_len);
//                printf("session_id:\n");
                printbhex(params->session_id, params->session_id_len);printf("\n");
                printf("cipher suite:%04X\n", params->cipher_suite);
//                printf("comp. method:%02X\n", params->compression_method);
//                printf("extensions:\n");
/*
                if(!params->n_extensions){
                    
                    printf("no extensions\n");
                }
                else{
                    
                    for(int i = 0; i < params->n_extensions; i++){
                    
                        printf("type:%d, length:%d, data:\n", params->extensions[i]->type, params->extensions[i]->data_len);
                        printbhex(params->extensions[i]->data, params->extensions[i]->data_len);
                        printf("\n\n");    
                    }
                }*/
                psh += len;
                idx += 4+len;
//                printf("next_message:0x%02X\n", psh[0]);
                client->last_hello_msg = serverHello->type;
                client->messages[client->n_messages++] = serverHello;
            }
            else if(client->last_hello_msg == 0x02){
                
                if(psh[0] != 0x0B){
                    
                    printf("erro novo\n");
                    return 1;
                }
                client->last_hello_msg = psh[0];
                unsigned int len = (psh[1] << 16) | (psh[2] << 8) | psh[3];
                psh += 4;
                TLSMessage *serverCertificate = tls_parse_certificate_message(psh, len);
                
                TLSCertificateParams *params = (TLSCertificateParams*)serverCertificate->params;
                
                client->messages[client->n_messages++] = serverCertificate;
                psh += len;
                idx += 4+len;
            }
            else if(client->last_hello_msg == 0x16){
            
                if(psh[0] == 0x0C){
                    
                    if(client->n_messages != 3){
                        
                        printf("erro key exchange server\n");
                        return 1;
                    }
                    client->last_hello_msg = psh[0];
                    unsigned int len = (psh[1] << 16) | (psh[2] << 8) | psh[3];
                    psh += 4;
                    TLSMessage *serverKeyExchange = tls_parse_server_key_exchange(psh, len);
                    if(!serverKeyExchange){
                        
                        printf("erro ke\n");
                        return 1;
                    }
                    TLSServerKeyExchangeParams *params = (TLSServerKeyExchangeParams*)serverKeyExchange->params;
//                    printf("key data:\n");
//                    printbhex(params->key_data, params->key_data_len);
                    printf("\n");
                    client->messages[client->n_messages++] = serverKeyExchange;
                    psh += len;
                    idx += 4+len;
                }
            }
            else{
                
                unsigned int len = (psh[1] << 16) | (psh[2] << 8) | psh[3];
                printf("psh:%d, len:%d\n", psh[0], len);
                if(psh[0] == TLSM_CERTIFICATE_REQUEST)
                    client->certificate_needed = 1;
                    
                if(psh[0] == TLSM_SERVER_KEY_EXCHANGE){
                    
                    if(client->last_hello_msg != 0x0B){
                        
                        printf("erro ordem\n");
                        return 1;
                    }
                    psh += 4;
                    TLSMessage *serverKeyExchange = tls_parse_server_key_exchange(psh, len);
                    if(!serverKeyExchange){
                        
                        printf("erro ke1\n");
                        return 1;
                    }
                    psh -= 4;
                    client->messages[client->n_messages++] = serverKeyExchange;
                }
                
                printf("n_messages:%d\n", client->n_messages);
                client->last_hello_msg = psh[0];
                
                psh += 4 + len;
                idx += 4 + len;
            }
            printf("idx:%d, recvlen:%d\n", idx, recv_len);
        }
        printf("OK\n");
        for(int i = 0; i < client->n_messages; i++){
            
            printf("%d, %d\n", client->messages[i]->type, client->last_hello_msg);
        }
    }
    else if(hdr[0] == 0x14){
        
        if(client->last_hello_msg == 0x14){
            
            printf("Order OK\n");
            printf("change cipher spec!\n");
            tls_receive_messages(client);
        }        
    }
    else if(hdr[0] == 0x17){
        
    }
    else if(hdr[0] == 0x15){
        
        printf("alerta: %02X%02X", recv_ct[0], recv_ct[1]);
        return 1;
    }
    return 0;
}

unsigned short tls_free_extension(TLSHelloExtension *extension){
    
    if(extension->data)
        free(extension->data);
    
    free(extension);
    return 0;
}

unsigned short tls_msg_to_stream(TLSMessage *message, unsigned char *out, unsigned short *out_len){
    
    switch(message->type){
        
        case TLSM_CLIENT_HELLO:
            return tls_build_client_hello(message, out, out_len);    
    }
    return 0; 
}

unsigned short tls_concatenate_messages(TLSMessage **messages, unsigned short n_messages, unsigned char *out, unsigned short *out_len){
    
    unsigned char *p_out = out;
    unsigned short t_len = 0;
    for(int i = 0; i < n_messages; i++){
        
        TLSMessage *message = messages[i];
        unsigned short len = 0;
        tls_msg_to_stream(message, 0, &len);
        
        t_len += len;
        
        if(p_out){
                
            tls_msg_to_stream(message, p_out, &len);
            p_out += len;
        }
    }
    *out_len = t_len;
    
    return 0;
}

unsigned short tls_handshake(TLSClient *client, unsigned char *server_name, unsigned char *port){
    
    TLSMessage *clientHello = tls_client_hello(server_name, port);
    if(client->verify_data){
        
        TLSClientHelloParams *params = (TLSClientHelloParams*)clientHello->params;
        for(int i = 0; i < params->n_extensions; i++){
        
            if(params->extensions[i]->type == 0xFF01){
                
                printf("modificar extensao!\n"); 
                params->extensions[i]->data_len = 0x0D;
                params->extensions[i]->data = (unsigned char*)malloc(13);
                params->extensions[i]->data++;
                memcpy(params->extensions[i]->data, client->verify_data, 12);
                params->extensions[i]->data--;
                params->extensions[i]->data[0] = 0x0C;    
            }    
        }
    }
    tls_send_message(client, clientHello);
    int nt = 0;
    FILE *arq = fopen("transcripts/last_client_hello.bn", "wb");
    fwrite(client->transcript, 1, client->transcript_len, arq);
    fclose(arq);
    
    if(tls_receive_messages(client)){
        
        printf("erro hs\n");
        return 1;
    }
    
    while(client->last_hello_msg != 0x0E){
        
        if(tls_receive_messages(client)){
        
            printf("erro hs\n");
            return 1;
        }
    }
    if(client->certificate_needed){
        
        printf("f:cert_needed\n");
        return 1;
    }
    printf("getting params...\n");
    TLSServerHelloParams *shParams = (TLSServerHelloParams*)tls_get_message(client, TLSM_SERVER_HELLO)->params;
    
    if(shParams->cipher_suite != TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA && shParams->cipher_suite != TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384){
        
        printf("cipher suite nao suportada:%04X\n", shParams->cipher_suite);
        return 1;
    }
//    return 0;
    unsigned char px[64], py[64], spx[64], spy[64], privKey[64];
    TLSServerKeyExchangeParams *keParams = (TLSServerKeyExchangeParams*)tls_get_message(client, TLSM_SERVER_KEY_EXCHANGE)->params;
    printf("got params\n");
    srand(time(0));
    b_random(privKey);
    privKey[32] &= 0x7F;
    TLSMessage *clientKeyExchange = 0;
    if(keParams->ecdhe_group == 0x0017){
        b_p256_gen_key_pair(privKey, px, py);
        printf("cke key pair:\n");printbhex(px, 64);printbhex(py, 64);printf("\n");
        if(b_p256_verify_pt(px, py)){
            
            printf("erro ponto hscke\n");
        }
        for(int i = 0; i < 32; i++){
            
            spx[i] = 0x00; spy[i] = 0x00;
            spx[32+i] = keParams->key_data[i];
            spy[32+i] = keParams->key_data[32+i];
        }
        clientKeyExchange = tls_client_key_exchange(px, py);
    }
    else if(keParams->ecdhe_group == 0x001D){
        
        unsigned long long lpx[4], lpk[4];
        x25519transform(privKey);
        btolongi(privKey, lpk);
        bm_el25519(lpk, bm_9, lpx);
        longtobi(lpx, px);
        TLSMessage *cke = (TLSMessage*)malloc(sizeof(TLSMessage));
        cke->type = TLSM_CLIENT_KEY_EXCHANGE;
        TLSClientKeyExchangeParams *params = (TLSClientKeyExchangeParams*)malloc(sizeof(TLSClientKeyExchangeParams));
        params->key_data_len = 32;
        params->key_data = (unsigned char*)malloc(32);
        
        for(int i = 0; i < 32; i++){
            
            params->key_data[i] = px[i];
        }
        cke->params = params;
        clientKeyExchange = cke;
    }
    else{
        
        printf("grupo nao suportado:%04X\n", keParams->ecdhe_group);
        return 1;
    }
    
    tls_send_message(client, clientKeyExchange);
    unsigned char *ecdhe_private_key = privKey;
    if(keParams->ecdhe_group == 0x0017)
        ecdhe_private_key += 32;
        
    tls_set_ecdhe_private_key(client, ecdhe_private_key, 32);
    printf("ecdhe_private_key:\n");printbhex(client->nextSpec->ecdhe_private_key, 32);printf("\n");
    tls_compute_secrets(client);
    tls_send_change_cipher_spec(client);
    tls_send_message(client, tls_finished(client));
    printf("receivenow\n");
    if(tls_receive_messages(client)){
        
        printf("erro hs1\n");
        FILE *arq1 = fopen("transcripts/last_error_transcript.bn", "wb");
        fwrite(client->transcript, 1, client->transcript_len, arq1);
        fclose(arq1);
        return 1;
    }
    printf("okr\n");
    if(client->verify_data){
        
        printf("verify data:\n");printhex(client->verify_data, 12);printf("\n");
    }
    for(int i = 0; i < client->n_messages; i++){
        
        printf("message:%02X\n", client->messages[i]->type);
    }
    return 0;
}