/* ========================================================================== */
/*                                                                            */
/*   Filename.c                                                               */
/*   (c) 2012 Author                                                          */
/*                                                                            */
/*   Description                                                              */
/*                                                                            */
/* ========================================================================== */
#include <stdio.h>
//#include <windows.h>
#include <tlsbase.h>
#include <basics.h>
#include <string.h>
#include <httpc.h>

//unsigned char message[] = "BARCLAY";

int main(int argc, char *argv[])
{
    
    WSADATA wsData;
    WSAStartup(MAKEWORD(2, 2), &wsData);
    
    struct gerio_client *client = new_gerio_client();   
    unsigned short ret = gerio_login(client, "gerio.app", "443", "jaguare", "jaguare");
    if(!ret){
    
        if(client->logged_in){
            
            struct gerio_transacao transacao = {0, 0, 0};        
            if(!gerio_get_transacao(client, &transacao)){
                
                printf("transacao:%d %d\n", transacao.tid, transacao.valor);
                gerio_transacao_para_tef(&transacao);
                transacao.status = 1;
                gerio_set_transacao(client, &transacao);
            }
            printf("id_sessao:%s\n", client->session_id);
        }
        
        free_gerio_client(client);
    }
        
    printf("ret:%d\n", ret);
    WSACleanup(); 
    return 0;
}