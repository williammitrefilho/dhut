#include <httpc.h>
#include <tlsbase.h>

struct gerio_client {
    
    TLSClient *tlsClient;
    unsigned char hostname[128];
    unsigned char session_id[33];
    unsigned short logged_in;
};

struct gerio_transacao{
    
    unsigned long tid;
    unsigned long valor;
    unsigned char status;
};

struct gerio_client* new_gerio_client();
unsigned short gerio_login(struct gerio_client *client, unsigned char *hostname, unsigned char *portnum, unsigned char *usuario, unsigned char *senha);
unsigned short gerio_get_transacao(struct gerio_client *client, struct gerio_transacao *transacao);
unsigned short gerio_set_transacao(struct gerio_client *client, struct gerio_transacao *transacao);
unsigned short free_gerio_client(struct gerio_client *client);
unsigned short gerio_cancelar_tef(struct gerio_transacao *transacao);
unsigned short gerio_confirmar_tef(struct gerio_transacao *transacao);
unsigned short gerio_tef_para_transacao(struct gerio_transacao *transacao);
unsigned short gerio_transacao_para_tef(struct gerio_transacao *transacao);
unsigned short gerio_print(unsigned char *impressora, unsigned char *dados, unsigned short dados_len);