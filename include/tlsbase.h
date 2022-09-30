#include <ber_entity.h>
#include <p256.h>
#include <prf.h>
#include <winsock2.h>
#include <converters.h>
#include <gcm.h>
#include <x25519.h>

#ifndef TLSBASE_H

#define TLSBASE_H

#define TLSM_CLIENT_HELLO 0x01
#define TLSM_SERVER_HELLO 0x02
#define TLSM_CERTIFICATE_REQUEST 0x0D
#define TLSM_CERTIFICATE 0x0B
#define TLSM_FINISHED 0x14
#define TLSM_CERTIFICATE_VERIFY 0x0F
#define TLSM_CLIENT_KEY_EXCHANGE 0x10
#define TLSM_SERVER_KEY_EXCHANGE 0x0C

#define TLS_ECDHE_P256 0x0017
#define TLS_ECDHE_X25519 0x001D

#define TLS_SHA1 0x0100
#define TLS_SHA256 0x0101
#define TLS_SHA384 0x0102

#define TLS_AES_256_CBC 0x201
#define TLS_AES_256_GCM 0x202

#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 0xC030
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA 0xC014

#define TLSERROR_SOCKET_ERROR 0x0001

unsigned short tls_last_error;
unsigned char label_extended_master_secret[23];
unsigned char label_key_expansion[14];
unsigned char label_client_finished[16];
unsigned char b_change_cipher_spec[6];


typedef struct TLSMessage{
    
    unsigned char type;
    void *params;
} TLSMessage;

typedef struct TLSHelloExtension{
    
    unsigned short type;
    unsigned short data_len;
    unsigned char *data;
} TLSHelloExtension;

typedef struct TLSCipherSpec{
    
    unsigned char *ecdhe_private_key;
    unsigned short ecdhe_private_key_len;
    unsigned char *master_secret;
    unsigned short master_secret_len;
    unsigned char *client_write_mac_key;
    unsigned short client_write_mac_key_len;
    unsigned char *server_write_mac_key;
    unsigned short server_write_mac_key_len;
    unsigned char *client_write_key;
    unsigned short client_write_key_len;
    unsigned char *server_write_key;
    unsigned short server_write_key_len;
    
    unsigned char *client_write_iv;
    unsigned short client_write_iv_len;
    unsigned char *server_write_iv;
    unsigned short server_write_iv_len;
    unsigned long long seq_number;
    unsigned short cipher_suite;
    void *other_params;
} TLSCipherSpec;

typedef struct TLSClientHelloParams{
    
    TLSHelloExtension **extensions;
    unsigned short n_extensions;
    unsigned char *server_name;
    unsigned char random[32];
    unsigned char session_id[32];
    unsigned short *cipher_suites;
    unsigned short n_cipher_suites;
    unsigned char *compression_methods;
    unsigned char n_compression_methods;    
} TLSClientHelloParams;

typedef struct TLSServerHelloParams{
    
    unsigned short version;
    TLSHelloExtension **extensions;
    unsigned short n_extensions;
    unsigned char random[32];
    unsigned char session_id_len;
    unsigned char session_id[32];
    unsigned short cipher_suite;
    unsigned char compression_method;
} TLSServerHelloParams;

typedef struct TLSCertificateParams{

    BerEntityList *certificates;
} TLSCertificateParams;

typedef struct TLSServerKeyExchangeParams{
    
    unsigned short ecdhe_group;
    unsigned char *key_data;
    unsigned short key_data_len;
} TLSServerKeyExchangeParams;

typedef struct TLSClientKeyExchangeParams{
    
    unsigned short key_data_len;
    unsigned char *key_data;
} TLSClientKeyExchangeParams;

typedef struct TLSClient{
    
    SOCKET socket;
    unsigned short prf_hash;
    unsigned char last_hello_msg;
    unsigned char last_received_handshake_msg;
    unsigned char last_sent_handshake_msg;
    unsigned char *transcript;
    unsigned short transcript_len;
    TLSMessage **messages;
    unsigned short n_messages;
    unsigned char server_hello_random[32];
    unsigned char client_hello_random[32];
    unsigned char session_id[32];
    unsigned short session_id_len;
    
    unsigned char *application_data;
    unsigned short application_data_len;
    
    unsigned char certificate_needed;
    unsigned char *verify_data;
    
    TLSCipherSpec *currentSpec;
    TLSCipherSpec *nextSpec;
} TLSClient;

typedef struct TLSSignature{
    
    unsigned char hash_algo;
    unsigned char signature_algo;
    unsigned short signature_len;
    unsigned char *signature;
} TLSSignature;

void               printbhex(unsigned char *data, unsigned short len);
unsigned short     tls_build_client_hello(TLSMessage *clientHello, unsigned char *out, unsigned short *out_len);
unsigned short     tls_build_client_key_exchange(TLSMessage *clientKeyExchange, unsigned char *out, unsigned short *out_len);
unsigned short     tls_build_finished(TLSMessage *finished, unsigned char *out, unsigned short *out_len);
TLSMessage*        tls_client_hello(const unsigned char server_name[], const unsigned char port[]);
TLSMessage*        tls_client_key_exchange(unsigned char px[64], unsigned char py[64]);
unsigned short     tls_compute_secrets(TLSClient *client);
unsigned short     tls_concatenate_messages(TLSMessage **messages, unsigned short n_messages, unsigned char *out, unsigned short *out_len);
TLSClient*         tls_connect(unsigned char *server_name, unsigned char *port);
TLSHelloExtension* tls_extension(unsigned short type, unsigned char *data, unsigned short data_len);
TLSMessage*        tls_finished(TLSClient *client);
unsigned short     tls_free_cipher_spec(TLSCipherSpec *spec);
unsigned short     tls_free_client(TLSClient* client);
unsigned short     tls_free_extension(TLSHelloExtension *extension);
TLSMessage*        tls_get_message(TLSClient *client, unsigned char message_type);
unsigned short     tls_handshake(TLSClient *client, unsigned char *server_name, unsigned char *port);
unsigned short     tls_msg_to_stream(TLSMessage *message, unsigned char *out, unsigned short *out_len);

TLSMessage*        tls_parse_certificate_message(unsigned char *data, unsigned short data_len);
TLSMessage*        tls_parse_server_hello(unsigned char *data, unsigned short data_len);
TLSMessage*        tls_parse_server_key_exchange(unsigned char *data, unsigned short data_len);

unsigned short     tls_receive_application_data(TLSClient *client);
unsigned short     tls_receive_messages(TLSClient *client);
unsigned short     tls_send_message(TLSClient *client, TLSMessage *message);
unsigned short     tls_send_application_data(TLSClient *client, unsigned char *data, unsigned short data_len);
unsigned short     tls_send_change_cipher_spec(TLSClient *client);
unsigned short     tls_set_ecdhe_private_key(TLSClient *client, unsigned char *ecdhe_private_key, unsigned short ecdhe_private_key_len);

#endif