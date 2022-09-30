#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct http_request{
    
    unsigned char *method;
    unsigned char *url;
    unsigned char *hostname;
    struct http_header **headers;
    unsigned short n_headers;
    unsigned char *data;
    unsigned short data_len;
};

struct http_header{
    
    unsigned char *name;
    unsigned short name_len;
    unsigned char *content;
    unsigned short content_len;
};

struct http_request* new_http_request(unsigned char *method, unsigned char *url);
unsigned short add_request_header(struct http_request *request, unsigned char *hdr_name, unsigned char *hdr_content);
unsigned short free_request_header(struct http_header *header);
unsigned short free_http_request(struct http_request *request);
struct http_header* get_request_header(struct http_request *request, unsigned char *name);
unsigned short build_http_request(struct http_request *request, unsigned char *out, unsigned short *out_len);
struct http_request* parse_http_response(unsigned char *data, unsigned short data_len);
unsigned short read_line(unsigned char *text, unsigned short text_len, unsigned char *dest, unsigned short dest_len, unsigned short n_line, unsigned short *poffset);