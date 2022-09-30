#include <httpc.h>

struct http_request* new_http_request(unsigned char *method, unsigned char *url){
    
    struct http_request *request = (struct http_request*)malloc(sizeof(struct http_request));
    unsigned short method_len = 0, url_len = 0;
    
    if(method && url){
    
        while(method[method_len] != 0x00) 
            method_len++;
        while(url[url_len] != 0x00)       
            url_len++;
        
        request->method = (unsigned char*)malloc(++method_len);
        memcpy(request->method, method, method_len);
        unsigned short hostname_len = 0;
        while(url[hostname_len] != '/' && hostname_len < url_len)
            hostname_len++;
            
        if(hostname_len > 0){
            request->hostname = (unsigned char*)malloc(hostname_len+1);
            memcpy(request->hostname, url, hostname_len);
            request->hostname[hostname_len] = 0x00;
        }
        else
            request->hostname = 0;
            
        unsigned char *purl = url;
        unsigned short qurl_len = 0; 
        purl += hostname_len;
        while(purl[qurl_len] != 0x00)
            qurl_len++;
    
        if(qurl_len){
            
            request->url = (unsigned char*)malloc(qurl_len+1);
            memcpy(request->url, purl, qurl_len+1);
        }
        else{
            
            request->url = (unsigned char*)malloc(2);
            memcpy(request->url, "/", 2);
        }
    }
    else{
        
        request->method = 0;
        request->url = 0;
    }
    request->n_headers = 0;
    
    request->data = 0;
    
    return request;
}

unsigned short add_request_header(struct http_request *request, unsigned char *hdr_name, unsigned char *hdr_content){
    
    struct http_header **headers = (struct http_header**)malloc((request->n_headers+1)*sizeof(struct http_header*));
    memcpy(headers, request->headers, request->n_headers*sizeof(struct http_header*));
    struct http_header *header = (struct http_header*)malloc(sizeof(struct http_header));
    
    unsigned short name_len = 0, content_len = 0;
    while(hdr_name[name_len] != 0x00)
        name_len++;
        
    while(hdr_content[content_len] != 0x00)
        content_len++;
        
    header->name = (unsigned char*)malloc(name_len+1);
    header->content = (unsigned char*)malloc(content_len+1);
    
    memcpy(header->name, hdr_name, name_len+1);
    memcpy(header->content, hdr_content, content_len+1);
    
    header->name_len = name_len;
    header->content_len = content_len;
    
    request->headers = headers;
    request->headers[request->n_headers++] = header;
    
    return 0;
}

struct http_header* get_request_header(struct http_request *request, unsigned char *name){
    
    unsigned short name_len = 0;
    while(name[name_len] != 0x00)
        name_len++;
        
    for(int i = 0; i < request->n_headers; i++){
    
        if(request->headers[i]->name_len == name_len && !memcmp(request->headers[i]->name, name, name_len)){
            
            return request->headers[i];
        }
    }
    return 0;
}

unsigned short read_line(unsigned char *text, unsigned short text_len, unsigned char *dest, unsigned short dest_len, unsigned short n_line, unsigned short *poffset){
    
    unsigned short cursor = 0, linelen = 0, nl = 0;
    unsigned char *ptext = text;
    while(cursor < (text_len - 1)){
        
//        printf("%d,", cursor);
        if(text[cursor] == '\r' && text[cursor+1] == '\n'){
            
//            printf("%d(%d)[%d]%s\n", nl, linelen, cursor, ptext);
            if(nl == n_line){
            
                memcpy(dest, ptext, linelen);
                dest[linelen] = 0x00;
                if(poffset){
                    *poffset = linelen + 2;
                }
                return 0;
            }
            ptext += linelen + 2;
            cursor += 2;
            linelen = 0;
            nl++;
            continue;
        }
        cursor++;
        linelen++;
    }
    linelen = text_len - (ptext - text);
    memcpy(dest, ptext, linelen);
    return 1;
}

unsigned short free_request_header(struct http_header *header){
    
    if(header->name)
        free(header->name);
     
    if(header->content)
        free(header->content);
      
    free(header);
    
    return 0;
}

unsigned short free_http_request(struct http_request *request){

    if(request->url)
        free(request->url);
  
    if(request->hostname)
        free(request->hostname);
   
    if(request->method)
        free(request->method);
        
    for(int i = 0; i < request->n_headers; i++){

        free_request_header(request->headers[i]);
    }

    if(request->data)
        free(request->data);

    free(request);

    return 0;
}

const unsigned char r_format[] = "%s %s HTTP/1.1";

unsigned short build_http_request(struct http_request *request, unsigned char *out, unsigned short *out_len){
    
    unsigned char buf[512], *pbuf = buf;
    unsigned short total_len = 0;
    sprintf(pbuf, r_format, request->method, request->url);
    while(pbuf[0] != 0x00){
        
        pbuf++;
        total_len++;
    }
    pbuf[0] = '\r';
    pbuf[1] = '\n';
    pbuf += 2;
    for(int i = 0; i < request->n_headers; i++){

        memcpy(pbuf, request->headers[i]->name, request->headers[i]->name_len);
        pbuf += request->headers[i]->name_len;
        pbuf[0] = ':'; pbuf[1] = ' ';
        pbuf+= 2;
        memcpy(pbuf, request->headers[i]->content, request->headers[i]->content_len);
        pbuf += request->headers[i]->content_len;
        pbuf[0] = '\r';
        pbuf[1] = '\n';
        pbuf += 2;
        pbuf[0] = 0x00;
    }

    pbuf[0] = '\r';
    pbuf[1] = '\n';
    pbuf += 2;
    if(request->data){
        
        memcpy(pbuf, request->data, request->data_len);
        pbuf += request->data_len;
    }
    pbuf[0] = 0x00;

    total_len = pbuf - buf;
    if(out)
        memcpy(out, buf, total_len);
        
    if(out_len)
        *out_len = total_len;
    
    return 0;
}

struct http_request* parse_http_response(unsigned char *data, unsigned short data_len){
   
    unsigned char line[512];
    unsigned char linelen = 0, firstline = 1, headers = 0;
    unsigned short cursor = 0;
    struct http_request *response;

    while(cursor < data_len && headers < 2){
    
        if(cursor < (data_len - 1) && data[cursor] == '\r' && data[cursor+1] == '\n'){
            
            if(firstline){
                
                if(linelen < 4){
                    
                    return 0;
                }
                if(memcmp("HTTP", line, 4)){
                    
                    return 0;
                }
                response = new_http_request(0, 0);
                response->hostname = 0;
                response->url = 0;
                response->method = 0;
                firstline = 0;
                headers = 1;
                cursor += 2;
                linelen = 0;
                continue;
            }
            line[linelen] = 0x00;
            if(!firstline){

                if(headers == 1 && linelen == 0){
                    
                    headers = 2;
                }
                else if(headers == 1){
                    
                    unsigned short c1 = 0;
                    while(c1 < 512 && line[c1] != ':'){
                        
                        if(line[c1] >= 0x41 && line[c1] <= 0x5A)
                            line[c1] += (0x20);
                        
                        c1++;
                    }
                    unsigned short c2 = linelen - c1 - 1;
                    unsigned char *pline = line;
                    pline += c1 + 1;
                    if(pline[0] == 0x20)
                        pline++;
                    
                    line[c1] = 0x00;
                    add_request_header(response, line, pline);
//                    printf("header:(%s %s)\n", line, pline);
                }
            }
//            printf("linha(%d %d):%s\n", linelen, cursor, line);

            linelen = 0;
            cursor += 2;
            continue;
        } 
        if(linelen < 511){
            
            line[linelen++] = data[cursor];
        }
        cursor++;
    }
    unsigned short content_len = data_len - cursor;
    if(content_len){
        
        unsigned char *pdata = data;
        pdata += cursor;
        response->data = (unsigned char*)malloc(content_len);
        memcpy(response->data, pdata, content_len);
        response->data_len = content_len;
//        printf("rest_len=%d\n", content_len);
    }
    return response;
}