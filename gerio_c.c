#include <gerio.h>

struct gerio_client* new_gerio_client(){
    
    struct gerio_client *client = (struct gerio_client*)malloc(sizeof(struct gerio_client));
    client->tlsClient = 0;
    client->logged_in = 0;
    return client;
}

unsigned short gerio_login(struct gerio_client *client, unsigned char *hostname, unsigned char *portnum, unsigned char *usuario, unsigned char *senha){
    
    client->tlsClient = tls_connect(hostname, portnum);
    if(!client->tlsClient){
        
        return 1;
    }
    if(tls_handshake(client->tlsClient, hostname, portnum)){
        
        printf("erro handshake\n");
        tls_free_client(client->tlsClient);
        return 1;
    }

    unsigned char url[] = "/pdvgc/?c=index&op=acesso", method[] = "POST";
    unsigned char full_url[256], s_request[512], s_request_data[128], s_ct_len[16];
    unsigned short req_len = 0, req_data_len = 0;
    sprintf(full_url, "%s%s", hostname, url);
    sprintf(s_request_data, "usuario=%s&senha=%s", usuario, senha);

    while(s_request_data[req_data_len] != 0x00)
        req_data_len++;
        
    sprintf(s_ct_len, "%d", req_data_len);

//    printf(full_url);printf("\n");
    
    struct http_request *request = new_http_request(method, full_url);
    add_request_header(request, "Host", hostname);
    add_request_header(request, "Content-type", "application/x-www-form-urlencoded");
    add_request_header(request, "Content-length", s_ct_len);
    
    request->data = s_request_data;
    request->data_len = req_data_len;
    
    build_http_request(request, s_request, &req_len);

    tls_send_application_data(client->tlsClient, s_request, req_len);
    if(tls_receive_application_data(client->tlsClient)){
        
        printf("erro appdata\n");
    }
    else{
        
//        printf(s_request);printf("\n");
//        printchars(client->tlsClient->application_data, client->tlsClient->application_data_len);printf("\n");
        struct http_request *response = parse_http_response(client->tlsClient->application_data, client->tlsClient->application_data_len);
        for(int i = 0; i < response->n_headers; i++){
            
//            printf("header:%s=%s\n", response->headers[i]->name, response->headers[i]->content);
            if(!memcmp(response->headers[i]->name, "set-cookie", response->headers[i]->name_len)){
                
                struct http_header *header = response->headers[i];
                unsigned short c1 = 0, name_len = 0;
                unsigned char *pcookie = header->content;
                while(c1 < header->content_len && pcookie[c1] != '=')
                    c1++;
                
                name_len = c1;
                unsigned char name[name_len+1];
                memcpy(name, pcookie, name_len);
                name[name_len] = 0x00;
                pcookie += name_len+1;
                c1 = 0;
                while(pcookie[c1] != ';' && c1 < (header->content_len - name_len - 1))
                    c1++;
                
                unsigned char value[c1+1];
                value[c1] = 0x00;
                memcpy(value, pcookie, c1);
//                printf("valor:%s\n", value);
                memcpy(client->session_id, value, c1+1);
                client->logged_in = 1;
            }
        }
        free_http_request(response);
    }
    sprintf(client->hostname, "%s", hostname);
    request->data = 0;
    free_http_request(request);
    
    tls_free_client(client->tlsClient);
    client->tlsClient = 0;
    return 0;
}

unsigned short gerio_get_transacao(struct gerio_client *client, struct gerio_transacao *transacao){
    
    if(!client->logged_in)
        return 1;

    client->tlsClient = tls_connect(client->hostname, "443");
    if(tls_handshake(client->tlsClient, client->hostname, "443")){
        
        tls_free_client(client->tlsClient);
        client->tlsClient = 0;
        return 1;    
    }
    
    unsigned char full_url[256], s_request[512], s_cookie[128];
    unsigned short s_req_len = 0;
    sprintf(full_url, "%s%s", client->hostname, "/pdvgc/?c=pedido&op=getNovaImpressao&aj=sim");
//    printf(full_url);
    struct http_request *request = new_http_request("GET", full_url);
    
    add_request_header(request, "Host", client->hostname);
    add_request_header(request, "Accept-Encoding", "");
    sprintf(s_cookie, "id_sessao=%s", client->session_id);
    add_request_header(request, "Cookie", s_cookie);
    
    build_http_request(request, s_request, &s_req_len);
    free_http_request(request);
    printchars(s_request, s_req_len);
    tls_send_application_data(client->tlsClient, s_request, s_req_len);
    if(tls_receive_application_data(client->tlsClient)){
        
        return 2;
    }
    printchars(client->tlsClient->application_data, client->tlsClient->application_data_len);
	FILE *arq1 = fopen("last-response.bn", "wb");
	fwrite(client->tlsClient->application_data, 1, client->tlsClient->application_data_len, arq1);
	fclose(arq1);
    struct http_request *response = parse_http_response(client->tlsClient->application_data, client->tlsClient->application_data_len);
    unsigned char *data = response->data;
    unsigned short data_len = 0;
    
    struct http_header *transfer_encoding = get_request_header(response, "transfer-encoding");
    if(transfer_encoding){

        unsigned char tlength[32];
        unsigned short length = 0, offset = 0;
        read_line(response->data, response->data_len, tlength, 32, 0, &offset);
        sscanf(tlength, "%x", &length);
        data_len = length;
        data += offset;
        printf("data(%d, %d, %d):", response->data, offset, data_len);
        for(int i = 0; i < length; i++){
            
            printf("%02X", data[i]);
        }
        printf("\n");
    }
    else{
        
        data_len = response->data_len;
    }   
    
    if(data_len > 22){
		
		data += 8;
		unsigned long mnsg_len = (data[0] << 24)
									|(data[1] << 16)
									|(data[2] << 8)
									|(data[3]);
		
		unsigned short status = (data[4] << 8) | data[5];

		if(status == 2){
			
			unsigned char *pdata = data;
			unsigned short print_len = data[2] << 8 | data[3];
			pdata += 4;
			
			gerio_print("EPSON TM-T20X Receipt", pdata, print_len);
			FILE *arq = fopen("printdata.bn", "wb");
			fwrite(data, 1, data_len, arq);
			fclose(arq);
		}
		free_http_request(response);
		tls_free_client(client->tlsClient);
		client->tlsClient = 0;
		return 1;
	}
    else{
			
		free_http_request(response);
		tls_free_client(client->tlsClient);
		client->tlsClient = 0;
        return 1;
    }
    free_http_request(response);
    tls_free_client(client->tlsClient);
    client->tlsClient = 0;
    return 0;
}

unsigned short gerio_set_transacao(struct gerio_client *client, struct gerio_transacao *transacao){
    
    if(!client->logged_in)
        return 1;
        
    client->tlsClient = tls_connect(client->hostname, "443");
    
    if(tls_handshake(client->tlsClient, client->hostname, "443")){
        
        tls_free_client(client->tlsClient);
        client->tlsClient = 0;
        return 1;    
    }
    
    unsigned char full_url[256], s_request[512], s_cookie[128];
    unsigned short s_req_len = 0;
    sprintf(full_url, "%s/pdvgc/?c=sinc&op=setStatus&aj=sim&tid=%d&status=%d", client->hostname, transacao->tid, transacao->status);
    printf(full_url);
    struct http_request *request = new_http_request("GET", full_url);
    
    add_request_header(request, "Host", client->hostname);
    add_request_header(request, "Accept-Encoding", "");
  
    sprintf(s_cookie, "id_sessao=%s", client->session_id);
    add_request_header(request, "Cookie", s_cookie);
    
    build_http_request(request, s_request, &s_req_len);
    free_http_request(request);
    printchars(s_request, s_req_len);
    tls_send_application_data(client->tlsClient, s_request, s_req_len);
    tls_receive_application_data(client->tlsClient);
    printchars(client->tlsClient->application_data, client->tlsClient->application_data_len);
    tls_free_client(client->tlsClient);
    client->tlsClient = 0;
    return 0;

}

unsigned short free_gerio_client(struct gerio_client *client){
    
    if(client->tlsClient)
        tls_free_client(client->tlsClient);
    return 0;
}

unsigned short gerio_cancelar_tef(struct gerio_transacao *transacao){
    
    const unsigned char msg_format[] = "000-000 = NCN\r\n001-000 = %d\r\n004-000 = 0\r\n706-000 = 4\r\n716-000 = SBMATE AUTOMACAO\r\n733-000 = 100\r\n999-999 = 0\r\n";
    FILE *arq = fopen("C:/tef_dial/req/intpos.001", "wb");
    if(arq){
        
        unsigned char msg[256];
        unsigned short msg_len = 0;
        sprintf(msg, msg_format, transacao->tid, transacao->valor);
        while(msg[msg_len] != 0x00){
            
            msg_len++;
        }
        fwrite(msg, 1, msg_len, arq);
        fclose(arq);
    }
    
    return 0;
}

unsigned short gerio_confirmar_tef(struct gerio_transacao *transacao){
    
    const unsigned char msg_format[] = "000-000 = CNF\r\n001-000 = %d\r\n004-000 = 0\r\n706-000 = 4\r\n716-000 = SBMATE AUTOMACAO\r\n733-000 = 100\r\n999-999 = 0\r\n";
    FILE *arq = fopen("C:/tef_dial/req/intpos.001", "wb");
    if(arq){
        
        unsigned char msg[256];
        unsigned short msg_len = 0;
        sprintf(msg, msg_format, transacao->tid, transacao->valor);
        while(msg[msg_len] != 0x00){
            
            msg_len++;
        }
        fwrite(msg, 1, msg_len, arq);
        fclose(arq);
    }
    
    return 0;
}

unsigned short gerio_print(unsigned char *impressora, unsigned char *dados, unsigned short dados_len){
	
	HANDLE hPrinter;
	int r = OpenPrinter(impressora, &hPrinter, NULL);
	if(!r){
		
		printf("erro\n");
		return 1;
	}
	DWORD sSize = 16;
	BYTE printData[16];
	r = AddJob(hPrinter, 1, printData, 16, &sSize);
	BYTE fPrintData[sSize];
	r = AddJob(hPrinter, 1, fPrintData, sSize, &sSize);
	if(!r){
		
		ClosePrinter(hPrinter);
		printf("erro:%d\n", GetLastError());
		return 1;
	}
	ADDJOB_INFO_1 *jobInfo = (ADDJOB_INFO_1*)fPrintData;
	
	HANDLE hFile = CreateFile(jobInfo->Path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE){
		
		ClosePrinter(hPrinter);
		printf("erro:%d\n", GetLastError());
		return 1;
	}
	WriteFile(hFile, dados, dados_len, NULL, NULL);
	CloseHandle(hFile);
	ScheduleJob(hPrinter, jobInfo->JobId);
	
	ClosePrinter(hPrinter);
	return 0;
}

unsigned short gerio_transacao_para_tef(struct gerio_transacao *transacao){
    
    const unsigned char msg_format[] = "000-000 = CRT\r\n001-000 = %d\r\n003-000 = %d\r\n004-000 = 0\r\n706-000 = 4\r\n716-000 = SBMATE AUTOMACAO\r\n733-000 = 100\r\n999-999 = 0\r\n";
    FILE *arq = fopen("C:/tef_dial/req/intpos.001", "wb");
    if(arq){
        
        unsigned char msg[256];
        unsigned short msg_len = 0;
        sprintf(msg, msg_format, transacao->tid, transacao->valor);
        while(msg[msg_len] != 0x00){
            
            msg_len++;
        }
        fwrite(msg, 1, msg_len, arq);
        fclose(arq);
    }
    
    return 0;
}

unsigned short gerio_tef_para_transacao(struct gerio_transacao *transacao){
    
    FILE *arq = fopen("C:/tef_dial/resp/intpos.001", "rb+");
    if(!arq)
        return 1;
    
    unsigned char line[256], *pline = line, printBuffer[1024];
	unsigned short wLen = 0;
    pline += 10;
    while(!feof(arq)){
        
        fgets(line, 256, arq);
        if(memcmp("009-000", line, 7) == 0){
            
            printf("status:%s\n", pline);
            if(pline[0] == 0x30)
                transacao->status = 1;
        }
		else if(memcmp("711-", line, 4) == 0){
			
			printf("711!\n");
			unsigned short idx = 0;
			while(pline[idx] != 0x00 && wLen < 1024){
				
				printBuffer[wLen++] = pline[idx++];
			}
		}
        printf(line);
    }
	if(wLen){
		printBuffer[wLen++] = 0x1B; printBuffer[wLen++] = 0x6D;
		gerio_print("EPSON TM-T20X Receipt", printBuffer, wLen);
	}
//    transacao->status = 1;
    fclose(arq);
    return 0;
}