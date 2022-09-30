/* ========================================================================== */
/*                                                                            */
/*   Filename.c                                                               */
/*   (c) 2012 Author                                                          */
/*                                                                            */
/*   Description                                                              */
/*                                                                            */
/* ========================================================================== */
#include <stdio.h>

const unsigned char msg_format[] = "000-000 = CRT\r\n001-000 = %d\r\n003-000 = %d\r\n004-000 = 0\r\n706-000 = 4\r\n716-000 = SBMATE AUTOMACAO\r\n733-000 = 100\r\n999-999 = 0\r\n";
void main()
{
    
    FILE *arq = fopen("C:/tef_dial/req/intpos.001", "wb");
    if(arq){
        
        unsigned char msg[256];
        fwrite(msg, 1, sizeof(msg) - 1, arq);
        fclose(arq);
    }
}