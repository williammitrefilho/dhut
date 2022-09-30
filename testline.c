#include <httpc.h>

void main()
{
    
    unsigned char text[] = "teste\r\nteste2\r\nteste3", dest[512];
    unsigned short text_len = 0;
    while(text[text_len] != 0x00){
        
        text_len++;
    }
    read_line(text, text_len, dest, 512, 2);
    printf(dest);
}