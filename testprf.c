/* ========================================================================== */
/*                                                                            */
/*   Filename.c                                                               */
/*   (c) 2012 Author                                                          */
/*                                                                            */
/*   Description                                                              */
/*                                                                            */
/* ========================================================================== */
#include <stdio.h>
#include <basics.h>
#include <sha.h>

void main()
{
    
    unsigned char secret[33] = "segredoooooooooooooooooooooooooo",
    seed[49] = "sementeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    label[11] = "labellllll",
    out[48];
    sha_sha384_prf2(secret, 32, label, 10, seed, 48, 48, out);
    printf("out:\n");printhex(out, 48);printf("\n");
}
