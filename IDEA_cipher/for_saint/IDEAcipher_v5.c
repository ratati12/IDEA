#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include "CipherModes_v1.h"

typedef unsigned __int128 uint128_t;


FILE * in;
FILE * out;
int main(int argc, char *argv[]) {
    uint64_t i;
    bool ENCRYPT=true, DECRYPT=false;
    uint64_t numtexts = 1;
    uint64_t plaintexts[4]={}, ciphertexts[4]={}, decodetexts[4]={};
    uint64_t initialvector = 0xBBBBCCCC44442222;
    uint128_t key = (((uint128_t)0xabcdabcdabcdabcd)<<64)+0xabcdabcdabcdabcd;
    if (argc < 3) {printf("Error: ./IDEA {-e/-d} filename\n"); return -1;}
    in = fopen(argv[2], "rb");
    fseek(in , 0, SEEK_END); 
    int blocks64 = ftell(in) / 8;
    fseek(in, 0, SEEK_SET);
    printf("\nOFB mode\n");
    if(strcmp(argv[1], "-e") == 0)
    {
        out = fopen(strcat(argv[2],".enc"), "wb");
        for (int i = 0; i<=blocks64; i++)
        {   
            plaintexts[0] = 0;
            fread(&plaintexts[0], sizeof(uint64_t), 1, in);
            Cipher_IDEA_Mode_OFB(ENCRYPT, key, initialvector, numtexts, plaintexts, ciphertexts);
            fwrite(&ciphertexts[0], sizeof(uint64_t), 1, out);
        }
    }
    if(strcmp(argv[1], "-d") == 0)
    {   
        out = fopen(strcat(argv[2],".dec"), "wb");
        for (int i = 0; i<=blocks64; i++)
        {
            ciphertexts[0]=0;
            fread(&ciphertexts[0], sizeof(uint64_t), 1, in);
            Cipher_IDEA_Mode_OFB(DECRYPT, key, initialvector, numtexts, ciphertexts, decodetexts);
            fwrite(&decodetexts[0], sizeof(uint64_t), 1, out);
        }
    }
    return 0;
}
