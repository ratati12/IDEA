/*
 *  Матяш А.А. ККСО-01-19, 
 *  Вариант - 17, 
 *  17 (mod 4) = 1
 *  Режим - CFB
*/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include "idea.h"

typedef unsigned __int128 uint128_t;


FILE * in;
FILE * out;
FILE * fkey;
int main(int argc, char *argv[]) {
    uint64_t i;
    bool ENCRYPT=true, DECRYPT=false;
    uint64_t numtexts = 1;
    uint64_t plaintexts[4]={}, ciphertexts[4]={}, decodetexts[4]={};
    uint64_t initialvector = 0xBBBBCCCC44442222;
    if (argc < 4) 
    {
        printf("Usage: ./IDEA [options] filename key\n  Options:\n\t-e, --encryption\n\t  Encryption\n\t-d, --decryption\n\t  Decryption\n"); 
        return -1;
    }
    if((fkey = fopen(argv[3], "rb")) == 0) return -2;
    uint128_t key;
    for (i = 0; i < 2; i++)
    {
        fread(&(((uint64_t*)&key)[i]), sizeof(uint64_t), 1, fkey);
    }
    fclose(fkey);

    if ((in = fopen(argv[2], "rb")) == 0 ) return -2;
    printf("{+} File open succesfull");
    fseek(in , 0, SEEK_END); 
    int blocks64 = ftell(in) / 8;
    fseek(in, 0, SEEK_SET);
    printf("\n{+} CFB mode in progress..");
    if(strcmp(argv[1], "-e") == 0 | strcmp(argv[1], "--encryption") == 0)
    {
        out = fopen(strcat(argv[2],".enc"), "wb");
        for (int i = 0; i<=blocks64; i++)
        {   
            plaintexts[0] = 0;
            fread(&plaintexts[0], sizeof(uint64_t), 1, in);
            Cipher_IDEA_Mode_CFB(ENCRYPT, key, initialvector, numtexts, plaintexts, ciphertexts);
            fwrite(&ciphertexts[0], sizeof(uint64_t), 1, out);
        }
        printf("\n{+} Result of encryption written into %s file", argv[2]);
    }
    if(strcmp(argv[1], "-d") == 0 | strcmp(argv[1], "--decryption") == 0)
    {   
        out = fopen(strcat(argv[2],".dec"), "wb");
        for (int i = 0; i<=blocks64; i++)
        {
            ciphertexts[0]=0;
            fread(&ciphertexts[0], sizeof(uint64_t), 1, in);
            Cipher_IDEA_Mode_CFB(DECRYPT, key, initialvector, numtexts, ciphertexts, decodetexts);
            fwrite(&decodetexts[0], sizeof(uint64_t), 1, out);
        }
        printf("\n{+} Result of decryption written into %s file", argv[2]);
    }
    fclose(in);
    fclose(out);
    printf("\n{+} Done\n");
    return 0;
}
