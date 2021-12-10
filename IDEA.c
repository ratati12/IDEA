//  Матяш А.А. ККСО-01-19, 
//  Вариант - 17, 
//  17 (mod 4) = 1
//  Режим - CFB

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#define max 65537
#define fuyi 65536
#define one 65536
#define round 8
typedef unsigned __int128 uint128_t;

void cipher();
void en_key();
void de_key();
unsigned int inv();
unsigned mul();

int main (int argc, char* argv[])
{
    int i, j, k, x;
    uint16_t Z[54];// = (uint16_t*) malloc(sizeof(uint16_t) * 54); // 52 16-битных подключа шифрования
    uint16_t DK[7][10]; // 52 16-биных подключа дешифрования
    uint64_t XX; // открытый текст
    uint16_t TT[5]; // расшифрованный закрытый текст
    uint16_t YY[5]; // закрытый текст
    uint128_t key;
    ((uint64_t*)&key)[0] = (uint64_t)0x1122334455667788; // 128-битный ключ 
    ((uint64_t*)&key)[1] = (uint64_t)0x1122334455667788; // 128-битный ключ 
    XX = (uint64_t)-1;
    en_key(key, Z); // генерация подключей шифрования Z[i][r]
    printf("\n\n encryption keys   DK1\t DK2\t DK3\t DK4\t DK5\t DK6\n");
    j = 1;
    for (i = 1; i <= 52; i++)
    {
        if (i == 1 | i == 7 | i == 13 | i == 19 | i == 25 | i == 31 | i == 37 | i == 43 | i == 49)
        {
            printf("\n%3d-th round", j);
            j++;
        }
        printf("\t%6u", Z[i]);
    } 
    //de_key(Z, DK); // генерация подключей дешифрования DK[i][r]
    printf("\n\n decryption keys   DK1\t DK2\t DK3\t DK4\t DK5\t DK6\n");
    for (j = 1; j <= 9; j++)
    {
        printf("\n %3d-th round ", j);
        if (j==9)
            for (i = 1; i <= 4; i++) printf(" %6d", DK[i][j]);
        else
            for (i = 1; i <= 6; i++) printf(" %6d", DK[i][j]);
    }
    printf ("\n\n plaintext X %6u %6u %6u %6u", ((uint16_t*)&XX)[1], ((uint16_t*)&XX)[2], ((uint16_t*)&XX)[3], ((uint16_t*)&XX)[4]);
    cipher(XX, YY, Z);
    printf ("\n\n ciphertext Y %6u %6u %6u %6u", YY[1], YY[2], YY[3], YY[4]);
    //cipher(YY, XX, DK);
    printf ("\n\n result of decryption T %6u %6u %6u %6u\n", TT[1], TT[2], TT[3], TT[4]);
    return 0;
}

void en_key(uint128_t key, uint16_t* Z)
{
    int i, j=0,k;
    uint16_t temp[9];
    while(j<52)
    {
        for (i = 1; i <= 8; i++)
        {
            temp[i] = ((uint16_t*)&key)[i-1];
        }
        for (k = 1; k <= 8; k++)
        {
            Z[j+k]=temp[k];
        }
        key = (key<<25) | (key >> 103);
        j+=8;
    }
}

void cipher(uint64_t XX, uint16_t* YY, uint16_t* Z)
{
    int i, j;
    int16_t A, B, C, D, E, F, P[5];
    for (i = 1; i <= 4; i++)
    {
        P[i] = ((uint16_t*)&XX)[i-1];
    }
    for (i = 1; i <= 8; i++) // Раунды 1-8
    {

        A = (P[1] * Z[1+(i-1)*6]) % max;
        B = (P[2] + Z[2+(i-1)*6]) % fuyi;
        C = (P[3] + Z[3+(i-1)*6]) % fuyi;
        D = (P[4] * Z[4+(i-1)*6]) % max;
        E = A^C;
        F = B^D;
        P[1] = A ^ ((((F + ((E*Z[5+(i-1)*6])%max))%fuyi)*Z[6+(i-1)*6])%max);
        P[2] = C ^ ((((F + ((E*Z[5+(i-1)*6])%max))%fuyi)*Z[6+(i-1)*6])%max);
        P[3] = B ^ ((((E*Z[5+(i-1)*6])%max)  + ((((F + ((E*Z[5+(i-1)*6])%max))%fuyi)*Z[6+(i-1)*6])%max))%fuyi);
        P[4] = D ^ ((((E*Z[5+(i-1)*6])%max)  + ((((F + ((E*Z[5+(i-1)*6])%max))%fuyi)*Z[6+(i-1)*6])%max))%fuyi);
    }
    YY[1] = (P[1] * Z[49]) % max;   // Раунды 49-52
    YY[2] = (P[2] + Z[50]) % fuyi;  //
    YY[3] = (P[3] + Z[51]) % fuyi;  //
    YY[4] = (P[4] * Z[52]) % max;   //
}














/*
   void en_key(uint128_t key, uint16_t* Z)
   {
   int i, j = 1;
   while (i <= 52) //Генерация 16-битных ключей 1-48
   {
#if 0
for  ( j = 0 ; j < 8 ; j++ ) {
Z[i+j] = ((uint16_t*)&key)[(j+6)%8];
}
i += 8;
{
uint64_t *ptr, tmp;
ptr = (uint64_t*)&key;
tmp = (ptr[0] >> 39);
ptr[0] = (ptr[0] << 25) | (ptr[1] >> 39);
ptr[1] = (ptr[1] << 25) | tmp; 
}
#else
Z[i] = (key >> 112) | (key << 16);
Z[i+1] = (key >> 96) | (key << 32);
Z[i+2] = (key >> 80) | (key << 48);
Z[i+3] = (key >> 64) | (key << 64);
Z[i+4] = (key >> 48) | (key << 80);
Z[i+5] = (key >> 32) | (key << 96);
Z[i+6] = (key >> 16) | (key << 112);
Z[i+7] = key;
i += 8;
key = (key << 25) | (key >> 103);
#endif
}
#if 0
for  ( j = 0 ; j < 4 ; j++ ) {
Z[i+j] = ((uint16_t*)&key)[(j+7)%8];
}
#else
Z[i] = (key >> 112) | (key << 16);
Z[i+1] = (key >> 96) | (key << 32);
Z[i+2] = (key >> 80) | (key << 48);
Z[i+3] = (key >> 64) | (key << 64);
#endif
}*/

