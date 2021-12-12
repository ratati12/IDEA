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
    uint16_t DK[54]; // 52 16-биных подключа дешифрования
    uint64_t XX; // открытый текст
    uint64_t TT; // расшифрованный закрытый текст
    uint64_t YY; // закрытый текст
    uint128_t key;
    ((uint64_t*)&key)[0] = (uint64_t)0x0001000200030004; // 128-битный ключ 
    ((uint64_t*)&key)[1] = (uint64_t)0x0005000600070008; // 128-битный ключ
    for (i = 0; i < 4; i++)
    {
        ((uint16_t*)&XX)[i] = (uint16_t)(0x0+i);
    }
    printf("\n\n 128 key\n");
    for (i = 0; i < 8; i++)
    {
        printf("%x", ((uint16_t*)&key)[i]);
    }
    en_key(key, Z); // генерация подключей шифрования Z[i][r]
    printf("\n\n encryption keys   Z1\t Z2\t Z3\t Z4\t Z5\t Z6\n");
    j = 1;
    for (i = 1; i <= 52; i++)
    {
        if (i == 1 | i == 7 | i == 13 | i == 19 | i == 25 | i == 31 | i == 37 | i == 43 | i == 49)
        {
            printf("\n%3d-th round", j);
            j++;
        }
        printf("\t%x", Z[i]);
    } 
    de_key(Z, DK); // генерация подключей дешифрования DK[i][r]
    printf("\n\n decryption keys   DK1\t DK2\t DK3\t DK4\t DK5\t DK6\n");
    j = 1;
    for (i = 1; i <= 52; i++)
    {
        if (i == 1 | i == 7 | i == 13 | i == 19 | i == 25 | i == 31 | i == 37 | i == 43 | i == 49)
        {
            printf("\n%3d-th round", j);
            j++;
        }
        printf("\t%x", DK[i]);
    }
    printf ("\n\n plaintext X %x %x %x %x", ((uint16_t*)&XX)[0], ((uint16_t*)&XX)[1], ((uint16_t*)&XX)[2], ((uint16_t*)&XX)[3]);
    cipher(XX, YY, Z);
    printf ("\n\n ciphertext Y %x %x %x %x", ((uint16_t*)&YY)[0], ((uint16_t*)&YY)[1], ((uint16_t*)&YY)[2], ((uint16_t*)&YY)[3]);
    cipher(YY, TT, DK);
    printf ("\n\n result of decryption T %x %x %x %x\n", ((uint16_t*)&TT)[0], ((uint16_t*)&TT)[1], ((uint16_t*)&TT)[2], ((uint16_t*)&TT)[3]);
    return 0;
}

void en_key(uint128_t key, uint16_t* Z)
{
    int i, j=0,k;
    uint16_t temp[9];
    while(j<52)
    {
        for (i = 1; i <= 4; i++)
        {
            temp[i] = ((uint16_t*)&key)[4-i];
            temp[i+4] = ((uint16_t*)&key)[8-i];
        }
        for (k = 1; k <= 8; k++)
        {
            Z[j+k]=temp[k];
        }
        key = (key<<25) | (key >> 103);
        j+=8;
    }
}

unsigned inv(unsigned xin){ 
    long n1,n2,q,r,b1,b2,t;
    if (xin == 0)
        b2 = 0;
    else{ 
        n1 = max; 
        n2 = xin; 
        b2 = 1; 
        b1 = 0;
        do{
            r = (n1 % n2); 
            q = (n1-r)/n2;
            if (r == 0){
                if (b2 < 0) 
                    b2 = max + b2;
            }
            else{
                n1 = n2;
                n2 = r;
                t = b2;
                b2 = b1 - q*b2;
                b1 = t; 
            }
        }
        while (r != 0);
    }
    return (unsigned)b2;
}

void de_key(uint16_t* Z, uint16_t* DK)
{
    int i=52, j;
    while (i>0) 
    {
        DK[53-i]=inv(Z[i-3]);
        DK[54-i]=fuyi - Z[i-2];
        DK[55-i]=fuyi - Z[i-1];
        DK[56-i]=inv(Z[i]);
        DK[57-i]=Z[i-5];
        DK[58-i]=Z[i-4];
        i-=6;
    }     
}

void cipher(uint64_t XX, uint64_t YY, uint16_t* Z)
{
    int i, j;
    uint16_t A=0, B=0, C=0, D=0, E=0, F=0, P[5];
    for (i = 1; i <= 4; i++)
    {
        P[i] = ((uint16_t*)&XX)[i-1];
    }
    printf("\n\n ROUND DATA\tD1\tD2\tD3\tD4\n");
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
        //printf ("%d: A = %x, B = %x, C = %x, D = %x, E = %x, F = %x\n", i, A, B, C, D, E, F);
        printf("%d-th round\t%x\t%x\t%x\t%x\n", i, P[1], P[2], P[3], P[4]);
    }
    ((uint16_t*)&YY)[0] = (P[1] * Z[49]) % max;   // Раунды 49-52
    ((uint16_t*)&YY)[1] = (P[2] + Z[50]) % fuyi;  //
    ((uint16_t*)&YY)[2] = (P[3] + Z[51]) % fuyi;  //
    ((uint16_t*)&YY)[3] = (P[4] * Z[52]) % max;   //
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

