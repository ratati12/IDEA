//  Матяш А.А. ККСО-01-19, 
//  Вариант - 17, 
//  17 (mod 4) = 1
//  Режим - CFB

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
# define max 65537
# define fuyi 65536
# define one 65535
# define round 8
typedef unsigned __int128 uint128_t;


void cipher(unsigned XX[5],unsigned YY[5],uint16_t Z[7][10]);   // Функция шифрования 
void en_key(uint128_t key, uint16_t Z[7][10] );                 // Функция генерации ключей шифрования
void de_key(uint16_t Z[7][10],uint16_t DK[7][10]);              // Функция генерации ключей дешифрования
unsigned inv(unsigned xin);                                     // Функция мультпликативной инверсии
unsigned mul(unsigned a, unsigned b);                           // Функция умножения 
void IDEA(unsigned XX[5], unsigned YY[5], char* mode);
FILE* in;
FILE* out;

int main(int argc, char * argv[])
{
    unsigned XX[5] = {0};
    unsigned YY[5] = {0};
    if (argc < 2 ) 
    {
        printf("Usage: ./IDEA -e/-d filename\n");
        return -1;
    }
    in = fopen(argv[2], "rb");
    out = fopen(strstr(argv[1], ".encrypted"), "wb");
    while(1)
    {
        for (int i = 1; i <= 4; i++)
        {
            XX[i] = 0;
            fread(&XX[i], sizeof(uint16_t), 1, in);
            printf("DEBUG : %x\n", XX[i]);
        }
        IDEA(XX, YY, argv[1]);
        for (int i = 1; i <= 4; i++)
        {
            fwrite(&YY[i], sizeof(unsigned), 1, out);
        }
    }
    fclose(in);
    fclose(out);
}


void IDEA(unsigned XX[5], unsigned YY[5], char* mode){
    int i, j, k, x;
    uint16_t Z[7][10]; //матрица 16-битных подключей шифрования
    uint16_t DK[7][10]; //матрица 16-битных подключей шиформавания
    // unsigned TT[5]; //4 16-битных блока расшифорванных данных
    uint128_t key; // 128-битный ключ
    ((uint64_t*)&key)[0] = (uint64_t)0x0001000200030004; // 128-битный ключ 
    ((uint64_t*)&key)[1] = (uint64_t)0x0005000600070008; // 128-битный ключ
    en_key(key, Z); 
        printf("\n encryption keys Z1 Z2 Z3 Z4 Z5 Z6");
          for(j = 1; j <= 9; j++){ 
          printf("\n %3d-th round ", j);
          if (j == 9) 
          for(i = 1; i <= 4; i++) 
          printf(" %x",Z[i][j]);
          else 
          for(i = 1; i <= 6; i++)
          printf(" %x",Z[i][j]);
          }

    de_key(Z,DK); 
        printf("\n \n decryption keys DK1 DK2 DK3 DK4 DK5 DK6 ");
          for(j = 1; j <= 9; j++){
          printf("\n %3d-th round ", j);
          if (j == 9)
          for(i = 1; i <= 4; i++)
          printf(" %x",DK[i][j]);
          else
          for(i = 1; i <= 6; i++)
          printf(" %x",DK[i][j]);
          }

        printf("\n \n plaintext X %x %x %x %x \n", XX[1], XX[2], XX[3], XX[4]);
    if (strcmp(mode, "-e") == 0) cipher(XX,YY,Z);
    if (strcmp(mode, "-d") == 0) cipher(XX,YY,DK);
    //    printf("\n \n cipherhertext Y %x %x %x %x \n", YY[1], YY[2], YY[3], YY[4]);
    //    cipher(YY,TT,DK);
    //    printf("\n \n result T %x %x %x %x \n", TT[1], TT[2], TT[3], TT[4]);
}

/* Алгоритм шифрования */
void cipher(unsigned XX[5],unsigned YY[5],uint16_t Z[7][10]){
    uint16_t r,x1,x2,x3,x4,kk,t1,t2,a;
    x1 = XX[1]; 
    x2 = XX[2]; 
    x3 = XX[3]; 
    x4 = XX[4];
    for (r = 1; r < 9; r++){ /* Раунды 1-8 */
        printf ("R = %d\n", r);
        x1 = mul(x1, Z[1][r]); 
        x4 = mul(x4, Z[4][r]);
        x2 = (x2 + Z[2][r]) & one; 
        x3 = (x3 + Z[3][r]) & one;
        kk = mul(Z[5][r], (x1^x3));
        t1 = mul(Z[6][r], (kk + (x2^x4)) & one);
        t2 = (kk + t1) & one;
        x1 = x1^t1; 
        x4 = x4^t2;
        a = x2^t2; 
        x2 = x3^t1; 
        x3 = a;

        if (r == 8) printf("CHECKPOINT");

        //printf("\n %3d-th rnd %x %x %x %x ", r, x1, x2, x3, x4);
    }
     printf("CHECKPOINT2");

    /* Выходное преобразование */
    YY[1] = mul(x1, Z[1][round+1]);
    YY[4] = mul(x4,Z[4][round+1]);
    YY[2] = (x3 + Z[2][round +1]) & one;
    YY[3] = (x2 + Z[3][round+1]) & one;
}

unsigned mul(unsigned a, unsigned b){
    long int p;
    long unsigned q;
    if (a == 0)
        p = max-b;
    else if (b == 0)
        p = max-a;
    else{
        q = (unsigned long)a*(unsigned long)b;
        p = (q & one) - (q >> 16);
        if (p <= 0)
            p = p+max;
    }
    return (unsigned)(p & one);
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

/* Генерация ключей шифрования */
void en_key(uint128_t key, uint16_t Z[7][10]){
    int i, j=0,k;
    uint16_t temp[9], S[54];
    while(j<52)
    {
        for (i = 1; i <= 4; i++)
        {
            temp[i] = ((uint16_t*)&key)[4-i];
            temp[i+4] = ((uint16_t*)&key)[8-i];
        }
        for (k = 1; k <= 8; k++)
        {   
            if (j == 48 && k > 4) break;
            S[j+k]=temp[k];
        }
        key = (key<<25) | (key >> 103);
        j+=8;
    }
    for (i = 1; i <= 7; i++)
    {
        for (j = 1; j <= 10; j++)
        {
            if (j == 9 & i > 4) break;
            Z[i][j] = S[i+(j-1)*6];
        }
    }
}

/* Генерация ключей дешифрования */
void de_key(uint16_t Z[7][10],uint16_t DK[7][10]){
    int i, j;
    uint16_t tZ[54], tD[54];
    for (i = 1; i <= 7; i++)
    {
        for (j = 1; j <= 10; j++)
        {
            if (j == 48 && i > 4) break;
            tZ[i+(j-1)*6] = Z[i][j];
        }
    } 
    i = 52; 
    while (i>0) 
    {
        tD[53-i]=inv(tZ[i-3]);
        if (i == 52 | i < 6)
        {
            tD[54-i]=fuyi - tZ[i-2];
            tD[55-i]=fuyi - tZ[i-1]; 
        }    
        else 
        {
            tD[54-i]=fuyi - tZ[i-1];
            tD[55-i]=fuyi - tZ[i-2];
        } 
        tD[56-i]=inv(tZ[i]);
        tD[57-i]=tZ[i-5];
        tD[58-i]=tZ[i-4];
        i-=6;
    } 
    for (i = 1; i < 10; i++)
    {
        for (j = 1; j < 7; j++)
        {
            DK[j][i]=tD[j+(i-1)*6];
        }
    }
}
