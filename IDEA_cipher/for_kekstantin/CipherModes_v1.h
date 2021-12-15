#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h> 
#include <time.h>
#include <stdbool.h>

typedef unsigned __int128 uint128_t;

#define ROL32(a,n) (((a) << (n)) | ((a) >> (32 - (n))))

void Cipher_IDEA_Mode_CTR(bool modeselect, uint128_t key, uint64_t initialvector, uint64_t numtexts, uint64_t *intexts, uint64_t *outtexts);

uint64_t Cipher_IDEA_encryptdecrypt(uint64_t plaintext, uint16_t *K, uint16_t offset);
void Key_Generator(uint128_t IDEAkey, uint16_t *encrypt, uint16_t *decrypt);
static uint16_t ideaMul(uint16_t a, uint16_t b);
static uint16_t ideaInv(uint16_t a);


void Cipher_IDEA_Mode_CTR(bool modeselect, uint128_t key, uint64_t initialvector, uint64_t numtexts, uint64_t *intexts, uint64_t *outtexts) {
	uint64_t i;
	uint16_t *key_encrypt, *key_decrypt;
	
	// allocate memory for round keys and generate round keys
	key_encrypt = (uint16_t*) malloc(sizeof(uint16_t) * 54);
	key_decrypt = (uint16_t*) malloc(sizeof(uint16_t) * 54);
	Key_Generator(key, key_encrypt, key_decrypt);

	// perform CFB encryption/decryption
	for(i = 0; i < numtexts; i++) {
		outtexts[i] = intexts[i] ^ Cipher_IDEA_encryptdecrypt(initialvector ^ i, key_encrypt, 0);
	}
}

uint64_t Cipher_IDEA_encryptdecrypt(uint64_t plaintext, uint16_t *K, uint16_t offset) {

    uint16_t a=(plaintext & 0xFFFF000000000000) >> 48, b=(plaintext & 0x0000FFFF00000000) >> 32,
             c=(plaintext & 0x00000000FFFF0000) >> 16, d=(plaintext & 0x000000000000FFFF) >> 0;
    uint64_t ciphertext;
    uint16_t e = 0, f = 0;
    uint16_t i;
    uint16_t *k;

    k = K+offset;
    uint16_t rounds = 8;

    for(i = 0; i < rounds; i++)
    {
        a = ideaMul(a, k[0]); 
        b += k[1]; 
        c += k[2]; 
        d = ideaMul(d, k[3]); 

        //printf("          a: %.4x, b: %.4x, c: %.4x, d: %.4x\n", a,b,c,d); 
        e = a ^ b; 
        f = c ^ d; 
        //printf("          e: %.4x, f: %.4x\n", e, f); 
        //e = ideaMul(e, k[4]); // to call this the new value of e or to say f += ideaMul(k[4], e);?
        e = ideaMul(e, 46457);
        f += e;
        //f = ideaMul(f,k[5]);
        f = ideaMul(f,46457);
        e += f;

        //printf("          e: %.4x, f: %.4x\n", e, f);

        a ^= f;
        d ^= e;

        b = f^b; 
        c = e^c; 
        if(i < rounds-1) { 
            uint16_t temp = c; 
            c = b; 
            b = temp; 
        }
        //printf("          a: %.4x, b: %.4x, c: %.4x, d: %.4x\n", a,b,c,d); 
        k += 6;


    }

    a = ideaMul(a, k[0]);
    c += k[1]; 
    b += k[2]; 
    d = ideaMul(d, k[3]);

    //printf("encode %d: a: %.4x, b: %.4x, c: %.4x, d: %.4x\n", 8,a,b,c,d);

    ciphertext = 0;
    ciphertext = (ciphertext | a) << 16;
    ciphertext = (ciphertext | b) << 16;
    ciphertext = (ciphertext | c) << 16;
    ciphertext = (ciphertext | d) << 0;

    return (ciphertext);  
}

void Key_Generator(uint128_t IDEAkey, uint16_t *encrypt, uint16_t *decrypt) {
    int i=0;
    // Generate encryption keys 1-48
    while(i < 52) {
        encrypt[i] = (IDEAkey >> 112); 
        encrypt[i+1] = (IDEAkey >> 80); 
        encrypt[i+2] = (IDEAkey >> 96); 
        encrypt[i+3] = (IDEAkey >> 64); 
        encrypt[i+4] = (IDEAkey >> 48); 
        encrypt[i+5] = (IDEAkey >> 32);
        encrypt[i+6] = (IDEAkey >> 16);
        encrypt[i+7] = (IDEAkey >> 0);   
        i += 8;
        IDEAkey = (IDEAkey << 25) | (IDEAkey >> (sizeof(IDEAkey)*8 - 25));
    }

    // keys 49-52
    encrypt[i] = (IDEAkey >> 112); //K49
    encrypt[i+1] = (IDEAkey >> 80); //K51
    encrypt[i+2] = (IDEAkey >> 96); //K50
    encrypt[i+3] = (IDEAkey >> 64); //K52

    //encrypt = encrypt - 52;
    for(i = 0; i < 52; i+=6) {
        decrypt[i] = ideaInv(encrypt[48-i]);

        if(i == 0 || i == 48) { // flip because first and last 4 keys
            decrypt[i + 1] = -encrypt[49 - i];
            decrypt[i + 2] = -encrypt[50 - i];
        } else { // otherwise don't flip
            decrypt[i + 1] = -encrypt[50 - i];
            decrypt[i + 2] = -encrypt[49 - i];
        }

        decrypt[i + 3] = ideaInv(encrypt[51 - i]);

        if(i < 48) {
            decrypt[i + 4] = encrypt[46 - i];
            decrypt[i + 5] = encrypt[47 - i];
        }
    }
}

static uint16_t ideaMul(uint16_t a, uint16_t b) {
    uint32_t c = a * b;
    if(c) {
        c = (ROL32(c,16) - c) >> 16;
        return (c + 1) & 0xFFFF;
    } else {
        return (1 - a - b) & 0xFFFF;
    }
}

static uint16_t ideaInv(uint16_t a) {
    uint32_t b;
    uint32_t q;
    uint32_t r;
    int32_t t;
    int32_t u;
    int32_t v;
    b = 0x10001;
    u = 0;
    v = 1;
    while(a > 0) {
        q = b / a;
        r = b % a;
        b = a;
        a = r;
        t = v;
        v = u - q * v;
        u = t;
    }
    if(u < 0) {
        u += 0x10001;
    }
    return u;
}
