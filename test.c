//#include"aes.h"
#include <stdlib.h> 
#include <time.h>   
#include<stdio.h>

#define KEYSIZE 32
#define IVSIZE 16

void generatekey(BYTE* key){
    for(int i=0; i<KEYSIZE; ++i){
        key[i]=(BYTE)rand()%256;                       //better use OpenSSL or Windows CryptoAPI
    }
}

void generateIL(BYTE* il){
    for(int i=0; i<IVSIZE; ++i){
        il[i]=(BYTE)rand()%256;
    }
}
void addPadding(unsigned char* data, size_t *dataSize){
    unsigned char paddingValue= 16 -(*dataSize % 16);
    for (size_t i=*dataSize; i<*dataSize +paddingValue;++i){
        data[i]=paddingValue;
    }
    *dataSize += paddingValue;
 
}
void xorEncrypt(PBYTE payload, size_t payload_len, PBYTE key, size_t key_len) {
    for (size_t i = 0; i < payload_len; ++i) {
        payload[i] ^= key[i % key_len];  
    }    
}

int main(){

    unsigned char key[]={'m','q','e','t','i','d','s','x','a','r','t','d','s','p'};   
    
    unsigned char shellcode[]="your shellcode";
    

   // struct AES_ctx ctx;   
    addPadding(shellcode, sizeof(shellcode));
    printf("Starting encryption ...\n");

BYTE pKey[KEYSIZE]; 
BYTE pIl[IVSIZE];  


srand(time(NULL) ^ getpid()); 
generatekey(pKey);

srand(rand() ^ time(NULL)); 
generatekey(pIl);


srand(rand() ^ pKey[0]); 
generatekey(pKey);


printf("Generated key:");
for (int i = 0; i < KEYSIZE; ++i) {
    printf("\\x%02x", pKey[i]); 
}
printf("\n");

printf("Generated IV:");
for (int i = 0; i < IVSIZE; ++i) {
    printf("\\x%02x", pIl[i]);
}
printf("\n");
// XOR encryption 
    printf("XORing...\n");
    xorEncrypt(shellcode, sizeof(shellcode),key,sizeof(key));
    printf("Encrypted shellcode: \n");
    for(int i=0;i<sizeof(shellcode);++i){
        printf("\\x%02x",shellcode[i]);
    }

    printf("Encrypted shellcode size %i", sizeof(shellcode));
    printf("______________________________________________\n");

    return 0;
  

}
