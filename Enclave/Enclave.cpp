#include "Enclave_t.h"
#include "sgx_trts.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
//hard code for now, disgusting
const long NODE_SIZE = 4*1024*10;
const long CACHE_SIZE = 64*1024*1024;
const long KV_SIZE= 4*1024;
const long SIGN_SIZE=2;
	
typedef char* NODE;

#define BEFORE_MERGE_SIZE NODE_SIZE+SIGN_SIZE
#define AFTER_MERGE_SIZE 2*NODE_SIZE+SIGN_SIZE

typedef unsigned char byte;
typedef unsigned short word16;
typedef unsigned int word32;
//char enclaveString[MAX_BUF_LEN] = "Internal enclave string is not initialized";

//prepare to print

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

byte enclaveNodeBeforeMerge[BEFORE_MERGE_SIZE]; 
byte enclaveNodeAfterMerge[AFTER_MERGE_SIZE]; 
unsigned int global_count = 0;
static void generate_key (byte * key, unsigned int count) {
    for(int i=0; i<16; i++)
        key[i] = 0;
    //oh man forgo little endian
    memcpy(key, &count, sizeof(unsigned int)) ;
}

static void generate_val(byte * val) {
    for(int stride=0; stride<KV_SIZE; ) {
        sgx_read_rand((unsigned char *) val+stride, 4); 
        stride += 4;
    }
}

static word16 checksum(byte *addr, long count)
{
  register word32 sum = 0;

  // Main summing loop
  while(count > 1)
  {
    sum = sum + *((word16 *) addr);
    addr += 2;
    count = count - 2;
  }

  // Add left-over byte, if any
  if (count > 0)
    sum = sum + *((byte *) addr);

  // Fold 32-bit sum to 16 bits
  while (sum>>16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return(~sum);
}

static void verify_checksum(byte * addr) {
    word16 check = checksum(addr, NODE_SIZE+SIGN_SIZE);

    //printf("check =%4X\n", check); 
    assert(check == 0 || check == 1); 
}


void enclaveOutNodeFunction(char * buffer, size_t len) {
    byte kv[KV_SIZE];
    for(int stride=0; stride < NODE_SIZE; stride+=KV_SIZE) {
        global_count ++;
        generate_val(kv);
        generate_key(kv, global_count);
        // Compute the 16-bit checksum
        memcpy(enclaveNodeBeforeMerge+stride, kv, KV_SIZE);
    }    
    word16 check = checksum(enclaveNodeBeforeMerge, NODE_SIZE);
    memcpy(enclaveNodeBeforeMerge+NODE_SIZE, &check, SIGN_SIZE);
    //printf("checksum = %02X \n", check);       
    memcpy(buffer, enclaveNodeBeforeMerge, NODE_SIZE+SIGN_SIZE);      
   

}
void enclaveInOutMergeFunction( char * buffer1, size_t len1, 
                                char * buffer2, size_t len2,
                                char * buffer3, size_t len3) {

    assert(len1 == NODE_SIZE + SIGN_SIZE);
    assert(len2 == len1);
    verify_checksum((byte *) buffer1);
    verify_checksum((byte *)buffer2);

    long stride1, stride2, stride3;
    for(stride1=0, stride2=0, stride3=0; stride1<NODE_SIZE && stride2<NODE_SIZE; ){
        int k1;
        int k2;
        memcpy(&k1, buffer1+stride1, 4);
        memcpy(&k2, buffer2+stride2, 4);
        if(k1 < k2) {
            memcpy(enclaveNodeAfterMerge+stride3, buffer1+stride1, KV_SIZE);
            stride1 += KV_SIZE; 
            stride3 += KV_SIZE;
        } else {
            memcpy(enclaveNodeAfterMerge+stride3, buffer2+stride2, KV_SIZE);
            stride2 += KV_SIZE; 
            stride3 += KV_SIZE; 
        }
    }
    if(stride1 < NODE_SIZE) {
    
        memcpy(enclaveNodeAfterMerge+stride3, buffer1+stride1, NODE_SIZE-stride1);
        stride3 += NODE_SIZE-stride1;
    } else if (stride2 < NODE_SIZE){
        
        memcpy(enclaveNodeAfterMerge+stride3, buffer2+stride2, NODE_SIZE-stride2);
        stride3 += NODE_SIZE-stride2;
    }   
    assert (stride3 == 2*NODE_SIZE); 
    word16 check = checksum(enclaveNodeAfterMerge, 2*NODE_SIZE);
    memcpy(enclaveNodeAfterMerge+2*NODE_SIZE, &check, SIGN_SIZE);
    //printf("checksum after merge = %04X \n", check);     
    assert(len3 == 2*NODE_SIZE+SIGN_SIZE);  
    memcpy(buffer3, enclaveNodeAfterMerge, 2*NODE_SIZE+SIGN_SIZE);      
 
}


