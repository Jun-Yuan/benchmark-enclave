#include <stdio.h>
//#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
//#include "stdafx.h"
#include <stdio.h>
#include <time.h>
typedef char* NODE;


//Ocall
void ocall_print_string(const char * str) {
    printf("%s\n", str);
}
const long NODE_SIZE = 4*1024*10;
const long CACHE_SIZE = 64*1024*1024;
const long KV_SIZE= 4*1024;
const long SIGN_SIZE=2;
	
typedef unsigned char byte;
main() {
    sgx_enclave_id_t enclaveId;
    sgx_status_t ret = SGX_SUCCESS;
    int updated, i=0;
    long  num_nodes = 2 * (CACHE_SIZE/NODE_SIZE+1);
    long num_kvs_per_node = (NODE_SIZE)/(KV_SIZE)+1;

    NODE * buffer = (NODE *) malloc(sizeof(NODE)*num_nodes);

    if (initialize_enclave(&enclaveId, "enclave.token", "enclave.signed.so") < 0) {
        perror("Fail to initialize enclave.");
        return 1;
    }

    for(long i=0; i<num_nodes; i++) {
        buffer[i] = (NODE) malloc (sizeof(char) * (NODE_SIZE + SIGN_SIZE)); 
//        printf("node %ld initialized and signed by enclave\n", i);
        enclaveOutNodeFunction(enclaveId, buffer[i], NODE_SIZE + SIGN_SIZE);
    
    }
    //testing code
    //verifying received node:
    #if 0
    for(long i=0; i<num_nodes; i++) {
        for(long stride=0; stride < NODE_SIZE; stride+=KV_SIZE) {
            byte kv[KV_SIZE];
            int key;
            memcpy(kv, buffer[i]+stride, KV_SIZE);
            memcpy(&key, kv, 4);
            printf("key: %d\n", key);
            
        }
        unsigned short checksum;
        memcpy(&checksum, buffer[i]+NODE_SIZE, 2);
        printf("checksum=%4X\n", checksum);
    }
    #endif
    //cache is 64M, so all the first half batch of nodes were totally swapped out
    //bring node[0] and node[1] in for a merge

    printf("node 0 and node 1 are to be merged\n");
    NODE merged_node = (NODE) malloc (sizeof(char) * (NODE_SIZE * 2 + SIGN_SIZE));
    clock_t t;
    t = clock();
    enclaveInOutMergeFunction(enclaveId, buffer[0], NODE_SIZE+SIGN_SIZE,
                                buffer[1], NODE_SIZE+SIGN_SIZE,
                                merged_node, 2*NODE_SIZE+SIGN_SIZE); 
    t = clock() - t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in second
    printf("merge took %f seconds to execute \n", time_taken);
    //verify the merge succeeded
    #if 0
        for(long stride=0; stride < 2*NODE_SIZE; stride+=KV_SIZE) {
            byte kv[KV_SIZE];
            int key;
            memcpy(kv, merged_node+stride, KV_SIZE);
            memcpy(&key, kv, 4);
            printf("key of merged: %d\n", key);
            
        }
        unsigned short checksum;
        memcpy(&checksum, merged_node+2*NODE_SIZE, 2);
        printf("checksum of merged=%4X\n", checksum);
    #endif
    
    free(buffer);
    free(merged_node);
    if(sgx_destroy_enclave(enclaveId) != SGX_SUCCESS)
    {
        printf("Error %x: cant destroy enclave\n", ret);
        return -1;
    }
    else printf("DONE\n");
    getchar();
    return 0;
}


