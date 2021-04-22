#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t enclaveOutNodeFunction(sgx_enclave_id_t eid, char* buf, size_t len);
sgx_status_t enclaveInOutMergeFunction(sgx_enclave_id_t eid, char* buf1, size_t len1, char* buf2, size_t len2, char* buf3, size_t len3);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
