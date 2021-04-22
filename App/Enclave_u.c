#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_enclaveOutNodeFunction_t {
	char* ms_buf;
	size_t ms_len;
} ms_enclaveOutNodeFunction_t;

typedef struct ms_enclaveInOutMergeFunction_t {
	char* ms_buf1;
	size_t ms_len1;
	char* ms_buf2;
	size_t ms_len2;
	char* ms_buf3;
	size_t ms_len3;
} ms_enclaveInOutMergeFunction_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print_string,
	}
};
sgx_status_t enclaveOutNodeFunction(sgx_enclave_id_t eid, char* buf, size_t len)
{
	sgx_status_t status;
	ms_enclaveOutNodeFunction_t ms;
	ms.ms_buf = buf;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t enclaveInOutMergeFunction(sgx_enclave_id_t eid, char* buf1, size_t len1, char* buf2, size_t len2, char* buf3, size_t len3)
{
	sgx_status_t status;
	ms_enclaveInOutMergeFunction_t ms;
	ms.ms_buf1 = buf1;
	ms.ms_len1 = len1;
	ms.ms_buf2 = buf2;
	ms.ms_len2 = len2;
	ms.ms_buf3 = buf3;
	ms.ms_len3 = len3;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

