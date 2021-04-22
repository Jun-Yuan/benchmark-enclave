#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_enclaveOutNodeFunction(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclaveOutNodeFunction_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclaveOutNodeFunction_t* ms = SGX_CAST(ms_enclaveOutNodeFunction_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	char* _in_buf = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ( _len_buf % sizeof(*_tmp_buf) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_buf = (char*)malloc(_len_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_buf, 0, _len_buf);
	}

	enclaveOutNodeFunction(_in_buf, _tmp_len);
	if (_in_buf) {
		if (memcpy_s(_tmp_buf, _len_buf, _in_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_buf) free(_in_buf);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclaveInOutMergeFunction(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclaveInOutMergeFunction_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclaveInOutMergeFunction_t* ms = SGX_CAST(ms_enclaveInOutMergeFunction_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf1 = ms->ms_buf1;
	size_t _tmp_len1 = ms->ms_len1;
	size_t _len_buf1 = _tmp_len1;
	char* _in_buf1 = NULL;
	char* _tmp_buf2 = ms->ms_buf2;
	size_t _tmp_len2 = ms->ms_len2;
	size_t _len_buf2 = _tmp_len2;
	char* _in_buf2 = NULL;
	char* _tmp_buf3 = ms->ms_buf3;
	size_t _tmp_len3 = ms->ms_len3;
	size_t _len_buf3 = _tmp_len3;
	char* _in_buf3 = NULL;

	CHECK_UNIQUE_POINTER(_tmp_buf1, _len_buf1);
	CHECK_UNIQUE_POINTER(_tmp_buf2, _len_buf2);
	CHECK_UNIQUE_POINTER(_tmp_buf3, _len_buf3);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf1 != NULL && _len_buf1 != 0) {
		if ( _len_buf1 % sizeof(*_tmp_buf1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf1 = (char*)malloc(_len_buf1);
		if (_in_buf1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf1, _len_buf1, _tmp_buf1, _len_buf1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_buf2 != NULL && _len_buf2 != 0) {
		if ( _len_buf2 % sizeof(*_tmp_buf2) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_buf2 = (char*)malloc(_len_buf2);
		if (_in_buf2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_buf2, _len_buf2, _tmp_buf2, _len_buf2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_buf3 != NULL && _len_buf3 != 0) {
		if ( _len_buf3 % sizeof(*_tmp_buf3) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_buf3 = (char*)malloc(_len_buf3)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_buf3, 0, _len_buf3);
	}

	enclaveInOutMergeFunction(_in_buf1, _tmp_len1, _in_buf2, _tmp_len2, _in_buf3, _tmp_len3);
	if (_in_buf3) {
		if (memcpy_s(_tmp_buf3, _len_buf3, _in_buf3, _len_buf3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_buf1) free(_in_buf1);
	if (_in_buf2) free(_in_buf2);
	if (_in_buf3) free(_in_buf3);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[2];
} g_ecall_table = {
	2,
	{
		{(void*)(uintptr_t)sgx_enclaveOutNodeFunction, 0, 0},
		{(void*)(uintptr_t)sgx_enclaveInOutMergeFunction, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][2];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

