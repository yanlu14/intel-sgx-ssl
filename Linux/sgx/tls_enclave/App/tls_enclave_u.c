#include "tls_enclave_u.h"
#include <errno.h>

typedef struct ms_seal_key_t {
	size_t ms_retval;
	const char* ms_file_name;
	size_t ms_file_name_len;
	char* ms_password;
	size_t ms_pw_len;
	char* ms_enc_buf;
	size_t ms_enc_buf_len;
} ms_seal_key_t;

typedef struct ms_start_enclave_tls_t {
	int ms_retval;
	int ms_client_fd;
	const char* ms_cert;
	size_t ms_cert_len;
	const char* ms_enc_key;
	size_t ms_enc_key_len;
} ms_start_enclave_tls_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_ocall_cc_read_t {
	int ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_buf_len;
} ms_ocall_cc_read_t;

typedef struct ms_ocall_cc_write_t {
	int ms_retval;
	int ms_fd;
	const void* ms_buf;
	size_t ms_buf_len;
} ms_ocall_cc_write_t;

typedef struct ms_ocall_cc_getenv_t {
	int ms_retval;
	const char* ms_name;
	size_t ms_name_len;
	void* ms_buf;
	int ms_buf_len;
	int* ms_need_len;
} ms_ocall_cc_getenv_t;

typedef struct ms_ocall_cc_fopen_t {
	uint64_t ms_retval;
	const char* ms_filename;
	size_t ms_filename_len;
	const char* ms_mode;
	size_t ms_mode_len;
} ms_ocall_cc_fopen_t;

typedef struct ms_ocall_cc_fclose_t {
	int ms_retval;
	uint64_t ms_fp;
} ms_ocall_cc_fclose_t;

typedef struct ms_ocall_cc_ferror_t {
	int ms_retval;
	uint64_t ms_fp;
} ms_ocall_cc_ferror_t;

typedef struct ms_ocall_cc_feof_t {
	int ms_retval;
	uint64_t ms_fp;
} ms_ocall_cc_feof_t;

typedef struct ms_ocall_cc_fflush_t {
	int ms_retval;
	uint64_t ms_fp;
} ms_ocall_cc_fflush_t;

typedef struct ms_ocall_cc_ftell_t {
	long int ms_retval;
	uint64_t ms_fp;
} ms_ocall_cc_ftell_t;

typedef struct ms_ocall_cc_fseek_t {
	int ms_retval;
	uint64_t ms_fp;
	long int ms_offset;
	int ms_origin;
} ms_ocall_cc_fseek_t;

typedef struct ms_ocall_cc_fread_t {
	size_t ms_retval;
	void* ms_buf;
	size_t ms_total_size;
	size_t ms_element_size;
	size_t ms_cnt;
	uint64_t ms_fp;
} ms_ocall_cc_fread_t;

typedef struct ms_ocall_cc_fwrite_t {
	size_t ms_retval;
	const void* ms_buf;
	size_t ms_total_size;
	size_t ms_element_size;
	size_t ms_cnt;
	uint64_t ms_fp;
} ms_ocall_cc_fwrite_t;

typedef struct ms_ocall_cc_fgets_t {
	int ms_retval;
	char* ms_str;
	int ms_max_cnt;
	uint64_t ms_fp;
} ms_ocall_cc_fgets_t;

typedef struct ms_ocall_cc_fputs_t {
	int ms_retval;
	const char* ms_str;
	size_t ms_total_size;
	uint64_t ms_fp;
} ms_ocall_cc_fputs_t;

static sgx_status_t SGX_CDECL tls_enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_read(void* pms)
{
	ms_ocall_cc_read_t* ms = SGX_CAST(ms_ocall_cc_read_t*, pms);
	ms->ms_retval = ocall_cc_read(ms->ms_fd, ms->ms_buf, ms->ms_buf_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_write(void* pms)
{
	ms_ocall_cc_write_t* ms = SGX_CAST(ms_ocall_cc_write_t*, pms);
	ms->ms_retval = ocall_cc_write(ms->ms_fd, ms->ms_buf, ms->ms_buf_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_getenv(void* pms)
{
	ms_ocall_cc_getenv_t* ms = SGX_CAST(ms_ocall_cc_getenv_t*, pms);
	ms->ms_retval = ocall_cc_getenv(ms->ms_name, ms->ms_name_len, ms->ms_buf, ms->ms_buf_len, ms->ms_need_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_fopen(void* pms)
{
	ms_ocall_cc_fopen_t* ms = SGX_CAST(ms_ocall_cc_fopen_t*, pms);
	ms->ms_retval = ocall_cc_fopen(ms->ms_filename, ms->ms_filename_len, ms->ms_mode, ms->ms_mode_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_fclose(void* pms)
{
	ms_ocall_cc_fclose_t* ms = SGX_CAST(ms_ocall_cc_fclose_t*, pms);
	ms->ms_retval = ocall_cc_fclose(ms->ms_fp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_ferror(void* pms)
{
	ms_ocall_cc_ferror_t* ms = SGX_CAST(ms_ocall_cc_ferror_t*, pms);
	ms->ms_retval = ocall_cc_ferror(ms->ms_fp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_feof(void* pms)
{
	ms_ocall_cc_feof_t* ms = SGX_CAST(ms_ocall_cc_feof_t*, pms);
	ms->ms_retval = ocall_cc_feof(ms->ms_fp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_fflush(void* pms)
{
	ms_ocall_cc_fflush_t* ms = SGX_CAST(ms_ocall_cc_fflush_t*, pms);
	ms->ms_retval = ocall_cc_fflush(ms->ms_fp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_ftell(void* pms)
{
	ms_ocall_cc_ftell_t* ms = SGX_CAST(ms_ocall_cc_ftell_t*, pms);
	ms->ms_retval = ocall_cc_ftell(ms->ms_fp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_fseek(void* pms)
{
	ms_ocall_cc_fseek_t* ms = SGX_CAST(ms_ocall_cc_fseek_t*, pms);
	ms->ms_retval = ocall_cc_fseek(ms->ms_fp, ms->ms_offset, ms->ms_origin);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_fread(void* pms)
{
	ms_ocall_cc_fread_t* ms = SGX_CAST(ms_ocall_cc_fread_t*, pms);
	ms->ms_retval = ocall_cc_fread(ms->ms_buf, ms->ms_total_size, ms->ms_element_size, ms->ms_cnt, ms->ms_fp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_fwrite(void* pms)
{
	ms_ocall_cc_fwrite_t* ms = SGX_CAST(ms_ocall_cc_fwrite_t*, pms);
	ms->ms_retval = ocall_cc_fwrite(ms->ms_buf, ms->ms_total_size, ms->ms_element_size, ms->ms_cnt, ms->ms_fp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_fgets(void* pms)
{
	ms_ocall_cc_fgets_t* ms = SGX_CAST(ms_ocall_cc_fgets_t*, pms);
	ms->ms_retval = ocall_cc_fgets(ms->ms_str, ms->ms_max_cnt, ms->ms_fp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL tls_enclave_ocall_cc_fputs(void* pms)
{
	ms_ocall_cc_fputs_t* ms = SGX_CAST(ms_ocall_cc_fputs_t*, pms);
	ms->ms_retval = ocall_cc_fputs(ms->ms_str, ms->ms_total_size, ms->ms_fp);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[20];
} ocall_table_tls_enclave = {
	20,
	{
		(void*)tls_enclave_sgx_oc_cpuidex,
		(void*)tls_enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)tls_enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)tls_enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)tls_enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)tls_enclave_u_sgxssl_ftime,
		(void*)tls_enclave_ocall_cc_read,
		(void*)tls_enclave_ocall_cc_write,
		(void*)tls_enclave_ocall_cc_getenv,
		(void*)tls_enclave_ocall_cc_fopen,
		(void*)tls_enclave_ocall_cc_fclose,
		(void*)tls_enclave_ocall_cc_ferror,
		(void*)tls_enclave_ocall_cc_feof,
		(void*)tls_enclave_ocall_cc_fflush,
		(void*)tls_enclave_ocall_cc_ftell,
		(void*)tls_enclave_ocall_cc_fseek,
		(void*)tls_enclave_ocall_cc_fread,
		(void*)tls_enclave_ocall_cc_fwrite,
		(void*)tls_enclave_ocall_cc_fgets,
		(void*)tls_enclave_ocall_cc_fputs,
	}
};
sgx_status_t seal_key(sgx_enclave_id_t eid, size_t* retval, const char* file_name, size_t file_name_len, char* password, size_t pw_len, char* enc_buf, size_t enc_buf_len)
{
	sgx_status_t status;
	ms_seal_key_t ms;
	ms.ms_file_name = file_name;
	ms.ms_file_name_len = file_name_len;
	ms.ms_password = password;
	ms.ms_pw_len = pw_len;
	ms.ms_enc_buf = enc_buf;
	ms.ms_enc_buf_len = enc_buf_len;
	status = sgx_ecall(eid, 0, &ocall_table_tls_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t start_enclave_tls(sgx_enclave_id_t eid, int* retval, int client_fd, const char* cert, size_t cert_len, const char* enc_key, size_t enc_key_len)
{
	sgx_status_t status;
	ms_start_enclave_tls_t ms;
	ms.ms_client_fd = client_fd;
	ms.ms_cert = cert;
	ms.ms_cert_len = cert_len;
	ms.ms_enc_key = enc_key;
	ms.ms_enc_key_len = enc_key_len;
	status = sgx_ecall(eid, 1, &ocall_table_tls_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

