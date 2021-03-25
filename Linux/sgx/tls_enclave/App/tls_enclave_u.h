#ifndef TLS_ENCLAVE_U_H__
#define TLS_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "stdbool.h"
#include "sgx_urts.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef U_SGXSSL_FTIME_DEFINED__
#define U_SGXSSL_FTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
#endif
#ifndef OCALL_CC_READ_DEFINED__
#define OCALL_CC_READ_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_read, (int fd, void* buf, size_t buf_len));
#endif
#ifndef OCALL_CC_WRITE_DEFINED__
#define OCALL_CC_WRITE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_write, (int fd, const void* buf, size_t buf_len));
#endif
#ifndef OCALL_CC_GETENV_DEFINED__
#define OCALL_CC_GETENV_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_getenv, (const char* name, size_t name_len, void* buf, int buf_len, int* need_len));
#endif
#ifndef OCALL_CC_FOPEN_DEFINED__
#define OCALL_CC_FOPEN_DEFINED__
uint64_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_fopen, (const char* filename, size_t filename_len, const char* mode, size_t mode_len));
#endif
#ifndef OCALL_CC_FCLOSE_DEFINED__
#define OCALL_CC_FCLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_fclose, (uint64_t fp));
#endif
#ifndef OCALL_CC_FERROR_DEFINED__
#define OCALL_CC_FERROR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_ferror, (uint64_t fp));
#endif
#ifndef OCALL_CC_FEOF_DEFINED__
#define OCALL_CC_FEOF_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_feof, (uint64_t fp));
#endif
#ifndef OCALL_CC_FFLUSH_DEFINED__
#define OCALL_CC_FFLUSH_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_fflush, (uint64_t fp));
#endif
#ifndef OCALL_CC_FTELL_DEFINED__
#define OCALL_CC_FTELL_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_ftell, (uint64_t fp));
#endif
#ifndef OCALL_CC_FSEEK_DEFINED__
#define OCALL_CC_FSEEK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_fseek, (uint64_t fp, long int offset, int origin));
#endif
#ifndef OCALL_CC_FREAD_DEFINED__
#define OCALL_CC_FREAD_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_fread, (void* buf, size_t total_size, size_t element_size, size_t cnt, uint64_t fp));
#endif
#ifndef OCALL_CC_FWRITE_DEFINED__
#define OCALL_CC_FWRITE_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_fwrite, (const void* buf, size_t total_size, size_t element_size, size_t cnt, uint64_t fp));
#endif
#ifndef OCALL_CC_FGETS_DEFINED__
#define OCALL_CC_FGETS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_fgets, (char* str, int max_cnt, uint64_t fp));
#endif
#ifndef OCALL_CC_FPUTS_DEFINED__
#define OCALL_CC_FPUTS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_cc_fputs, (const char* str, size_t total_size, uint64_t fp));
#endif

sgx_status_t seal_key(sgx_enclave_id_t eid, size_t* retval, const char* file_name, size_t file_name_len, char* password, size_t pw_len, char* enc_buf, size_t enc_buf_len);
sgx_status_t start_enclave_tls(sgx_enclave_id_t eid, int* retval, int client_fd, const char* cert, size_t cert_len, const char* enc_key, size_t enc_key_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
