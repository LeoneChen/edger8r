#ifndef TEST_U_H__
#define TEST_U_H__

#include "sgx_edger8r.h" /* for sgx_status_t etc. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _my_union_t
#define _my_union_t
typedef union my_union_t {
  uint32_t *union_0;
  uint32_t **union_1;
  uint64_t union_3;
} my_union_t;
#endif

#ifndef _my_struct_t
#define _my_struct_t
typedef struct my_struct_t {
  uint64_t **buf;
  size_t size;
  my_union_t my_union;
} my_struct_t;
#endif

#ifndef OCALL1_DEFINED__
#define OCALL1_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall1, (char val));
#endif
#ifndef OCALL2_DEFINED__
#define OCALL2_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall2, (char *val));
#endif
#ifndef OCALL3_DEFINED__
#define OCALL3_DEFINED__
char *SGX_UBRIDGE(SGX_NOCONVENTION, ocall3, (char *val, size_t count));
#endif
#ifndef OCALL4_DEFINED__
#define OCALL4_DEFINED__
int **SGX_UBRIDGE(SGX_NOCONVENTION, ocall4,
                  (struct my_struct_t * val, size_t count));
#endif
#ifndef OCALL5_DEFINED__
#define OCALL5_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall5, (buffer_t buf, size_t len));
#endif
#ifndef OCALL6_DEFINED__
#define OCALL6_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall6, (int arr[4][5]));
#endif
#ifndef OCALL7_DEFINED__
#define OCALL7_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall7, (array_t arr));
#endif

sgx_status_t ecall1(sgx_enclave_id_t eid, char val);
sgx_status_t ecall2(sgx_enclave_id_t eid, char *val);
sgx_status_t ecall3(sgx_enclave_id_t eid, char **retval, char *val,
                    size_t count);
sgx_status_t ecall4(sgx_enclave_id_t eid, int ***retval,
                    struct my_struct_t *val, size_t count);
sgx_status_t ecall5(sgx_enclave_id_t eid, buffer_t buf, size_t len);
sgx_status_t ecall6(sgx_enclave_id_t eid, int arr[4][5]);
sgx_status_t ecall7(sgx_enclave_id_t eid, array_t arr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
