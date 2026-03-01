#include "test_u.h"
#include <errno.h>

typedef struct ms_ecall1_t {
  char ms_val;
} ms_ecall1_t;

typedef struct ms_ecall2_t {
  char *ms_val;
} ms_ecall2_t;

typedef struct ms_ecall3_t {
  char *ms_retval;
  char *ms_val;
  size_t ms_count;
} ms_ecall3_t;

typedef struct ms_ecall4_t {
  int **ms_retval;
  struct my_struct_t *ms_val;
  size_t ms_count;
} ms_ecall4_t;

typedef struct ms_ecall5_t {
  buffer_t ms_buf;
  size_t ms_len;
} ms_ecall5_t;

typedef struct ms_ecall6_t {
  int *ms_arr;
} ms_ecall6_t;

typedef struct ms_ecall7_t {
  array_t *ms_arr;
} ms_ecall7_t;

typedef struct ms_ocall1_t {
  char ms_val;
} ms_ocall1_t;

typedef struct ms_ocall2_t {
  char *ms_val;
} ms_ocall2_t;

typedef struct ms_ocall3_t {
  char *ms_retval;
  char *ms_val;
  size_t ms_count;
} ms_ocall3_t;

typedef struct ms_ocall4_t {
  int **ms_retval;
  struct my_struct_t *ms_val;
  size_t ms_count;
} ms_ocall4_t;

typedef struct ms_ocall5_t {
  buffer_t ms_buf;
  size_t ms_len;
} ms_ocall5_t;

typedef struct ms_ocall6_t {
  int *ms_arr;
} ms_ocall6_t;

typedef struct ms_ocall7_t {
  array_t *ms_arr;
} ms_ocall7_t;

extern void _harness_ocall1(char val) __attribute__((weak));
static sgx_status_t SGX_CDECL test_ocall1(void *pms) {
  ms_ocall1_t *ms = SGX_CAST(ms_ocall1_t *, pms);
  (_harness_ocall1 ? _harness_ocall1(ms->ms_val) : ocall1(ms->ms_val));

  return SGX_SUCCESS;
}

extern void _harness_ocall2(char *val) __attribute__((weak));
static sgx_status_t SGX_CDECL test_ocall2(void *pms) {
  ms_ocall2_t *ms = SGX_CAST(ms_ocall2_t *, pms);
  (_harness_ocall2 ? _harness_ocall2(ms->ms_val) : ocall2(ms->ms_val));

  return SGX_SUCCESS;
}

extern char *_harness_ocall3(char *val, size_t count) __attribute__((weak));
static sgx_status_t SGX_CDECL test_ocall3(void *pms) {
  ms_ocall3_t *ms = SGX_CAST(ms_ocall3_t *, pms);
  ms->ms_retval = (_harness_ocall3 ? _harness_ocall3(ms->ms_val, ms->ms_count)
                                   : ocall3(ms->ms_val, ms->ms_count));

  return SGX_SUCCESS;
}

extern int **_harness_ocall4(struct my_struct_t *val, size_t count)
    __attribute__((weak));
static sgx_status_t SGX_CDECL test_ocall4(void *pms) {
  ms_ocall4_t *ms = SGX_CAST(ms_ocall4_t *, pms);
  ms->ms_retval = (_harness_ocall4 ? _harness_ocall4(ms->ms_val, ms->ms_count)
                                   : ocall4(ms->ms_val, ms->ms_count));

  return SGX_SUCCESS;
}

extern void _harness_ocall5(buffer_t buf, size_t len) __attribute__((weak));
static sgx_status_t SGX_CDECL test_ocall5(void *pms) {
  ms_ocall5_t *ms = SGX_CAST(ms_ocall5_t *, pms);
  (_harness_ocall5 ? _harness_ocall5(ms->ms_buf, ms->ms_len)
                   : ocall5(ms->ms_buf, ms->ms_len));

  return SGX_SUCCESS;
}

extern void _harness_ocall6(int arr[4][5]) __attribute__((weak));
static sgx_status_t SGX_CDECL test_ocall6(void *pms) {
  ms_ocall6_t *ms = SGX_CAST(ms_ocall6_t *, pms);
  (_harness_ocall6 ? _harness_ocall6((int (*)[5])ms->ms_arr)
                   : ocall6((int (*)[5])ms->ms_arr));

  return SGX_SUCCESS;
}

extern void _harness_ocall7(array_t arr) __attribute__((weak));
static sgx_status_t SGX_CDECL test_ocall7(void *pms) {
  ms_ocall7_t *ms = SGX_CAST(ms_ocall7_t *, pms);
  (_harness_ocall7
       ? _harness_ocall7((ms->ms_arr != NULL) ? (*ms->ms_arr) : NULL)
       : ocall7((ms->ms_arr != NULL) ? (*ms->ms_arr) : NULL));

  return SGX_SUCCESS;
}

static const struct {
  size_t nr_ocall;
  void *table[7];
} ocall_table_test = {7,
                      {
                          (void *)test_ocall1,
                          (void *)test_ocall2,
                          (void *)test_ocall3,
                          (void *)test_ocall4,
                          (void *)test_ocall5,
                          (void *)test_ocall6,
                          (void *)test_ocall7,
                      }};

sgx_status_t ecall1(sgx_enclave_id_t eid, char val) {
  sgx_status_t status;
  ms_ecall1_t ms;
  ms.ms_val = val;
  status = sgx_ecall(eid, 0, &ocall_table_test, &ms);
  return status;
}

sgx_status_t ecall2(sgx_enclave_id_t eid, char *val) {
  sgx_status_t status;
  ms_ecall2_t ms;
  ms.ms_val = val;
  status = sgx_ecall(eid, 1, &ocall_table_test, &ms);
  return status;
}

sgx_status_t ecall3(sgx_enclave_id_t eid, char **retval, char *val,
                    size_t count) {
  sgx_status_t status;
  ms_ecall3_t ms;
  ms.ms_val = val;
  ms.ms_count = count;
  status = sgx_ecall(eid, 2, &ocall_table_test, &ms);
  if (status == SGX_SUCCESS && retval)
    *retval = ms.ms_retval;
  return status;
}

sgx_status_t ecall4(sgx_enclave_id_t eid, int ***retval,
                    struct my_struct_t *val, size_t count) {
  sgx_status_t status;
  ms_ecall4_t ms;
  ms.ms_val = val;
  ms.ms_count = count;
  status = sgx_ecall(eid, 3, &ocall_table_test, &ms);
  if (status == SGX_SUCCESS && retval)
    *retval = ms.ms_retval;
  return status;
}

sgx_status_t ecall5(sgx_enclave_id_t eid, buffer_t buf, size_t len) {
  sgx_status_t status;
  ms_ecall5_t ms;
  ms.ms_buf = buf;
  ms.ms_len = len;
  status = sgx_ecall(eid, 4, &ocall_table_test, &ms);
  return status;
}

sgx_status_t ecall6(sgx_enclave_id_t eid, int arr[4][5]) {
  sgx_status_t status;
  ms_ecall6_t ms;
  ms.ms_arr = (int *)arr;
  status = sgx_ecall(eid, 5, &ocall_table_test, &ms);
  return status;
}

sgx_status_t ecall7(sgx_enclave_id_t eid, array_t arr) {
  sgx_status_t status;
  ms_ecall7_t ms;
  ms.ms_arr = (array_t *)&arr[0];
  status = sgx_ecall(eid, 6, &ocall_table_test, &ms);
  return status;
}
