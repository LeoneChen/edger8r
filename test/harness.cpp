/*
 * EnclaveFuzz - SGX Enclave Fuzzing Test Harness (Auto-Generated)
 *
 * Generated from EDL: test.edl
 *
 * ============================================================================
 * Fuzzing Framework Architecture
 * ============================================================================
 *
 * Initialization (once):
 *     LibFuzzer → LLVMFuzzerInitialize()
 *                  ↓
 *                 customized_init()  ← Register harnesses, calculate weights
 *
 * Fuzzing loop (per input):
 *     LibFuzzer → LLVMFuzzerTestOneInput(data, size)
 *                  ↓ Reinitialize g_fdp with new input
 *                  ↓ Recreate enclave (__g_harness_eid)
 *                  ↓
 *                 customized_harness()  ← Weighted selection
 *                  ↓
 *                 _harness_xxx()   ← Auto-generated test functions
 *                  ↓
 *                 ECall → Enclave Code
 *
 * ============================================================================
 * EDL Attribute Reference
 * ============================================================================
 *
 * | Attribute    | Meaning             | Fuzzing Strategy (ECall)         |
 * |--------------|---------------------|----------------------------------|
 * | [in]         | Input to callee     | Generate fuzzy data (Host→Encl)  |
 * | [out]        | Output from callee  | Allocate buffer (Encl→Host)      |
 * | [in,out]     | Bidirectional       | Generate input + allocate        |
 * | [size=N]     | Buffer size (bytes) | Use N for allocation             |
 * | [count=N]    | Array element count | Use N * sizeof(element)          |
 * | [string]     | Null-terminated str | Ensure null terminator           |
 * | [user_check] | No auto checking    | High fuzz value                  |
 *
 * CRITICAL: Direction Semantics ([in]/[out] relative to callee)
 * - For ECalls (Enclave is callee):
 *   [in] = Host→Enclave → FUZZ THIS in harness
 *   [out] = Enclave→Host → Allocate buffer only
 * - For OCalls (Host is callee):
 *   [in] = Enclave→Host → No fuzzing needed
 *   [out] = Host→Enclave → FUZZ THIS in OCall wrapper
 *
 * ============================================================================
 * Memory Management (Two Approaches)
 * ============================================================================
 * Approach 1 (Auto-Managed by g_alloc_mgr) - CURRENT DEFAULT:
 * - Use calloc() + g_alloc_mgr.push_back() to track allocations
 * - Framework in LLVMFuzzerTestOneInput (at test.cpp) automatically frees all
 * tracked memory after each iteration
 * - No explicit free() needed in harness functions
 * - Pros: Simple, no memory leaks, centralized cleanup
 * - Cons: Memory accumulates until end of iteration
 *
 * Approach 2 (Explicit free()):
 * - Use calloc() without g_alloc_mgr tracking
 * - Manually write free() calls at appropriate locations in harness code
 * - Pros: Immediate memory release, lower memory footprint
 * - Cons: Must ensure all allocations are freed, risk of memory leaks
 *
 * Usage: Choose approach based on your needs:
 * - Default: g_alloc_mgr for safety and simplicity
 * - Manual: Direct free() for memory-sensitive scenarios
 *
 * ============================================================================
 * Weighted Selection System
 * ============================================================================
 * Each harness has a weight (default: 10). Adjust weights in customized_init():
 * - High weight (e.g., 50-100) for critical/bottleneck paths
 * - Low weight (e.g., 1-5) for well-covered paths
 * - Modify test_harness_registry[i].weight before calculating total_weight
 *
 * ============================================================================
 */

#include "FuzzedDataProvider.h"
#include "test_u.h"
#include <errno.h>
#include <sgx_urts.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

template <typename T> constexpr size_t safe_sizeof() {
  return sizeof(
      typename std::conditional<std::is_void<T>::value, char, T>::type);
}

// ============================================================================
// Global Variables
// ============================================================================

extern FuzzedDataProvider *g_fdp;
extern std::vector<uint8_t *> g_alloc_mgr;
extern sgx_enclave_id_t __g_harness_eid;

// Fuzzing configuration parameters
static size_t g_max_strlen = 128; // Max string length for [string] attributes
static size_t g_max_cnt = 32;     // Max count for unbounded arrays
static size_t g_max_size = 512;   // Max size for unbounded buffers

// ============================================================================
// Test Harness Registration System
// ============================================================================

typedef void (*TestHarness)(void);

struct TestHarnessEntry {
  TestHarness function;
  int weight; // Selection weight (default: 10)
};

static TestHarnessEntry test_harness_registry[10240];
static unsigned int test_harness_count = 0;
static int total_weight = 0;

// ============================================================================
// OCall Wrappers
// ============================================================================
// These wrappers intercept OCalls and fuzz [out] parameters
// to test Enclave's resilience to untrusted data
// ============================================================================

extern "C" void _harness_ocall1(char val) { ocall1(val); }

extern "C" void _harness_ocall2(char *val) {
  ocall2(val);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_val = g_fdp->ConsumeIntegralInRange<size_t>(
        sizeof(char) < 8 ? (20 / sizeof(char)) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)val, count_0_val * sizeof(char));
  }
}

extern "C" char *_harness_ocall3(char *val, size_t count) {
  char *_fuzz_ret = ocall3(val, count);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_val = ((count) * (sizeof(char))) / sizeof(char);
    g_fdp->ConsumeData((void *)val, count_0_val * sizeof(char));
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0__fuzz_ret = g_fdp->ConsumeIntegralInRange<size_t>(
        sizeof(char) < 8 ? (20 / sizeof(char)) : 1, g_max_cnt);
    g_fdp->ConsumeData((void *)_fuzz_ret, count_0__fuzz_ret * sizeof(char));
  }
  return _fuzz_ret;
}

extern "C" int **_harness_ocall4(struct my_struct_t *val, size_t count) {
  int **_fuzz_ret = ocall4(val, count);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_val =
        ((count) * (sizeof(struct my_struct_t))) / sizeof(struct my_struct_t);
    for (size_t i_0_val = 0; i_0_val < count_0_val; i_0_val++) {
      struct my_struct_t val_0_deref;
      val_0_deref = val[i_0_val];
      size_t count_2_buf = ((10) * (val_0_deref.size)) / sizeof(uint64_t *);
      for (size_t i_2_buf = 0; i_2_buf < count_2_buf; i_2_buf++) {
        uint64_t *buf_2_deref = NULL;
        buf_2_deref = val_0_deref.buf[i_2_buf];
        size_t count_3_buf_2_deref = g_fdp->ConsumeIntegralInRange<size_t>(
            sizeof(uint64_t) < 8 ? (20 / sizeof(uint64_t)) : 1, g_max_cnt);
        g_fdp->ConsumeData((void *)buf_2_deref,
                           count_3_buf_2_deref * sizeof(uint64_t));
      }
      g_fdp->ConsumeData(&val_0_deref.size, sizeof(size_t));
      g_fdp->ConsumeData(&val_0_deref.my_union, 1);
    }
  }
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0__fuzz_ret = g_fdp->ConsumeIntegralInRange<size_t>(
        sizeof(int *) < 8 ? (20 / sizeof(int *)) : 1, g_max_cnt);
    for (size_t i_0__fuzz_ret = 0; i_0__fuzz_ret < count_0__fuzz_ret;
         i_0__fuzz_ret++) {
      int *_fuzz_ret_0_deref = NULL;
      _fuzz_ret_0_deref = _fuzz_ret[i_0__fuzz_ret];
      size_t count_1__fuzz_ret_0_deref = g_fdp->ConsumeIntegralInRange<size_t>(
          sizeof(int) < 8 ? (20 / sizeof(int)) : 1, g_max_cnt);
      g_fdp->ConsumeData((void *)_fuzz_ret_0_deref,
                         count_1__fuzz_ret_0_deref * sizeof(int));
    }
  }
  return _fuzz_ret;
}

extern "C" void _harness_ocall5(buffer_t buf, size_t len) {
  ocall5(buf, len);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    size_t count_0_buf =
        ((1) * (len)) /
        safe_sizeof<typename std::remove_pointer<buffer_t>::type>();
    g_fdp->ConsumeData(
        (void *)buf,
        count_0_buf *
            safe_sizeof<typename std::remove_pointer<buffer_t>::type>());
  }
}

extern "C" void _harness_ocall6(int arr[4][5]) {
  ocall6(arr);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    for (size_t i_0_0 = 0; i_0_0 < 4; i_0_0++) {
      for (size_t i_0_1 = 0; i_0_1 < 5; i_0_1++) {
        g_fdp->ConsumeData(&arr[i_0_0][i_0_1], sizeof(int));
      }
    }
  }
}

extern "C" void _harness_ocall7(array_t arr) {
  ocall7(arr);
  if (g_fdp->ConsumeProbability<double>() < 0.5 /* as an example */) {
    g_fdp->ConsumeData(&arr[0], 1);
  }
}

// ============================================================================
// ECall Test Harnesses
// ============================================================================
// Auto-generated harness functions for each ECall
// Each function prepares fuzz inputs and invokes the corresponding ECall
// ============================================================================

static void _harness_ecall1(void) {
  char val;
  g_fdp->ConsumeData(&val, sizeof(char));
  ecall1(__g_harness_eid, val);
}
static void _harness_ecall2(void) {
  char *val = NULL;
  val = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_val = g_fdp->ConsumeIntegralInRange<size_t>(
        sizeof(char) < 8 ? (20 / sizeof(char)) : 1, g_max_cnt);
    val = (char *)calloc(count_0_val, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)val);
    g_fdp->ConsumeData((void *)val, count_0_val * sizeof(char));
  }
  ecall2(__g_harness_eid, val);
}
static void _harness_ecall3(void) {
  char *_fuzz_ret = NULL;
  _fuzz_ret = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0__fuzz_ret = g_fdp->ConsumeIntegralInRange<size_t>(
        sizeof(char) < 8 ? (20 / sizeof(char)) : 1, g_max_cnt);
    _fuzz_ret = (char *)calloc(count_0__fuzz_ret, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)_fuzz_ret);
  }
  char *val = NULL;
  size_t count;
  count = g_fdp->ConsumeIntegralInRange<size_t>(
      sizeof(size_t) < 8 ? (20 / sizeof(size_t)) : 1, g_max_cnt);
  val = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_val =
        ((count) * (sizeof(char)) + sizeof(char) - 1) / sizeof(char);
    val = (char *)calloc(count_0_val, sizeof(char));
    g_alloc_mgr.push_back((uint8_t *)val);
    g_fdp->ConsumeData((void *)val, count_0_val * sizeof(char));
  }
  ecall3(__g_harness_eid, &_fuzz_ret, val, count);
}
static void _harness_ecall4(void) {
  int **_fuzz_ret = NULL;
  size_t count_0__fuzz_ret = g_fdp->ConsumeIntegralInRange<size_t>(
      sizeof(int *) < 8 ? (20 / sizeof(int *)) : 1, g_max_cnt);
  _fuzz_ret = (int **)calloc(count_0__fuzz_ret, sizeof(int *));
  g_alloc_mgr.push_back((uint8_t *)_fuzz_ret);
  for (size_t i_0__fuzz_ret = 0; i_0__fuzz_ret < count_0__fuzz_ret;
       i_0__fuzz_ret++) {
    int *_fuzz_ret_0_deref = NULL;
    _fuzz_ret_0_deref = NULL;
    if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
      size_t count_1__fuzz_ret_0_deref = g_fdp->ConsumeIntegralInRange<size_t>(
          sizeof(int) < 8 ? (20 / sizeof(int)) : 1, g_max_cnt);
      _fuzz_ret_0_deref = (int *)calloc(count_1__fuzz_ret_0_deref, sizeof(int));
      g_alloc_mgr.push_back((uint8_t *)_fuzz_ret_0_deref);
    }
    _fuzz_ret[i_0__fuzz_ret] = _fuzz_ret_0_deref;
  }
  struct my_struct_t *val = NULL;
  size_t count;
  count = g_fdp->ConsumeIntegralInRange<size_t>(
      sizeof(size_t) < 8 ? (20 / sizeof(size_t)) : 1, g_max_cnt);
  size_t count_0_val = ((count) * (sizeof(struct my_struct_t)) +
                        sizeof(struct my_struct_t) - 1) /
                       sizeof(struct my_struct_t);
  val = (struct my_struct_t *)calloc(count_0_val, sizeof(struct my_struct_t));
  g_alloc_mgr.push_back((uint8_t *)val);
  for (size_t i_0_val = 0; i_0_val < count_0_val; i_0_val++) {
    struct my_struct_t val_0_deref;
    val_0_deref.size = g_fdp->ConsumeIntegralInRange<size_t>(1, g_max_size);
    size_t count_2_buf = ((10) * (val_0_deref.size) + sizeof(uint64_t *) - 1) /
                         sizeof(uint64_t *);
    val_0_deref.buf = (uint64_t **)calloc(count_2_buf, sizeof(uint64_t *));
    g_alloc_mgr.push_back((uint8_t *)val_0_deref.buf);
    for (size_t i_2_buf = 0; i_2_buf < count_2_buf; i_2_buf++) {
      uint64_t *buf_2_deref = NULL;
      buf_2_deref = NULL;
      if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
        size_t count_3_buf_2_deref = g_fdp->ConsumeIntegralInRange<size_t>(
            sizeof(uint64_t) < 8 ? (20 / sizeof(uint64_t)) : 1, g_max_cnt);
        buf_2_deref = (uint64_t *)calloc(count_3_buf_2_deref, sizeof(uint64_t));
        g_alloc_mgr.push_back((uint8_t *)buf_2_deref);
        g_fdp->ConsumeData((void *)buf_2_deref,
                           count_3_buf_2_deref * sizeof(uint64_t));
      }
      val_0_deref.buf[i_2_buf] = buf_2_deref;
    }
    g_fdp->ConsumeData(&val_0_deref.my_union, 1);
    val[i_0_val] = val_0_deref;
  }
  ecall4(__g_harness_eid, &_fuzz_ret, val, count);
}
static void _harness_ecall5(void) {
  buffer_t buf = NULL;
  size_t len;
  len = g_fdp->ConsumeIntegralInRange<size_t>(1, g_max_size);
  buf = NULL;
  if (g_fdp->ConsumeProbability<double>() < 0.9 /* as an example */) {
    size_t count_0_buf =
        ((1) * (len) +
         safe_sizeof<typename std::remove_pointer<buffer_t>::type>() - 1) /
        safe_sizeof<typename std::remove_pointer<buffer_t>::type>();
    buf = (buffer_t)calloc(
        count_0_buf,
        safe_sizeof<typename std::remove_pointer<buffer_t>::type>());
    g_alloc_mgr.push_back((uint8_t *)buf);
    g_fdp->ConsumeData(
        (void *)buf,
        count_0_buf *
            safe_sizeof<typename std::remove_pointer<buffer_t>::type>());
  }
  ecall5(__g_harness_eid, buf, len);
}
static void _harness_ecall6(void) {
  int arr[4][5];
  for (size_t i_0_0 = 0; i_0_0 < 4; i_0_0++) {
    for (size_t i_0_1 = 0; i_0_1 < 5; i_0_1++) {
      g_fdp->ConsumeData(&arr[i_0_0][i_0_1], sizeof(int));
    }
  }
  ecall6(__g_harness_eid, arr);
}
static void _harness_ecall7(void) {
  array_t arr;
  g_fdp->ConsumeData(&arr[0], 1);
  ecall7(__g_harness_eid, arr);
}

// ============================================================================
// Customized Initialization
// ============================================================================
// This function is called once during fuzzer initialization
// (LLVMFuzzerInitialize).
//
// REQUIRED: Register all test harnesses by filling test_harness_registry[]
//
// Usage:
//   test_harness_registry[test_harness_count++] = {harness_function, weight};
//
// IMPORTANT:
// - This function is called BEFORE any fuzzing iterations start
// - DO NOT create or initialize the enclave here (__g_harness_eid will be 0)
// - DO NOT access g_fdp here (it's not initialized yet)
// - Keep initialization lightweight and fast
// - Weight MUST be > 0 for all harnesses
//
// Optional: Add custom initialization such as:
// - Environment variable configuration (setenv, putenv)
// - Global state initialization
// - Logging/debugging setup
// - Resource pre-allocation
// - Configuration file loading
// ============================================================================

extern "C" void customized_init() {
  // ========================================================================
  // Step 1: Register all test harnesses
  // ========================================================================
  test_harness_registry[test_harness_count++] = {_harness_ecall1,
                                                 10}; // Test ecall1
  test_harness_registry[test_harness_count++] = {_harness_ecall2,
                                                 10}; // Test ecall2
  test_harness_registry[test_harness_count++] = {_harness_ecall3,
                                                 10}; // Test ecall3
  test_harness_registry[test_harness_count++] = {_harness_ecall4,
                                                 10}; // Test ecall4
  test_harness_registry[test_harness_count++] = {_harness_ecall5,
                                                 10}; // Test ecall5
  test_harness_registry[test_harness_count++] = {_harness_ecall6,
                                                 10}; // Test ecall6
  test_harness_registry[test_harness_count++] = {_harness_ecall7,
                                                 10}; // Test ecall7

  // ========================================================================
  // Step 2: Calculate total weight for weighted random selection
  // ========================================================================

  // Sanity check: ensure at least one harness is registered
  if (test_harness_count == 0) {
    fprintf(stderr, "[!] Error: No test harnesses registered\n");
    abort();
  }

  total_weight = 0;
  for (unsigned int i = 0; i < test_harness_count; i++) {
    total_weight += test_harness_registry[i].weight;
  }

  // Sanity check: ensure total weight > 0
  if (total_weight == 0) {
    fprintf(stderr, "[!] Error: All harness weights are 0\n");
    abort();
  }

  // ========================================================================
  // Step 3: Custom initialization (optional)
  // ========================================================================
  // Examples:
  // - setenv("SGX_AESM_ADDR", "1", 1);
  // - freopen("/tmp/fuzzer.log", "w", stderr);
  // - Initialize global variables
  // - Pre-load configuration files
}

// ============================================================================
// Main Test Entry Point
// ============================================================================
// Called by LLVMFuzzerTestOneInput for each fuzzing iteration
// Performs weighted random selection of test harnesses
// ============================================================================

extern "C" void customized_harness(void) {
  // Weighted random selection
  do {
    int rand_val = g_fdp->ConsumeIntegralInRange<int>(0, total_weight - 1);
    int cumulative = 0;
    for (unsigned int i = 0; i < test_harness_count; i++) {
      cumulative += test_harness_registry[i].weight;
      if (rand_val < cumulative) {
        test_harness_registry[i].function();
        break;
      }
    }
  } while (g_fdp->remaining_bytes() > 0);
}
