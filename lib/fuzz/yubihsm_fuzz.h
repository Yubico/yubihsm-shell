#ifndef _FUZZER_H
#define _FUZZER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <yubihsm.h>

extern yh_session *fuzz_session;
#define FUZZ_BACKEND_PASSWORD "fuzzfuzz"

extern uint8_t *backend_data;
extern size_t backend_data_len;

#ifdef __cplusplus
}
#endif

#endif
