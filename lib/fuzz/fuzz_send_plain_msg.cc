#include <assert.h>
#include "debug_lib.h"

extern "C" {
#include "yubihsm.h"
}

#include "../src/fuzz/fuzzer.h"

FuzzedDataProvider *fuzz_data;
yh_connector *connector;

static bool initialize() {
  yh_rc rc = yh_init_connector("yhfuzz://yubihsm_fuzz", &connector);
  assert(rc == YHR_SUCCESS);
  rc = yh_connect(connector, 0);
  assert(rc == YHR_SUCCESS);
  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static bool is_initialized = initialize();

  if (size < 2) {
    return 0;
  }
  size_t data_len = data[0];
  size_t response_len = data[1];

  fuzz_data = new FuzzedDataProvider(data + 2, size - 2);

  uint8_t *hsm_data = new uint8_t[data_len];
  uint8_t *response = new uint8_t[response_len];
  yh_cmd response_cmd;

  yh_send_plain_msg(connector, YHC_ECHO, hsm_data, data_len, &response_cmd,
                    response, &response_len);

  delete hsm_data;
  delete response;
  delete fuzz_data;

  return 0;
}