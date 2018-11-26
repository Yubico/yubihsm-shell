/*
 * Copyright 2015-2018 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <yubihsm.h>

#ifndef DEFAULT_CONNECTOR_URL
#define DEFAULT_CONNECTOR_URL "http://127.0.0.1:12345"
#endif

int main(void) {
  yh_connector *connector = NULL;
  yh_rc yrc = YHR_GENERIC_ERROR;

  const char *connector_url;

  connector_url = getenv("DEFAULT_CONNECTOR_URL");
  if (connector_url == NULL) {
    connector_url = DEFAULT_CONNECTOR_URL;
  }

  yrc = yh_init();
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "unable to initialize yubihsm: %s\n", yh_strerror(yrc));
    exit(EXIT_FAILURE);
  }

  yrc = yh_init_connector(connector_url, &connector);
  assert(yrc == YHR_SUCCESS);

  yrc = yh_connect(connector, 0);
  assert(yrc == YHR_SUCCESS);

  char *received_url;
  yrc = yh_get_connector_address(connector, &received_url);
  assert(yrc == YHR_SUCCESS);

  printf("Successfully connected to %s, device is ", received_url);
  if (yh_connector_has_device(connector) == false) {
    printf("not present\n");
    exit(EXIT_FAILURE); // This won't happen since we manged to connect
  }
  printf("present\n");

  uint8_t c_major, c_minor, c_patch;
  yrc = yh_get_connector_version(connector, &c_major, &c_minor, &c_patch);
  assert(yrc == YHR_SUCCESS);
  printf("Connector Version: %hhu.%hhu.%hhu\n", c_major, c_minor, c_patch);

  uint8_t d_major, d_minor, d_patch;
  uint32_t serial;
  uint8_t log_total, log_used;
  yh_algorithm algorithms[YH_MAX_ALGORITHM_COUNT];
  size_t n_algorithms = sizeof(algorithms);
  yrc =
    yh_util_get_device_info(connector, &d_major, &d_minor, &d_patch, &serial,
                            &log_total, &log_used, algorithms, &n_algorithms);
  assert(yrc == YHR_SUCCESS);

  printf("Device Version: %hhu.%hhu.%hhu\n", d_major, d_minor, d_patch);
  printf("Serial: %d\n", serial);
  printf("Log: %d/%d (used/total)\n", log_used, log_total);
  printf("Supported algorithms:\n");
  for (size_t i = 0; i < n_algorithms; i++) {
    const char *str;
    yh_algo_to_string(algorithms[i], &str);
    printf("%s\n", str);
  }

  yrc = yh_exit();
  assert(yrc == YHR_SUCCESS);

  return 0;
}
