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

#include <stdlib.h>
#include <yubihsm.h>
#include <sys/time.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define EXIT_SKIPPED 77;

yh_device **devices;
uint16_t n_devices;
yh_session *ses;

typedef struct {
  uint16_t len;
  double min;
  double max;
  double tot;
} repetition_stats;

#define DEFAULT_KEY                                                            \
  "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"

#define N_REPS                                                                 \
  8 // Data length for repetition i is 2^(1 + i) for i in [0, N_REPS-1]
#define N_ITERATIONS 1000
#define ECHO_BYTE 0x0f

int main() {

  yh_rc yrc;

  uint8_t key_enc[YH_KEY_LEN];
  uint8_t key_mac[YH_KEY_LEN];
  uint8_t key_dek[YH_KEY_LEN];

  uint8_t host_challenge[YH_HOST_CHAL_LEN] = {0};

  uint8_t yh_context[YH_CONTEXT_LEN];

  struct timeval before, after;
  double this;
  repetition_stats rs[N_REPS], rs2[N_REPS];

  uint8_t data[YH_MSG_BUF_SIZE];
  uint8_t response[YH_MSG_BUF_SIZE];
  uint16_t response_len;
  uint16_t len;

  uint8_t verbosity = 0; // YH_VERB_USB | YH_VERB_CRYPTO | YH_VERB_INTERMEDIATE
                         // | YH_VERB_INFO | YH_VERB_ERR;

  yrc = yh_init(&devices, &n_devices);
  if (yrc != YH_SUCCESS) {
    fprintf(stderr, "Unable to initialize\n");
    fprintf(stderr, "(Typically this happens if you don't have permissions to "
                    "open the device\n");
    fprintf(stderr, "try re-running as root/Administrator)\n");
    return EXIT_SKIPPED;
  }

  if (n_devices == 0) {
    fprintf(stderr, "No suitable device found. Skipping this test\n");
    return EXIT_SKIPPED;
  }

  yh_set_verbosity(verbosity);

  memset(data, ECHO_BYTE, 1024);

  // Plain commands
  len = 4;
  for (uint16_t rep = 0; rep < N_REPS; rep++) {
    len *= 2;
    rs[rep].len = len;
    fprintf(stderr, "now doing plain with len %d\n", len);
    for (uint16_t i = 0; i < N_ITERATIONS; i++) {
      response_len = sizeof(response);

      gettimeofday(&before, NULL);
      yrc = yh_send_plain_msg(devices[0], YHC_ECHO, data, rs[rep].len, response,
                              &response_len);
      gettimeofday(&after, NULL);

      this = (after.tv_sec - before.tv_sec) * 1000;
      this += ((double) (after.tv_usec - before.tv_usec)) / 1000;
      if (i == 0) {
        rs[rep].max = rs[rep].min = this;
        rs[rep].tot = 0;
      } else {
        if (this > rs[rep].max) {
          rs[rep].max = this;
        }
        if (this < rs[rep].min) {
          rs[rep].min = this;
        }
      }

      rs[rep].tot += this;

      if (rs[rep].len != response_len ||
          memcmp(data, response, rs[rep].len) != 0) {
        fprintf(stderr, "Data mismatch\n");
        return EXIT_FAILURE;
      }
    }
  }

  // Auth commands
  memcpy(key_enc, DEFAULT_KEY, YH_KEY_LEN); // TODO: fix
  memcpy(key_mac, DEFAULT_KEY, YH_KEY_LEN); // TODO: fix
  memcpy(key_dek, DEFAULT_KEY, YH_KEY_LEN); // TODO: fix

  yrc = yh_open_device(devices[0]);
  if (yrc != YH_SUCCESS) {
    fprintf(stderr, "Unable to open device: %s\n", yh_strerror(yrc));
    return EXIT_FAILURE;
  }

  yrc = yh_create_session(devices[0], 0, host_challenge, key_enc, 16, key_mac,
                          16, yh_context, &ses);
  if (yrc != YH_SUCCESS) {
    fprintf(stderr, "Failed to create session: %s\n", yh_strerror(yrc));
    return EXIT_FAILURE;
  }

  yrc = yh_authenticate_session(ses, yh_context);
  if (yrc != YH_SUCCESS) {
    fprintf(stderr, "Failed to create session: %d, %s\n", yrc,
            yh_strerror(yrc));
    return EXIT_FAILURE;
  }

  len = 4;
  for (uint16_t rep = 0; rep < N_REPS; rep++) {
    len *= 2;
    rs2[rep].len = len;
    fprintf(stderr, "now doing auth with len %d\n", len);
    for (uint16_t i = 0; i < N_ITERATIONS; i++) {
      response_len = sizeof(response);

      gettimeofday(&before, NULL);
      yrc = yh_send_secure_msg(ses, YHC_ECHO, data, rs2[rep].len, response,
                               &response_len);
      gettimeofday(&after, NULL);
      if (yrc != YH_SUCCESS) {
        fprintf(stderr, "Failed to send message: %d, %s\n", yrc,
                yh_strerror(yrc));
        return EXIT_FAILURE;
      }

      this = (after.tv_sec - before.tv_sec) * 1000;
      this += ((double) (after.tv_usec - before.tv_usec)) / 1000;
      if (i == 0) {
        rs2[rep].max = rs2[rep].min = this;
        rs2[rep].tot = 0;
      } else {
        if (this > rs2[rep].max) {
          rs2[rep].max = this;
        }
        if (this < rs2[rep].min) {
          rs2[rep].min = this;
        }
      }

      rs2[rep].tot += this;

      if (rs2[rep].len != response_len ||
          memcmp(data, response, rs2[rep].len) != 0) {
        fprintf(stderr, "Data mismatch\n");
        return EXIT_FAILURE;
      }
    }
  }

  yh_exit(devices, n_devices);

  fprintf(stdout, "Iterations %d\n", N_ITERATIONS);
  fprintf(stdout, "|  Len   | min [ms] | max [ms] | avg [ms] | type  |\n");
  fprintf(stdout, "---------------------------------------------------\n");
  for (uint16_t i = 0; i < N_REPS; i++) {
    fprintf(stdout, "| %6d | %8.02f | %8.02f | %8.02f | plain |\n", rs[i].len,
            rs[i].min, rs[i].max, rs[i].tot / N_ITERATIONS);
  }
  for (uint16_t i = 0; i < N_REPS; i++) {
    fprintf(stdout, "| %6d | %8.02f | %8.02f | %8.02f | auth  |\n", rs2[i].len,
            rs2[i].min, rs2[i].max, rs2[i].tot / N_ITERATIONS);
  }

  return EXIT_SUCCESS;
}
