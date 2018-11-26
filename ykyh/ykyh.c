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
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "internal.h"
#include "ykyh.h"

static ykyh_rc send_data(ykyh_state *state, APDU *apdu, unsigned char *data,
                         unsigned long *recv_len, int *sw);

static void dump_hex(const unsigned char *buf, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(stderr, "%02x ", buf[i]);
  }
}

ykyh_rc ykyh_init(ykyh_state **state, int verbose) {
  if (state == NULL) {
    if (verbose) {
      fprintf(stderr, "Unable to initialize: %s",
              ykyh_strerror(YKYHR_INVALID_PARAMS));
    }

    return YKYHR_INVALID_PARAMS;
  }

  ykyh_state *s = malloc(sizeof(ykyh_state));

  if (s == NULL) {
    if (verbose) {
      fprintf(stderr, "Unable to initialize: %s",
              ykyh_strerror(YKYHR_MEMORY_ERROR));
    }

    return YKYHR_MEMORY_ERROR;
  }

  memset(s, 0, sizeof(ykyh_state));
  s->verbose = verbose;
  s->context = SCARD_E_INVALID_HANDLE;
  *state = s;

  return YKYHR_SUCCESS;
}

ykyh_rc ykyh_done(ykyh_state *state) {
  ykyh_disconnect(state);

  if (state != NULL) {
    free(state);
  }

  return YKYHR_SUCCESS;
}

ykyh_rc ykyh_disconnect(ykyh_state *state) {
  if (state == NULL) {
    return YKYHR_INVALID_PARAMS;
  }

  if (state->card) {
    SCardDisconnect(state->card, SCARD_RESET_CARD);
    state->card = 0;
  }

  if (SCardIsValidContext(state->context) == SCARD_S_SUCCESS) {
    SCardReleaseContext(state->context);
    state->context = SCARD_E_INVALID_HANDLE;
  }

  return YKYHR_SUCCESS;
}

ykyh_rc ykyh_connect(ykyh_state *state, const char *wanted) {
  unsigned long active_protocol;
  char reader_buf[2048];
  size_t num_readers = sizeof(reader_buf);
  long rc;
  char *reader_ptr;

  if (state == NULL) {
    return YKYHR_INVALID_PARAMS;
  }

  ykyh_rc ret = ykyh_list_readers(state, reader_buf, &num_readers);
  if (ret != YKYHR_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to list_readers: %s", ykyh_strerror(ret));
    }

    return ret;
  }

  for (reader_ptr = reader_buf; *reader_ptr != '\0';
       reader_ptr += strlen(reader_ptr) + 1) {
    if (wanted) {
      if (!strstr(reader_ptr, wanted)) {
        if (state->verbose) {
          fprintf(stderr, "skipping reader '%s' since it doesn't match '%s'\n",
                  reader_ptr, wanted);
        }
        continue;
      }
    }

    if (state->verbose) {
      fprintf(stderr, "trying to connect to reader '%s'\n", reader_ptr);
    }

    rc =
      SCardConnect(state->context, reader_ptr, SCARD_SHARE_SHARED,
                   SCARD_PROTOCOL_T1, &state->card, (LPDWORD) &active_protocol);

    if (rc != SCARD_S_SUCCESS) {
      if (state->verbose) {
        fprintf(stderr, "SCardConnect failed, rc=%08lx\n", rc);
      }
      continue;
    }

    APDU apdu;
    unsigned char data[0xff];
    unsigned long recv_len = sizeof(data);
    int sw;
    ykyh_rc res;

    memset(apdu.raw, 0, sizeof(apdu));
    apdu.st.ins = 0xa4;
    apdu.st.p1 = 0x04;
    apdu.st.lc = sizeof(aid);
    memcpy(apdu.st.data, aid, sizeof(aid));

    if ((res = send_data(state, &apdu, data, &recv_len, &sw)) !=
        YKYHR_SUCCESS) {
      if (state->verbose) {
        fprintf(stderr, "Failed communicating with card: '%s'\n",
                ykyh_strerror(res));
      }

      continue;
    } else if (sw == SW_SUCCESS) {
      return YKYHR_SUCCESS;
    } else {
      if (state->verbose) {
        fprintf(stderr, "Failed selecting application: %04x\n", sw);
      }
    }
  }

  if (*reader_ptr == '\0') {
    if (state->verbose) {
      fprintf(stderr, "error: no usable reader found\n");
    }
    SCardReleaseContext(state->context);
    state->context = SCARD_E_INVALID_HANDLE;
    return YKYHR_PCSC_ERROR;
  }

  return YKYHR_GENERIC_ERROR;
}

ykyh_rc ykyh_list_readers(ykyh_state *state, char *readers, size_t *len) {
  unsigned long num_readers = 0;
  long rc;

  if (state == NULL || readers == NULL) {
    return YKYHR_INVALID_PARAMS;
  }

  if (SCardIsValidContext(state->context) != SCARD_S_SUCCESS) {
    rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context);
    if (rc != SCARD_S_SUCCESS) {
      if (state->verbose) {
        fprintf(stderr, "error: SCardEstablishContext failed, rc=%08lx\n", rc);
      }
      return YKYHR_PCSC_ERROR;
    }
  }

  rc = SCardListReaders(state->context, NULL, NULL, (LPDWORD) &num_readers);
  if (rc != SCARD_S_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "error: SCardListReaders failed, rc=%08lx\n", rc);
    }
    SCardReleaseContext(state->context);
    state->context = SCARD_E_INVALID_HANDLE;
    return YKYHR_PCSC_ERROR;
  }

  if (num_readers > *len) {
    num_readers = *len;
  }

  rc = SCardListReaders(state->context, NULL, readers, (LPDWORD) &num_readers);
  if (rc != SCARD_S_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "error: SCardListReaders failed, rc=%08lx\n", rc);
    }
    SCardReleaseContext(state->context);
    state->context = SCARD_E_INVALID_HANDLE;
    return YKYHR_PCSC_ERROR;
  }

  *len = num_readers;

  return YKYHR_SUCCESS;
}

static ykyh_rc send_data(ykyh_state *state, APDU *apdu, unsigned char *data,
                         unsigned long *recv_len, int *sw) {
  long rc;
  unsigned int send_len = (unsigned int) apdu->st.lc + 5;

  *sw = 0;

  if (state->verbose > 1) {
    fprintf(stderr, "> ");
    dump_hex(apdu->raw, send_len);
    fprintf(stderr, "\n");
  }
  rc = SCardTransmit(state->card, SCARD_PCI_T1, apdu->raw, send_len, NULL, data,
                     (LPDWORD) recv_len);
  if (rc != SCARD_S_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "error: SCardTransmit failed, rc=%08lx\n", rc);
    }
    return YKYHR_PCSC_ERROR;
  }

  if (state->verbose > 1) {
    fprintf(stderr, "< ");
    dump_hex(data, *recv_len);
    fprintf(stderr, "\n");
  }
  if (*recv_len >= 2) {
    *sw = (data[*recv_len - 2] << 8) | data[*recv_len - 1];
  }

  return YKYHR_SUCCESS;
}

ykyh_rc ykyh_get_version(ykyh_state *state, char *version, size_t len) {
  APDU apdu;
  unsigned char data[261];
  unsigned long recv_len = sizeof(data);
  int sw;
  ykyh_rc res;

  if (state == NULL || version == NULL) {
    return YKYHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKYH_INS_GET_VERSION;
  if ((res = send_data(state, &apdu, data, &recv_len, &sw)) != YKYHR_SUCCESS) {
    return res;
  } else if (sw == SW_SUCCESS) {
    int result = snprintf(version, len, "%d.%d.%d", data[0], data[1], data[2]);
    if (result < 0) {
      if (state->verbose) {
        fprintf(stderr, "Version buffer too small\n");
      }
      return YKYHR_GENERIC_ERROR;
    }
    return YKYHR_SUCCESS;
  } else {
    return YKYHR_GENERIC_ERROR;
  }
}

ykyh_rc ykyh_put(ykyh_state *state, const char *name, const uint8_t *key_enc,
                 size_t key_enc_len, const uint8_t *key_mac, size_t key_mac_len,
                 const char *pw, const uint8_t touch_policy) {
  APDU apdu;
  uint8_t *ptr = apdu.st.data;
  unsigned char data[261];
  unsigned long recv_len = sizeof(data);
  int sw;

  if (state == NULL || name == NULL || strlen(name) < YKYH_MIN_NAME_LEN ||
      strlen(name) > YKYH_MAX_NAME_LEN || key_enc == NULL ||
      key_enc_len != YKYH_KEY_LEN || key_mac == NULL ||
      key_mac_len != YKYH_KEY_LEN || pw == NULL || strlen(pw) != YKYH_KEY_LEN) {
    return YKYHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKYH_INS_PUT;

  *(ptr++) = YKYH_TAG_NAME;
  apdu.st.lc++;
  *(ptr++) = strlen(name);
  apdu.st.lc++;
  memcpy(ptr, name, strlen(name));
  ptr += strlen(name);
  apdu.st.lc += strlen(name);

  *(ptr++) = YKYH_TAG_ALGO;
  apdu.st.lc++;
  *(ptr++) = 1;
  apdu.st.lc++;
  *(ptr++) = YKYH_SCP03_ALGO;
  apdu.st.lc++;

  *(ptr++) = YKYH_TAG_KEY_ENC;
  apdu.st.lc++;
  *(ptr++) = 16;
  apdu.st.lc++;
  memcpy(ptr, key_enc, 16);
  ptr += 16;
  apdu.st.lc += 16;

  *(ptr++) = YKYH_TAG_KEY_MAC;
  apdu.st.lc++;
  *(ptr++) = 16;
  apdu.st.lc++;
  memcpy(ptr, key_mac, 16);
  ptr += 16;
  apdu.st.lc += 16;

  *(ptr++) = YKYH_TAG_PW;
  apdu.st.lc++;
  *(ptr++) = YKYH_PW_LEN;
  apdu.st.lc++;
  memcpy(ptr, pw, YKYH_PW_LEN);
  ptr += YKYH_PW_LEN;
  apdu.st.lc += YKYH_PW_LEN;

  *(ptr++) = YKYH_TAG_TOUCH;
  apdu.st.lc++;
  *(ptr++) = 1;
  apdu.st.lc++;
  *(ptr++) = touch_policy ? 1 : 0;
  apdu.st.lc++;

  ykyh_rc rc = send_data(state, &apdu, data, &recv_len, &sw);
  if (rc != YKYHR_SUCCESS) {
    return rc;
  } else if (sw != SW_SUCCESS) {
    return YKYHR_GENERIC_ERROR; // TODO(adma): better error
  }

  return YKYHR_SUCCESS;
}

ykyh_rc ykyh_delete(ykyh_state *state, char *name) {
  APDU apdu;
  uint8_t *ptr;
  unsigned char data[64];
  unsigned long recv_len = sizeof(data);
  int sw;
  ykyh_rc rc;

  if (state == NULL || name == NULL || strlen(name) < YKYH_MIN_NAME_LEN ||
      strlen(name) > YKYH_MAX_NAME_LEN) {
    return YKYHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKYH_INS_DELETE;

  ptr = apdu.st.data;

  *(ptr++) = YKYH_TAG_NAME;
  apdu.st.lc++;
  *(ptr++) = strlen(name);
  apdu.st.lc++;
  memcpy(ptr, name, strlen(name));
  ptr += strlen(name);
  apdu.st.lc += strlen(name);

  rc = send_data(state, &apdu, data, &recv_len, &sw);
  if (rc != YKYHR_SUCCESS) {
    return rc;
  } else if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to delete key: %04x\n", sw);
    }
    return YKYHR_GENERIC_ERROR;
  }

  return YKYHR_SUCCESS;
}

ykyh_rc ykyh_calculate(ykyh_state *state, const char *name, uint8_t *context,
                       size_t context_len, const char *pw, uint8_t *key_s_enc,
                       size_t key_s_enc_len, uint8_t *key_s_mac,
                       size_t key_s_mac_len, uint8_t *key_s_rmac,
                       size_t key_s_rmac_len, uint8_t *retries) {
  APDU apdu;
  uint8_t *ptr;
  unsigned char data[64]; // NOTE(adma): must be >= (YKYH_KEY_LEN * 3) + 2 = 50
  unsigned long recv_len = sizeof(data);
  int sw;
  ykyh_rc rc;

  if (state == NULL || name == NULL || strlen(name) < YKYH_MIN_NAME_LEN ||
      strlen(name) > YKYH_MAX_NAME_LEN || context == NULL ||
      context_len != YKYH_CONTEXT_LEN || pw == NULL ||
      strlen(pw) != YKYH_PW_LEN || key_s_enc == NULL ||
      key_s_enc_len != YKYH_KEY_LEN || key_s_mac == NULL ||
      key_s_mac_len != YKYH_KEY_LEN || key_s_rmac == NULL ||
      key_s_rmac_len != YKYH_KEY_LEN) {
    return YKYHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKYH_INS_CALCULATE;

  ptr = apdu.st.data;

  *(ptr++) = YKYH_TAG_NAME;
  apdu.st.lc++;
  *(ptr++) = strlen(name);
  apdu.st.lc++;
  memcpy(ptr, name, strlen(name));
  ptr += strlen(name);
  apdu.st.lc += strlen(name);

  *(ptr++) = YKYH_TAG_CONTEXT;
  apdu.st.lc++;
  *(ptr++) = context_len;
  apdu.st.lc++;
  memcpy(ptr, context, context_len);
  ptr += context_len;
  apdu.st.lc += context_len;

  *(ptr++) = YKYH_TAG_PW;
  apdu.st.lc++;
  *(ptr++) = YKYH_PW_LEN;
  apdu.st.lc++;
  memcpy(ptr, pw, YKYH_PW_LEN);
  ptr += YKYH_PW_LEN;
  apdu.st.lc += YKYH_PW_LEN;

  rc = send_data(state, &apdu, data, &recv_len, &sw);
  if (rc != YKYHR_SUCCESS) {
    return rc;
  } else if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to derive keys: %04x\n", sw);
    }
    if ((sw & 0xfff0) == SW_ERR_AUTHENTICATION_FAILED) {
      if (retries != NULL) {
        *retries = sw & ~SW_ERR_AUTHENTICATION_FAILED;
      }
      return YKYHR_WRONG_PW;
    } else {
      return YKYHR_ENTRY_NOT_FOUND;
    }
  }

  ptr = data;

  memcpy(key_s_enc, ptr, YKYH_KEY_LEN);
  ptr += YKYH_KEY_LEN;
  memcpy(key_s_mac, ptr, YKYH_KEY_LEN);
  ptr += YKYH_KEY_LEN;
  memcpy(key_s_rmac, ptr, YKYH_KEY_LEN);
  ptr += YKYH_KEY_LEN;

  return YKYHR_SUCCESS;
}

ykyh_rc ykyh_reset(ykyh_state *state) {

  APDU apdu;
  unsigned char data[8];
  unsigned long recv_len = sizeof(data);
  int sw;
  ykyh_rc res;

  if (state == NULL) {
    return YKYHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKYH_INS_RESET;
  apdu.st.p1 = YKYH_P1_RESET;
  apdu.st.p2 = YKYH_P2_RESET;

  res = send_data(state, &apdu, data, &recv_len, &sw);
  if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to reset: %s\n", ykyh_strerror(res));
    }
  }

  return res;
}

ykyh_rc ykyh_list_keys(ykyh_state *state, ykyh_list_entry *list,
                       size_t *list_items) {

  APDU apdu;
  unsigned char data[1024];
  unsigned long recv_len = sizeof(data);
  int sw;
  ykyh_rc res;

  if (state == NULL || list_items == NULL) {
    return YKYHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKYH_INS_LIST;

  res = send_data(state, &apdu, data, &recv_len, &sw);
  if (res != YKYHR_SUCCESS || sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to list keys: %s\n", ykyh_strerror(res));
    }
    return res;
  }

  if (list == NULL) {
    *list_items = data[0];

    return YKYHR_SUCCESS;
  }

  if (*list_items < data[0]) {
    return YKYHR_GENERIC_ERROR; // TODO(adma): not enough space, better error?
  }
  *list_items = data[0];

  size_t i = 1;
  for (size_t j = 0; j < *list_items; j++) {
    if (data[i++] == YKYH_TAG_NAME_LIST) {
      size_t len = data[i++];
      list[j].algo = data[i++];
      memset(list[j].name, 0, sizeof(list[j].name));
      memcpy(list[j].name, data + i, len - 2);
      i += len - 2;
      list[j].ctr = data[i++];
    } else {
      return YKYHR_GENERIC_ERROR;
    }
  }

  if (i != recv_len - 2) {
    return YKYHR_GENERIC_ERROR;
  }

  return YKYHR_SUCCESS;
}

ykyh_rc ykyh_get_challenge(ykyh_state *state) {

  (void) state;
  return YKYHR_SUCCESS;
}
