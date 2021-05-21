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
#include "ykhsmauth.h"

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

static uint16_t encode_len(uint8_t *buf, uint16_t len) {
  if (len > 0xff) {
    *buf++ = 0x82;
    *buf++ = len >> 8;
    *buf++ = len;
    return 3;
  }
  if (len > 0x7f) {
    *buf++ = 0x81;
    *buf++ = len;
    return 2;
  }
  *buf++ = len;
  return 1;
}

static void dump_hex(const unsigned char *buf, unsigned int len) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    fprintf(stderr, "%02x ", buf[i]);
  }
}

static ykhsmauth_rc translate_error(uint16_t sw, uint8_t *retries) {
  if ((sw & 0xfff0) == SW_AUTHENTICATION_FAILED) {
    if (retries != NULL) {
      *retries = sw & ~0xfff0;
    }
    return YKHSMAUTHR_WRONG_PW;
  } else if (sw == SW_FILE_FULL) {
    return YKHSMAUTHR_STORAGE_FULL;
  } else if (sw == SW_FILE_NOT_FOUND) {
    return YKHSMAUTHR_ENTRY_NOT_FOUND;
  } else if (sw == SW_FILE_INVALID || sw == SW_WRONG_DATA) {
    return YKHSMAUTHR_INVALID_PARAMS;
  } else if (sw == SW_MEMORY_ERROR) {
    return YKHSMAUTHR_MEMORY_ERROR;
  } else if (sw == SW_SECURITY_STATUS_NOT_SATISFIED) {
    return YKHSMAUTHR_TOUCH_ERROR;
  } else {
    return YKHSMAUTHR_GENERIC_ERROR;
  }
}

ykhsmauth_rc ykhsmauth_init(ykhsmauth_state **state, int verbose) {
  if (state == NULL) {
    if (verbose) {
      fprintf(stderr, "Unable to initialize: %s",
              ykhsmauth_strerror(YKHSMAUTHR_INVALID_PARAMS));
    }

    return YKHSMAUTHR_INVALID_PARAMS;
  }

  ykhsmauth_state *s = malloc(sizeof(ykhsmauth_state));

  if (s == NULL) {
    if (verbose) {
      fprintf(stderr, "Unable to initialize: %s",
              ykhsmauth_strerror(YKHSMAUTHR_MEMORY_ERROR));
    }

    return YKHSMAUTHR_MEMORY_ERROR;
  }

  memset(s, 0, sizeof(ykhsmauth_state));
  s->verbose = verbose;
  s->context = SCARD_E_INVALID_HANDLE;
  *state = s;

  return YKHSMAUTHR_SUCCESS;
}

ykhsmauth_rc ykhsmauth_done(ykhsmauth_state *state) {
  ykhsmauth_disconnect(state);

  if (state != NULL) {
    free(state);
  }

  return YKHSMAUTHR_SUCCESS;
}

ykhsmauth_rc ykhsmauth_disconnect(ykhsmauth_state *state) {
  if (state == NULL) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  if (state->card) {
    SCardDisconnect(state->card, SCARD_RESET_CARD);
    state->card = 0;
  }

  if (SCardIsValidContext(state->context) == SCARD_S_SUCCESS) {
    SCardReleaseContext(state->context);
    state->context = SCARD_E_INVALID_HANDLE;
  }

  return YKHSMAUTHR_SUCCESS;
}

static ykhsmauth_rc send_data(ykhsmauth_state *state, APDU *apdu,
                              unsigned char *data, unsigned long *recv_len,
                              int *sw) {
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
    return YKHSMAUTHR_PCSC_ERROR;
  }

  if (state->verbose > 1) {
    fprintf(stderr, "< ");
    dump_hex(data, *recv_len);
    fprintf(stderr, "\n");
  }
  if (*recv_len >= 2) {
    *sw = (data[*recv_len - 2] << 8) | data[*recv_len - 1];
    *recv_len -= 2;
  } else {
    *sw = 0;
  }

  return YKHSMAUTHR_SUCCESS;
}

ykhsmauth_rc ykhsmauth_connect(ykhsmauth_state *state, const char *wanted) {
  unsigned long active_protocol;
  char reader_buf[2048];
  size_t num_readers = sizeof(reader_buf);
  long rc;
  char *reader_ptr;

  if (state == NULL) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  ykhsmauth_rc ret = ykhsmauth_list_readers(state, reader_buf, &num_readers);
  if (ret != YKHSMAUTHR_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to list_readers: %s", ykhsmauth_strerror(ret));
    }

    return ret;
  }

  for (reader_ptr = reader_buf; *reader_ptr != '\0';
       reader_ptr += strlen(reader_ptr) + 1) {
    if (wanted) {
      bool found = false;
      char *ptr = reader_ptr;
      while (strlen(ptr) >= strlen(wanted)) {
        if (strncasecmp(ptr, wanted, strlen(wanted)) == 0) {
          found = true;
          break;
        }
        ptr++;
      }
      if (found == false) {
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
    ykhsmauth_rc res;

    memset(apdu.raw, 0, sizeof(apdu));
    apdu.st.ins = 0xa4;
    apdu.st.p1 = 0x04;
    apdu.st.lc = sizeof(aid);
    memcpy(apdu.st.data, aid, sizeof(aid));

    if ((res = send_data(state, &apdu, data, &recv_len, &sw)) !=
        YKHSMAUTHR_SUCCESS) {
      if (state->verbose) {
        fprintf(stderr, "Failed communicating with card: '%s'\n",
                ykhsmauth_strerror(res));
      }

      continue;
    } else if (sw == SW_SUCCESS) {
      return YKHSMAUTHR_SUCCESS;
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
    return YKHSMAUTHR_PCSC_ERROR;
  }

  return YKHSMAUTHR_GENERIC_ERROR;
}

ykhsmauth_rc ykhsmauth_list_readers(ykhsmauth_state *state, char *readers,
                                    size_t *len) {
  unsigned long num_readers = 0;
  long rc;

  if (state == NULL || readers == NULL) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  if (SCardIsValidContext(state->context) != SCARD_S_SUCCESS) {
    rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context);
    if (rc != SCARD_S_SUCCESS) {
      if (state->verbose) {
        fprintf(stderr, "error: SCardEstablishContext failed, rc=%08lx\n", rc);
      }
      return YKHSMAUTHR_PCSC_ERROR;
    }
  }

  rc = SCardListReaders(state->context, NULL, NULL, (LPDWORD) &num_readers);
  if (rc != SCARD_S_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "error: SCardListReaders failed, rc=%08lx\n", rc);
    }
    SCardReleaseContext(state->context);
    state->context = SCARD_E_INVALID_HANDLE;
    return YKHSMAUTHR_PCSC_ERROR;
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
    return YKHSMAUTHR_PCSC_ERROR;
  }

  *len = num_readers;

  return YKHSMAUTHR_SUCCESS;
}

ykhsmauth_rc ykhsmauth_get_version(ykhsmauth_state *state, char *version,
                                   size_t len) {
  APDU apdu;
  unsigned char data[261];
  unsigned long recv_len = sizeof(data);
  int sw;
  ykhsmauth_rc res;

  if (state == NULL || version == NULL) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKHSMAUTH_INS_GET_VERSION;
  if ((res = send_data(state, &apdu, data, &recv_len, &sw)) !=
      YKHSMAUTHR_SUCCESS) {
    return res;
  } else if (sw == SW_SUCCESS && recv_len == 3) {
    int result = snprintf(version, len, "%d.%d.%d", data[0], data[1], data[2]);
    if (result < 0) {
      if (state->verbose) {
        fprintf(stderr, "Version buffer too small\n");
      }
      return YKHSMAUTHR_GENERIC_ERROR;
    }
    return YKHSMAUTHR_SUCCESS;
  } else {
    return translate_error(sw, NULL);
  }
}

ykhsmauth_rc ykhsmauth_put(ykhsmauth_state *state, const uint8_t *mgmkey,
                           size_t mgmkey_len, const char *label, uint8_t algo,
                           const uint8_t *key, size_t key_len,
                           const uint8_t *cpw, size_t cpw_len,
                           const uint8_t touch_policy, uint8_t *retries) {
  APDU apdu;
  uint8_t *ptr = apdu.st.data;
  unsigned char data[261];
  unsigned long recv_len = sizeof(data);
  int sw;

  if (state == NULL || mgmkey == NULL || mgmkey_len != YKHSMAUTH_PW_LEN ||
      label == NULL || strlen(label) < YKHSMAUTH_MIN_LABEL_LEN ||
      strlen(label) > YKHSMAUTH_MAX_LABEL_LEN || key == NULL || cpw == NULL ||
      cpw_len > YKHSMAUTH_PW_LEN) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  if (algo != YKHSMAUTH_YUBICO_AES128_ALGO &&
      algo != YKHSMAUTH_YUBICO_ECP256_ALGO) {
    if (state->verbose) {
      fprintf(stderr, "Only YKHSMAUTH_YUBICO_AES128_ALGO and "
                      "YKHSMAUTH_YUBICO_ECP256_ALGO supported\n");
    }
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  if (algo == YKHSMAUTH_YUBICO_AES128_ALGO &&
      key_len != YKHSMAUTH_YUBICO_AES128_KEY_LEN) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  if (algo == YKHSMAUTH_YUBICO_ECP256_ALGO &&
      key_len != YKHSMAUTH_YUBICO_ECP256_KEY_LEN) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKHSMAUTH_INS_PUT;

  *(ptr++) = YKHSMAUTH_TAG_MGMKEY;
  *(ptr++) = 16;
  memcpy(ptr, mgmkey, 16);
  ptr += 16;

  *(ptr++) = YKHSMAUTH_TAG_LABEL;
  *(ptr++) = strlen(label);
  memcpy(ptr, label, strlen(label));
  ptr += strlen(label);

  *(ptr++) = YKHSMAUTH_TAG_ALGO;
  *(ptr++) = 1;
  *(ptr++) = algo;

  if (algo == YKHSMAUTH_YUBICO_AES128_ALGO) {
    *(ptr++) = YKHSMAUTH_TAG_KEY_ENC;
    *(ptr++) = YKHSMAUTH_YUBICO_AES128_KEY_LEN / 2;
    memcpy(ptr, key, YKHSMAUTH_YUBICO_AES128_KEY_LEN / 2);
    ptr += YKHSMAUTH_YUBICO_AES128_KEY_LEN / 2;

    *(ptr++) = YKHSMAUTH_TAG_KEY_MAC;
    *(ptr++) = YKHSMAUTH_YUBICO_AES128_KEY_LEN / 2;
    memcpy(ptr, key + YKHSMAUTH_YUBICO_AES128_KEY_LEN / 2,
           YKHSMAUTH_YUBICO_AES128_KEY_LEN / 2);
    ptr += YKHSMAUTH_YUBICO_AES128_KEY_LEN / 2;
  } else if (algo == YKHSMAUTH_YUBICO_ECP256_ALGO) {
    *(ptr++) = YKHSMAUTH_TAG_PUBKEY;
    *(ptr++) = YKHSMAUTH_YUBICO_ECP256_KEY_LEN;
    memcpy(ptr, key, YKHSMAUTH_YUBICO_ECP256_KEY_LEN);
    ptr += YKHSMAUTH_YUBICO_ECP256_KEY_LEN;
  }

  *(ptr++) = YKHSMAUTH_TAG_PW;
  *(ptr++) = YKHSMAUTH_PW_LEN;
  memcpy(ptr, cpw, cpw_len);
  memset(ptr + cpw_len, 0, YKHSMAUTH_PW_LEN - cpw_len);
  ptr += YKHSMAUTH_PW_LEN;

  *(ptr++) = YKHSMAUTH_TAG_TOUCH;
  *(ptr++) = 1;
  *(ptr++) = touch_policy ? 1 : 0;

  apdu.st.lc = ptr - apdu.st.data;

  ykhsmauth_rc rc = send_data(state, &apdu, data, &recv_len, &sw);
  if (rc != YKHSMAUTHR_SUCCESS) {
    return rc;
  } else if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to store credential: %04x\n", sw);
    }

    return translate_error(sw, retries);
  }

  return YKHSMAUTHR_SUCCESS;
}

ykhsmauth_rc ykhsmauth_delete(ykhsmauth_state *state, uint8_t *mgmkey,
                              size_t mgmkey_len, char *label,
                              uint8_t *retries) {
  APDU apdu;
  uint8_t *ptr;
  unsigned char data[64];
  unsigned long recv_len = sizeof(data);
  int sw;
  ykhsmauth_rc rc;

  if (state == NULL || mgmkey == NULL || mgmkey_len != YKHSMAUTH_PW_LEN ||
      label == NULL || strlen(label) < YKHSMAUTH_MIN_LABEL_LEN ||
      strlen(label) > YKHSMAUTH_MAX_LABEL_LEN) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKHSMAUTH_INS_DELETE;

  ptr = apdu.st.data;

  *(ptr++) = YKHSMAUTH_TAG_MGMKEY;
  *(ptr++) = 16;
  memcpy(ptr, mgmkey, 16);
  ptr += 16;

  *(ptr++) = YKHSMAUTH_TAG_LABEL;
  *(ptr++) = strlen(label);
  memcpy(ptr, label, strlen(label));
  ptr += strlen(label);

  apdu.st.lc = ptr - apdu.st.data;

  rc = send_data(state, &apdu, data, &recv_len, &sw);
  if (rc != YKHSMAUTHR_SUCCESS) {
    return rc;
  } else if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to delete credential: %04x\n", sw);
    }

    return translate_error(sw, retries);
  }

  return YKHSMAUTHR_SUCCESS;
}

ykhsmauth_rc ykhsmauth_calculate(ykhsmauth_state *state, const char *label,
                                 uint8_t *context, size_t context_len,
                                 uint8_t *card_crypto, size_t card_crypto_len,
                                 const uint8_t *pw, size_t pw_len,
                                 uint8_t *key_s_enc, size_t key_s_enc_len,
                                 uint8_t *key_s_mac, size_t key_s_mac_len,
                                 uint8_t *key_s_rmac, size_t key_s_rmac_len,
                                 uint8_t *retries) {
  APDU apdu;
  uint8_t *ptr;
  unsigned char data[64]; // NOTE(adma): must be >= (3 * YKHSMAUTH_KEY_LEN +
                          // YKHSMAUTH_HOST_CRYPTO_LEN) + 2 = 58
  unsigned long recv_len = sizeof(data);
  int sw;
  ykhsmauth_rc rc;

  if (state == NULL || label == NULL ||
      strlen(label) < YKHSMAUTH_MIN_LABEL_LEN ||
      strlen(label) > YKHSMAUTH_MAX_LABEL_LEN || context == NULL ||
      context_len > 2 * YKHSMAUTH_YUBICO_ECP256_KEY_LEN || pw == NULL ||
      pw_len > YKHSMAUTH_PW_LEN || key_s_enc == NULL ||
      key_s_enc_len != YKHSMAUTH_SESSION_KEY_LEN || key_s_mac == NULL ||
      key_s_mac_len != YKHSMAUTH_SESSION_KEY_LEN || key_s_rmac == NULL ||
      key_s_rmac_len != YKHSMAUTH_SESSION_KEY_LEN) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKHSMAUTH_INS_CALCULATE;

  ptr = apdu.st.data;

  *(ptr++) = YKHSMAUTH_TAG_LABEL;
  ptr += encode_len(ptr, strlen(label));
  memcpy(ptr, label, strlen(label));
  ptr += strlen(label);

  *(ptr++) = YKHSMAUTH_TAG_CONTEXT;
  ptr += encode_len(ptr, context_len);
  memcpy(ptr, context, context_len);
  ptr += context_len;

  if (card_crypto_len > YKHSMAUTH_CARD_CRYPTO_LEN) {
    *(ptr++) = YKHSMAUTH_TAG_RESPONSE;
    ptr += encode_len(ptr, card_crypto_len);
    memcpy(ptr, card_crypto, card_crypto_len);
    ptr += card_crypto_len;
  }

  *(ptr++) = YKHSMAUTH_TAG_PW;
  ptr += encode_len(ptr, YKHSMAUTH_PW_LEN);
  memcpy(ptr, pw, pw_len);
  memset(ptr + pw_len, 0, YKHSMAUTH_PW_LEN - pw_len);
  ptr += YKHSMAUTH_PW_LEN;

  apdu.st.lc = ptr - apdu.st.data;

  rc = send_data(state, &apdu, data, &recv_len, &sw);
  if (rc != YKHSMAUTHR_SUCCESS) {
    return rc;
  } else if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to derive keys: %04x\n", sw);
    }

    return translate_error(sw, retries);
  }

  if (recv_len != 3 * YKHSMAUTH_SESSION_KEY_LEN &&
      recv_len != 3 * YKHSMAUTH_SESSION_KEY_LEN + YKHSMAUTH_HOST_CRYPTO_LEN) {
    if (state->verbose) {
      fprintf(stderr, "Wrong length returned: %lu\n", recv_len);
    }
    return YKHSMAUTHR_GENERIC_ERROR;
  }

  ptr = data;

  memcpy(key_s_enc, ptr, YKHSMAUTH_SESSION_KEY_LEN);
  ptr += YKHSMAUTH_SESSION_KEY_LEN;
  memcpy(key_s_mac, ptr, YKHSMAUTH_SESSION_KEY_LEN);
  ptr += YKHSMAUTH_SESSION_KEY_LEN;
  memcpy(key_s_rmac, ptr, YKHSMAUTH_SESSION_KEY_LEN);
  ptr += YKHSMAUTH_SESSION_KEY_LEN;

  // Ignore host crypto for now

  return YKHSMAUTHR_SUCCESS;
}

ykhsmauth_rc ykhsmauth_reset(ykhsmauth_state *state) {

  APDU apdu;
  unsigned char data[8];
  unsigned long recv_len = sizeof(data);
  int sw;
  ykhsmauth_rc res;

  if (state == NULL) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKHSMAUTH_INS_RESET;
  apdu.st.p1 = YKHSMAUTH_P1_RESET;
  apdu.st.p2 = YKHSMAUTH_P2_RESET;

  res = send_data(state, &apdu, data, &recv_len, &sw);
  if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to reset: %s\n", ykhsmauth_strerror(res));
    }

    return translate_error(sw, NULL);
  }

  return res;
}

ykhsmauth_rc ykhsmauth_list_keys(ykhsmauth_state *state,
                                 ykhsmauth_list_entry *list,
                                 size_t *list_items) {

  APDU apdu;
  unsigned char data[1024];
  unsigned long recv_len = sizeof(data);
  int sw;
  ykhsmauth_rc rc;

  if (state == NULL || list_items == NULL) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKHSMAUTH_INS_LIST;

  rc = send_data(state, &apdu, data, &recv_len, &sw);
  if (rc != YKHSMAUTHR_SUCCESS) {
    return rc;
  } else if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to list keys: %04x\n", sw);
    }

    return translate_error(sw, NULL);
  }

  size_t element = 0;
  size_t i = 0;

  // i + 1 here guarantees we can read tag and len
  while (i + 1 < recv_len) {
    if (data[i++] == YKHSMAUTH_TAG_LABEL_LIST) {
      size_t len = data[i++];
      if (list != NULL) {
        if (element >= *list_items) {
          return YKHSMAUTHR_MEMORY_ERROR;
        } else if (i + len > recv_len || len < 3 ||
                   len - 3 > sizeof(list[element].label)) {
          if (state->verbose) {
            fprintf(stderr,
                    "Length of element doesn't match expectations (%zu)\n",
                    len);
          }
          return YKHSMAUTHR_GENERIC_ERROR;
        }

        list[element].algo = data[i++];
        list[element].touch = data[i++];
        memset(list[element].label, 0, sizeof(list[element].label));
        memcpy(list[element].label, data + i, len - 3);
        i += len - 3;
        list[element].ctr = data[i++];
      } else {
        i += len;
      }
      element++;
    } else {
      if (state->verbose) {
        fprintf(stderr, "Unexpected tag returned on list\n");
      }
      return YKHSMAUTHR_GENERIC_ERROR;
    }
  }

  *list_items = element;

  if (i != recv_len) {
    return YKHSMAUTHR_GENERIC_ERROR;
  }

  return YKHSMAUTHR_SUCCESS;
}

ykhsmauth_rc ykhsmauth_get_challenge(ykhsmauth_state *state, const char *label,
                                     uint8_t *challenge,
                                     size_t *challenge_len) {

  APDU apdu;
  unsigned char data[256], *ptr;
  unsigned long recv_len = sizeof(data);
  int sw;
  ykhsmauth_rc rc;

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKHSMAUTH_INS_GET_CHALLENGE;

  ptr = apdu.st.data;

  *ptr++ = YKHSMAUTH_TAG_LABEL;
  ptr += encode_len(ptr, strlen(label));
  memcpy(ptr, label, strlen(label));
  ptr += strlen(label);

  apdu.st.lc = ptr - apdu.st.data;

  rc = send_data(state, &apdu, data, &recv_len, &sw);
  if (rc != YKHSMAUTHR_SUCCESS) {
    return rc;
  } else if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to get challenge: %04x\n", sw);
    }

    return translate_error(sw, NULL);
  }

  *challenge_len = recv_len;
  memcpy(challenge, data, recv_len);

  return YKHSMAUTHR_SUCCESS;
}

ykhsmauth_rc ykhsmauth_get_pubkey(ykhsmauth_state *state, const char *label,
                                  uint8_t *pubkey, size_t *pubkey_len) {

  APDU apdu;
  unsigned char data[256], *ptr;
  unsigned long recv_len = sizeof(data);
  int sw;
  ykhsmauth_rc rc;

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKHSMAUTH_INS_GET_PUBKEY;

  ptr = apdu.st.data;

  if (strlen(label)) {
    *ptr++ = YKHSMAUTH_TAG_LABEL;
    ptr += encode_len(ptr, strlen(label));
    memcpy(ptr, label, strlen(label));
    ptr += strlen(label);
  }

  apdu.st.lc = ptr - apdu.st.data;

  rc = send_data(state, &apdu, data, &recv_len, &sw);
  if (rc != YKHSMAUTHR_SUCCESS) {
    return rc;
  } else if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to get pubkey: %04x\n", sw);
    }

    return translate_error(sw, NULL);
  }

  *pubkey_len = recv_len;
  memcpy(pubkey, data, recv_len);

  return YKHSMAUTHR_SUCCESS;
}

ykhsmauth_rc ykhsmauth_get_mgmkey_retries(ykhsmauth_state *state,
                                          uint8_t *retries) {
  APDU apdu;
  unsigned char data[261];
  unsigned long recv_len = sizeof(data);
  int sw;
  ykhsmauth_rc rc;

  if (state == NULL || retries == NULL) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKHSMAUTH_INS_GET_MGMKEY_RETRIES;
  rc = send_data(state, &apdu, data, &recv_len, &sw);
  if (rc != YKHSMAUTHR_SUCCESS) {
    return rc;
  } else if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to get Management key retries: %04x\n", sw);
    }

    return translate_error(sw, NULL);
  }

  *retries = data[0];

  return YKHSMAUTHR_SUCCESS;
}

ykhsmauth_rc ykhsmauth_put_mgmkey(ykhsmauth_state *state, uint8_t *mgmkey,
                                  size_t mgmkey_len, uint8_t *new_mgmkey,
                                  size_t new_mgmkey_len, uint8_t *retries) {
  APDU apdu;
  uint8_t *ptr = apdu.st.data;
  unsigned char data[261];
  unsigned long recv_len = sizeof(data);
  int sw;

  if (state == NULL || mgmkey == NULL || mgmkey_len != YKHSMAUTH_PW_LEN ||
      new_mgmkey == NULL || new_mgmkey_len != YKHSMAUTH_PW_LEN) {
    return YKHSMAUTHR_INVALID_PARAMS;
  }

  memset(apdu.raw, 0, sizeof(apdu));
  apdu.st.ins = YKHSMAUTH_INS_PUT_MGMKEY;

  *(ptr++) = YKHSMAUTH_TAG_MGMKEY;
  *(ptr++) = 16;
  memcpy(ptr, mgmkey, 16);
  ptr += 16;

  *(ptr++) = YKHSMAUTH_TAG_MGMKEY;
  *(ptr++) = 16;
  memcpy(ptr, new_mgmkey, 16);
  ptr += 16;

  apdu.st.lc = ptr - apdu.st.data;

  ykhsmauth_rc rc = send_data(state, &apdu, data, &recv_len, &sw);
  if (rc != YKHSMAUTHR_SUCCESS) {
    return rc;
  } else if (sw != SW_SUCCESS) {
    if (state->verbose) {
      fprintf(stderr, "Unable to store Management key: %04x\n", sw);
    }

    return translate_error(sw, retries);
  }

  return YKHSMAUTHR_SUCCESS;
}
