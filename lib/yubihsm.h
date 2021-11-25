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

/**
 @mainpage

 @section Introduction

 Libyubihsm is a library for communicating with a YubiHSM 2 device.

 @section Usage

 To use the library, include <yubihsm.h> in the C code and pass the -lyubihsm
 flag to the linker.
 Debug output is controlled with the function #yh_set_verbosity().

 First step of using a YubiHSM 2 is to initialize the library with #yh_init(),
 initialize a connector with #yh_init_connector() and then connect it to the
 YubiHSM 2 with #yh_connect(). After this, a session must be established with
 #yh_create_session_derived(), #yh_create_session(),
 #yh_begin_create_session() + yh_finish_create_session().

 When a session is established, commands can be exchanged over it. The
 functions in the namespace yh_util are high-level convenience functions that do
 specific tasks with the device.

 @section api API Reference

 All public functions and definitions can be found in yubihsm.h

 @section example Code example

 Here is a small example of establishing a session with a YubiHSM 2 and fetching
 some pseudo random bytes before closing the session.

 \code{.c}
 int main(void) {
   yh_connector *connector = NULL;
   yh_session *session = NULL;
   uint8_t data[128] = {0};
   size_t data_len = sizeof(data);

   assert(yh_init() == YHR_SUCCESS);
   assert(yh_init_connector("http://localhost:12345", &connector)==YHR_SUCCESS);
   assert(yh_connect(connector, 0) == YHR_SUCCESS);
   assert(yh_create_session_derived(connector, 1, YH_DEFAULT_PASSWORD,
   strlen(YH_DEFAULT_PASSWORD), false, &session) == YHR_SUCCESS);
   assert(yh_util_get_pseudo_random(session, sizeof(data), data,
 &data_len)==YHR_SUCCESS);
   assert(data_len == sizeof(data));
   assert(yh_util_close_session(session) == YHR_SUCCESS);
   assert(yh_destroy_session(&session) == YHR_SUCCESS);
   assert(yh_disconnect(connector) == YHR_SUCCESS);
 }
 \endcode

 */

/** @file yubihsm.h
 *
 * Everything you need to establish a connection to the YubiHSM 2 and use its
 * functions.
 */

#ifndef YUBIHSM_H
#define YUBIHSM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/// Length of context array for authentication
#define YH_CONTEXT_LEN 16
/// Length of host challenge for authentication
#define YH_HOST_CHAL_LEN 8
/// Maximum length of message buffer
#define YH_MSG_BUF_SIZE 2048
/// Length of authentication keys
#define YH_KEY_LEN 16
/// Device vendor ID
#define YH_VID 0x1050
/// Device product ID
#define YH_PID 0x0030
/// Response flag for commands
#define YH_CMD_RESP_FLAG 0x80
/// Max items the device may hold
#define YH_MAX_ITEMS_COUNT 256
/// Max sessions the device may hold
#define YH_MAX_SESSIONS 16
/// Default encryption key
#define YH_DEFAULT_ENC_KEY                                                     \
  "\x09\x0b\x47\xdb\xed\x59\x56\x54\x90\x1d\xee\x1c\xc6\x55\xe4\x20"
/// Default MAC key
#define YH_DEFAULT_MAC_KEY                                                     \
  "\x59\x2f\xd4\x83\xf7\x59\xe2\x99\x09\xa0\x4c\x45\x05\xd2\xce\x0a"
/// Default authentication key password
#define YH_DEFAULT_PASSWORD "password"
/// Salt to be used for PBKDF2 key derivation
#define YH_DEFAULT_SALT "Yubico"
/// Number of iterations for PBKDF2 key derivation
#define YH_DEFAULT_ITERS 10000
/// Length of capabilities array
#define YH_CAPABILITIES_LEN 8
/// Max log entries the device may hold
#define YH_MAX_LOG_ENTRIES 64
/// Max length of object labels
#define YH_OBJ_LABEL_LEN 40
/// Max number of domains
#define YH_MAX_DOMAINS 16
/// Size that the log digest is truncated to
#define YH_LOG_DIGEST_SIZE 16
/// URL scheme used for direct USB access
#define YH_USB_URL_SCHEME "yhusb://"

// Debug levels
/// Debug level quiet. No messages printed out
#define YH_VERB_QUIET 0x00
/// Debug level intermediate. Intermediate results printed out
#define YH_VERB_INTERMEDIATE 0x01
/// Debug level crypto. Crypto results printed out
#define YH_VERB_CRYPTO 0x02
/// Debug level raw. Raw messages printed out
#define YH_VERB_RAW 0x04
/// Debug level info. General information messages printed out
#define YH_VERB_INFO 0x08
/// Debug level error. Error messages printed out
#define YH_VERB_ERR 0x10
/// Debug level all. All previous options enabled
#define YH_VERB_ALL 0xff

/// This is the overhead when doing aes-ccm wrapping: 1 byte identifier, 13
/// bytes nonce and 16 bytes mac
#define YH_CCM_WRAP_OVERHEAD (1 + 13 + 16)
#define YH_EC_P256_PRIVKEY_LEN 32
#define YH_EC_P256_PUBKEY_LEN 65

#ifdef __cplusplus
extern "C" {
#endif

/// Reference to a connector
typedef struct yh_connector yh_connector;

/// Reference to a session
typedef struct yh_session yh_session;

/// Capabilities representation
typedef struct {
  /// Capabilities is represented as an 8 byte uint8_t array
  uint8_t capabilities[YH_CAPABILITIES_LEN];
} yh_capabilities;

/**
 * Return codes.
 **/
typedef enum {
  /// Returned value when function was successful
  YHR_SUCCESS = 0,
  /// Returned value when unable to allocate memory
  YHR_MEMORY_ERROR = -1,
  /// Returned value when failing to initialize libyubihsm
  YHR_INIT_ERROR = -2,
  /// Returned value when a connection error was encountered
  YHR_CONNECTION_ERROR = -3,
  /// Returned value when failing to find a suitable connector
  YHR_CONNECTOR_NOT_FOUND = -4,
  /// Returned value when an argument to a function is invalid
  YHR_INVALID_PARAMETERS = -5,
  /// Returned value when there is a mismatch between expected and received
  /// length of an argument to a function
  YHR_WRONG_LENGTH = -6,
  /// Returned value when there is not enough space to store data
  YHR_BUFFER_TOO_SMALL = -7,
  /// Returned value when failing to verify cryptogram
  YHR_CRYPTOGRAM_MISMATCH = -8,
  /// Returned value when failing to authenticate the session
  YHR_SESSION_AUTHENTICATION_FAILED = -9,
  /// Returned value when failing to verify MAC
  YHR_MAC_MISMATCH = -10,
  /// Returned value when the device returned no error
  YHR_DEVICE_OK = -11,
  /// Returned value when the device receives and invalid command
  YHR_DEVICE_INVALID_COMMAND = -12,
  /// Returned value when the device receives a malformed command invalid data
  YHR_DEVICE_INVALID_DATA = -13,
  /// Returned value when the device session is invalid
  YHR_DEVICE_INVALID_SESSION = -14,
  /// Return value when the device fails to encrypt or verify the message
  YHR_DEVICE_AUTHENTICATION_FAILED = -15,
  /// Return value when no more sessions can be opened on the device
  YHR_DEVICE_SESSIONS_FULL = -16,
  /// Return value when failing to create a device session
  YHR_DEVICE_SESSION_FAILED = -17,
  /// Return value when encountering a storage failure on the device
  YHR_DEVICE_STORAGE_FAILED = -18,
  /// Return value when there is a mismatch between expected and received
  /// length of an argument to a function on the device
  YHR_DEVICE_WRONG_LENGTH = -19,
  /// Return value when the permissions to perform the operation are wrong
  YHR_DEVICE_INSUFFICIENT_PERMISSIONS = -20,
  /// Return value when the log buffer is full and forced audit is set
  YHR_DEVICE_LOG_FULL = -21,
  /// Return value when the object not found on the device
  YHR_DEVICE_OBJECT_NOT_FOUND = -22,
  /// Return value when an invalid Object ID is used
  YHR_DEVICE_INVALID_ID = -23,
  /// Return value when an invalid OTP is submitted
  YHR_DEVICE_INVALID_OTP = -24,
  /// Return value when the device is in demo mode and has to be power cycled
  YHR_DEVICE_DEMO_MODE = -25,
  /// Return value when the command execution has not terminated
  YHR_DEVICE_COMMAND_UNEXECUTED = -26,
  /// Return value when encountering an unknown error
  YHR_GENERIC_ERROR = -27,
  /// Return value when trying to add an object with an ID that already exists
  YHR_DEVICE_OBJECT_EXISTS = -28,
  /// Return value when connector operation failed
  YHR_CONNECTOR_ERROR = -29,
  /// Return value when encountering SSH CA constraint violation
  YHR_DEVICE_SSH_CA_CONSTRAINT_VIOLATION = -30,
  /// Return value when an algorithm is disabled
  YHR_DEVICE_ALGORITHM_DISABLED = -31,
} yh_rc;

/// Macro to define command and response command
#define ADD_COMMAND(c, v) c = v, c##_R = v | YH_CMD_RESP_FLAG

/**
 * Command definitions
 */
typedef enum {
  /// Echo data back from the device.
  ADD_COMMAND(YHC_ECHO, 0x01),
  /// Create a session with the device.
  ADD_COMMAND(YHC_CREATE_SESSION, 0x03),
  /// Authenticate the session to the device
  ADD_COMMAND(YHC_AUTHENTICATE_SESSION, 0x04),
  /// Send a command over an established session
  ADD_COMMAND(YHC_SESSION_MESSAGE, 0x05),
  /// Get device metadata
  ADD_COMMAND(YHC_GET_DEVICE_INFO, 0x06),
  /// Factory reset a device
  ADD_COMMAND(YHC_RESET_DEVICE, 0x08),
  /// Get the device pubkey for asym auth
  ADD_COMMAND(YHC_GET_DEVICE_PUBKEY, 0x0a),
  /// Close session
  ADD_COMMAND(YHC_CLOSE_SESSION, 0x40),
  /// Get storage information
  ADD_COMMAND(YHC_GET_STORAGE_INFO, 0x041),
  /// Import an Opaque Object into the device
  ADD_COMMAND(YHC_PUT_OPAQUE, 0x42),
  /// Get an Opaque Object from device
  ADD_COMMAND(YHC_GET_OPAQUE, 0x43),
  /// Import an Authentication Key into the device
  ADD_COMMAND(YHC_PUT_AUTHENTICATION_KEY, 0x44),
  /// Import an Asymmetric Key into the device
  ADD_COMMAND(YHC_PUT_ASYMMETRIC_KEY, 0x45),
  /// Generate an Asymmetric Key in the device
  ADD_COMMAND(YHC_GENERATE_ASYMMETRIC_KEY, 0x46),
  /// Sign data using RSA-PKCS#1v1.5
  ADD_COMMAND(YHC_SIGN_PKCS1, 0x47),
  /// List objects in the device
  ADD_COMMAND(YHC_LIST_OBJECTS, 0x48),
  /// Decrypt data that was encrypted using RSA-PKCS#1v1.5
  ADD_COMMAND(YHC_DECRYPT_PKCS1, 0x49),
  /// Get an Object under wrap from the device.
  ADD_COMMAND(YHC_EXPORT_WRAPPED, 0x4a),
  /// Import a wrapped Object into the device
  ADD_COMMAND(YHC_IMPORT_WRAPPED, 0x4b),
  /// Import a Wrap Key into the device
  ADD_COMMAND(YHC_PUT_WRAP_KEY, 0x4c),
  /// Get all current audit log entries from the device Log Store
  ADD_COMMAND(YHC_GET_LOG_ENTRIES, 0x4d),
  /// Get all metadata about an Object
  ADD_COMMAND(YHC_GET_OBJECT_INFO, 0x4e),
  /// Set a device-global options that affect general behavior
  ADD_COMMAND(YHC_SET_OPTION, 0x4f),
  /// Get a device-global option
  ADD_COMMAND(YHC_GET_OPTION, 0x50),
  /// Get a fixed number of pseudo-random bytes from the device
  ADD_COMMAND(YHC_GET_PSEUDO_RANDOM, 0x51),
  /// Import a HMAC key into the device
  ADD_COMMAND(YHC_PUT_HMAC_KEY, 0x52),
  /// Perform an HMAC operation in the device
  ADD_COMMAND(YHC_SIGN_HMAC, 0x53),
  /// Get the public key of an Asymmetric Key in the device
  ADD_COMMAND(YHC_GET_PUBLIC_KEY, 0x54),
  /// Sign data using RSA-PSS
  ADD_COMMAND(YHC_SIGN_PSS, 0x55),
  /// Sign data using ECDSA
  ADD_COMMAND(YHC_SIGN_ECDSA, 0x56),
  /// Perform an ECDH key exchange operation with a private key in the device
  ADD_COMMAND(YHC_DERIVE_ECDH, 0x57),
  /// Delete object in the device
  ADD_COMMAND(YHC_DELETE_OBJECT, 0x58),
  /// Decrypt data using RSA-OAEP
  ADD_COMMAND(YHC_DECRYPT_OAEP, 0x59),
  /// Generate an HMAC Key in the device
  ADD_COMMAND(YHC_GENERATE_HMAC_KEY, 0x5a),
  /// Generate a Wrap Key in the device
  ADD_COMMAND(YHC_GENERATE_WRAP_KEY, 0x5b),
  /// Verify a generated HMAC
  ADD_COMMAND(YHC_VERIFY_HMAC, 0x5c),
  /// Sign SSH certificate request
  ADD_COMMAND(YHC_SIGN_SSH_CERTIFICATE, 0x5d),
  /// Import a template into the device
  ADD_COMMAND(YHC_PUT_TEMPLATE, 0x5e),
  /// Get a template from the device
  ADD_COMMAND(YHC_GET_TEMPLATE, 0x5f),
  /// Decrypt a Yubico OTP
  ADD_COMMAND(YHC_DECRYPT_OTP, 0x60),
  /// Create a Yubico OTP AEAD
  ADD_COMMAND(YHC_CREATE_OTP_AEAD, 0x61),
  /// Generate an OTP AEAD from random data
  ADD_COMMAND(YHC_RANDOMIZE_OTP_AEAD, 0x62),
  /// Re-encrypt a Yubico OTP AEAD from one OTP AEAD Key to another OTP AEAD Key
  ADD_COMMAND(YHC_REWRAP_OTP_AEAD, 0x63),
  /// Get attestation of an Asymmetric Key
  ADD_COMMAND(YHC_SIGN_ATTESTATION_CERTIFICATE, 0x64),
  /// Import an OTP AEAD Key into the device
  ADD_COMMAND(YHC_PUT_OTP_AEAD_KEY, 0x65),
  /// Generate an OTP AEAD Key in the device
  ADD_COMMAND(YHC_GENERATE_OTP_AEAD_KEY, 0x66),
  /// Set the last extracted audit log entry
  ADD_COMMAND(YHC_SET_LOG_INDEX, 0x67),
  /// Encrypt (wrap) data using a Wrap Key
  ADD_COMMAND(YHC_WRAP_DATA, 0x68),
  /// Decrypt (unwrap) data using a Wrap Key
  ADD_COMMAND(YHC_UNWRAP_DATA, 0x69),
  /// Sign data using EdDSA
  ADD_COMMAND(YHC_SIGN_EDDSA, 0x6a),
  /// Blink the LED of the device
  ADD_COMMAND(YHC_BLINK_DEVICE, 0x6b),
  /// Replace the Authentication Key used to establish the current Session.
  ADD_COMMAND(YHC_CHANGE_AUTHENTICATION_KEY, 0x6c),
  /// The response byte returned from the device if the command resulted in an
  /// error
  YHC_ERROR = 0x7f,
} yh_cmd;

#undef ADD_COMMAND

/**
 * Object types
 *
 * @see <a
 * href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Objects</a>
 */
typedef enum {
  /// Opaque Object is an unchecked kind of Object, normally used to store
  /// raw data in the device
  YH_OPAQUE = 0x01,
  /// Authentication Key is used to establish Sessions with a device
  YH_AUTHENTICATION_KEY = 0x02,
  /// Asymmetric Key is the private key of an asymmetric key-pair
  YH_ASYMMETRIC_KEY = 0x03,
  /// Wrap Key is a secret key used to wrap and unwrap Objects during the
  /// export and import process
  YH_WRAP_KEY = 0x04,
  /// HMAC Key is a secret key used when computing and verifying HMAC signatures
  YH_HMAC_KEY = 0x05,
  /// Template is a binary object used for example to validate SSH certificate
  /// requests
  YH_TEMPLATE = 0x06,
  /// OTP AEAD Key is a secret key used to decrypt Yubico OTP values
  YH_OTP_AEAD_KEY = 0x07,
  /// Public Key is the public key of an asymmetric key-pair. The public key
  /// never exists in device and is mostly here for PKCS#11.
  YH_PUBLIC_KEY = 0x83,
} yh_object_type;

/// Max number of algorithms defined here
#define YH_MAX_ALGORITHM_COUNT 0xff
/**
 * Algorithms
 *
 * @see <a
 * href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Objects</a>
 */
typedef enum {
  /// rsa-pkcs1-sha1
  YH_ALGO_RSA_PKCS1_SHA1 = 1,
  /// rsa-pkcs1-sha256
  YH_ALGO_RSA_PKCS1_SHA256 = 2,
  /// rsa-pkcs1-sha384
  YH_ALGO_RSA_PKCS1_SHA384 = 3,
  /// rsa-pkcs1-sha512
  YH_ALGO_RSA_PKCS1_SHA512 = 4,
  /// rsa-pss-sha1
  YH_ALGO_RSA_PSS_SHA1 = 5,
  /// rsa-pss-sha256
  YH_ALGO_RSA_PSS_SHA256 = 6,
  /// rsa-pss-sha384
  YH_ALGO_RSA_PSS_SHA384 = 7,
  /// rsa-pss-sha512
  YH_ALGO_RSA_PSS_SHA512 = 8,
  /// rsa2048
  YH_ALGO_RSA_2048 = 9,
  /// rsa3072
  YH_ALGO_RSA_3072 = 10,
  /// rsa4096
  YH_ALGO_RSA_4096 = 11,
  /// ecp256
  YH_ALGO_EC_P256 = 12,
  /// ecp384
  YH_ALGO_EC_P384 = 13,
  /// ecp521
  YH_ALGO_EC_P521 = 14,
  /// eck256
  YH_ALGO_EC_K256 = 15,
  /// ecbp256
  YH_ALGO_EC_BP256 = 16,
  /// ecbp384
  YH_ALGO_EC_BP384 = 17,
  /// ecbp512
  YH_ALGO_EC_BP512 = 18,
  /// hmac-sha1
  YH_ALGO_HMAC_SHA1 = 19,
  /// hmac-sha256
  YH_ALGO_HMAC_SHA256 = 20,
  /// hmac-sha384
  YH_ALGO_HMAC_SHA384 = 21,
  /// hmac-sha512
  YH_ALGO_HMAC_SHA512 = 22,
  /// ecdsa-sha1
  YH_ALGO_EC_ECDSA_SHA1 = 23,
  /// ecdh
  YH_ALGO_EC_ECDH = 24,
  /// rsa-oaep-sha1
  YH_ALGO_RSA_OAEP_SHA1 = 25,
  /// rsa-oaep-sha256
  YH_ALGO_RSA_OAEP_SHA256 = 26,
  /// rsa-oaep-sha384
  YH_ALGO_RSA_OAEP_SHA384 = 27,
  /// rsa-oaep-sha512
  YH_ALGO_RSA_OAEP_SHA512 = 28,
  /// aes128-ccm-wrap
  YH_ALGO_AES128_CCM_WRAP = 29,
  /// opaque-data
  YH_ALGO_OPAQUE_DATA = 30,
  /// opaque-x509-certificate
  YH_ALGO_OPAQUE_X509_CERTIFICATE = 31,
  /// mgf1-sha1
  YH_ALGO_MGF1_SHA1 = 32,
  /// mgf1-sha256
  YH_ALGO_MGF1_SHA256 = 33,
  /// mgf1-sha384
  YH_ALGO_MGF1_SHA384 = 34,
  /// mgf1-sha512
  YH_ALGO_MGF1_SHA512 = 35,
  /// template-ssh
  YH_ALGO_TEMPLATE_SSH = 36,
  /// aes128-yubico-otp
  YH_ALGO_AES128_YUBICO_OTP = 37,
  /// aes128-yubico-authentication
  YH_ALGO_AES128_YUBICO_AUTHENTICATION = 38,
  /// aes192-yubico-otp
  YH_ALGO_AES192_YUBICO_OTP = 39,
  /// aes256-yubico-otp
  YH_ALGO_AES256_YUBICO_OTP = 40,
  /// aes192-ccm-wrap
  YH_ALGO_AES192_CCM_WRAP = 41,
  /// aes256-ccm-wrap
  YH_ALGO_AES256_CCM_WRAP = 42,
  /// ecdsa-sha256
  YH_ALGO_EC_ECDSA_SHA256 = 43,
  /// ecdsa-sha384
  YH_ALGO_EC_ECDSA_SHA384 = 44,
  /// ecdsa-sha512
  YH_ALGO_EC_ECDSA_SHA512 = 45,
  /// ed25519
  YH_ALGO_EC_ED25519 = 46,
  /// ecp224
  YH_ALGO_EC_P224 = 47,
  /// rsa-pkcs1-decrypt
  YH_ALGO_RSA_PKCS1_DECRYPT = 48,
  /// ec-p256-yubico-authentication
  YH_ALGO_EC_P256_YUBICO_AUTHENTICATION = 49,
} yh_algorithm;

/**
 * Global options
 */
typedef enum {
  /// Enable/Disable Forced Audit mode
  YH_OPTION_FORCE_AUDIT = 1,
  /// Enable/Disable logging of specific commands
  YH_OPTION_COMMAND_AUDIT = 3,
  /// Toggle algorithms on/off
  YH_OPTION_ALGORITHM_TOGGLE = 4,
  /// Fips mode on/off
  YH_OPTION_FIPS_MODE = 5,
} yh_option;

/**
 * Options for the connector, set with yh_set_connector_option()
 */
typedef enum {
  /// File with CA certificate to validate the connector with (const char *).
  /// Not implemented on Windows
  YH_CONNECTOR_HTTPS_CA = 1,
  /// Proxy server to use for connecting to the connector (const char *). Not
  /// implemented on Windows
  YH_CONNECTOR_PROXY_SERVER = 2,
  /// File with client certificate to authenticate client with (const char *).
  /// Not implemented on Windows
  YH_CONNECTOR_HTTPS_CERT = 3,
  /// File with client certificates key (const char *).
  /// Not implemented on Windows
  YH_CONNECTOR_HTTPS_KEY = 4,
  /// Comma separated list of hosts ignoring proxy, `*` to disable proxy.
  /// Not implemented on Windows
  YH_CONNECTOR_NOPROXY = 5,
} yh_connector_option;

#pragma pack(push, 1)
/**
 * Logging struct as returned by device
 *
 * @see <a
 * href="https://developers.yubico.com/YubiHSM2/Concepts/Logs.html">Objects</a>
 */
typedef struct {
  /// Monotonically increasing index
  uint16_t number;
  /// What command was executed @see yh_cmd
  uint8_t command;
  /// Length of in-data
  uint16_t length;
  /// ID of Authentication Key used
  uint16_t session_key;
  /// ID of first Object used
  uint16_t target_key;
  /// ID of second Object used
  uint16_t second_key;
  /// Command result @see yh_cmd
  uint8_t result;
  /// Systick at time of execution
  uint32_t systick;
  /// Truncated sha256 digest of this last digest + this entry
  uint8_t digest[YH_LOG_DIGEST_SIZE];
} yh_log_entry;

/**
 * Object descriptor
 */
typedef struct {
  /// Object capabilities @see yh_capabilities
  yh_capabilities capabilities;
  /// Object ID
  uint16_t id;
  /// Object length
  uint16_t len;
  /// Object domains
  uint16_t domains;
  /// Object type
  yh_object_type type;
  /// Object algorithm
  yh_algorithm algorithm;
  /// Object sequence
  uint8_t sequence;
  /// Object origin
  uint8_t origin;
  /// Object label. The label consists of raw bytes and is not restricted to
  /// printable characters or valid UTF-8 glyphs
  char label[YH_OBJ_LABEL_LEN + 1];
  /// Object delegated capabilities
  yh_capabilities delegated_capabilities;
} yh_object_descriptor;
#pragma pack(pop)

static const struct {
  const char *name;
  int bit;
} yh_capability[] = {
  {"change-authentication-key", 0x2e},
  {"create-otp-aead", 0x1e},
  {"decrypt-oaep", 0x0a},
  {"decrypt-otp", 0x1d},
  {"decrypt-pkcs", 0x09},
  {"delete-asymmetric-key", 0x29},
  {"delete-authentication-key", 0x28},
  {"delete-hmac-key", 0x2b},
  {"delete-opaque", 0x27},
  {"delete-otp-aead-key", 0x2d},
  {"delete-template", 0x2c},
  {"delete-wrap-key", 0x2a},
  {"derive-ecdh", 0x0b},
  {"export-wrapped", 0x0c},
  {"exportable-under-wrap", 0x10},
  {"generate-asymmetric-key", 0x04},
  {"generate-hmac-key", 0x15},
  {"generate-otp-aead-key", 0x24},
  {"generate-wrap-key", 0x0f},
  {"get-log-entries", 0x18},
  {"get-opaque", 0x00},
  {"get-option", 0x12},
  {"get-pseudo-random", 0x13},
  {"get-template", 0x1a},
  {"import-wrapped", 0x0d},
  {"put-asymmetric-key", 0x03},
  {"put-authentication-key", 0x02},
  {"put-mac-key", 0x14},
  {"put-opaque", 0x01},
  {"put-otp-aead-key", 0x23},
  {"put-template", 0x1b},
  {"put-wrap-key", 0x0e},
  {"randomize-otp-aead", 0x1f},
  {"reset-device", 0x1c},
  {"rewrap-from-otp-aead-key", 0x20},
  {"rewrap-to-otp-aead-key", 0x21},
  {"set-option", 0x11},
  {"sign-attestation-certificate", 0x22},
  {"sign-ecdsa", 0x07},
  {"sign-eddsa", 0x08},
  {"sign-hmac", 0x16},
  {"sign-pkcs", 0x05},
  {"sign-pss", 0x06},
  {"sign-ssh-certificate", 0x19},
  {"unwrap-data", 0x26},
  {"verify-hmac", 0x17},
  {"wrap-data", 0x25},
};

static const struct {
  const char *name;
  yh_algorithm algorithm;
} yh_algorithms[] = {
  {"aes128-ccm-wrap", YH_ALGO_AES128_CCM_WRAP},
  {"aes128-yubico-authentication", YH_ALGO_AES128_YUBICO_AUTHENTICATION},
  {"aes128-yubico-otp", YH_ALGO_AES128_YUBICO_OTP},
  {"aes192-ccm-wrap", YH_ALGO_AES192_CCM_WRAP},
  {"aes192-yubico-otp", YH_ALGO_AES192_YUBICO_OTP},
  {"aes256-ccm-wrap", YH_ALGO_AES256_CCM_WRAP},
  {"aes256-yubico-otp", YH_ALGO_AES256_YUBICO_OTP},
  {"ecbp256", YH_ALGO_EC_BP256},
  {"ecbp384", YH_ALGO_EC_BP384},
  {"ecbp512", YH_ALGO_EC_BP512},
  {"ecdh", YH_ALGO_EC_ECDH},
  {"ecdsa-sha1", YH_ALGO_EC_ECDSA_SHA1},
  {"ecdsa-sha256", YH_ALGO_EC_ECDSA_SHA256},
  {"ecdsa-sha384", YH_ALGO_EC_ECDSA_SHA384},
  {"ecdsa-sha512", YH_ALGO_EC_ECDSA_SHA512},
  {"eck256", YH_ALGO_EC_K256},
  {"ecp224", YH_ALGO_EC_P224},
  {"ecp256", YH_ALGO_EC_P256},
  {"ecp256-yubico-authentication", YH_ALGO_EC_P256_YUBICO_AUTHENTICATION},
  {"ecp384", YH_ALGO_EC_P384},
  {"ecp521", YH_ALGO_EC_P521},
  {"ed25519", YH_ALGO_EC_ED25519},
  {"hmac-sha1", YH_ALGO_HMAC_SHA1},
  {"hmac-sha256", YH_ALGO_HMAC_SHA256},
  {"hmac-sha384", YH_ALGO_HMAC_SHA384},
  {"hmac-sha512", YH_ALGO_HMAC_SHA512},
  {"mgf1-sha1", YH_ALGO_MGF1_SHA1},
  {"mgf1-sha256", YH_ALGO_MGF1_SHA256},
  {"mgf1-sha384", YH_ALGO_MGF1_SHA384},
  {"mgf1-sha512", YH_ALGO_MGF1_SHA512},
  {"opaque-data", YH_ALGO_OPAQUE_DATA},
  {"opaque-x509-certificate", YH_ALGO_OPAQUE_X509_CERTIFICATE},
  {"rsa-oaep-sha1", YH_ALGO_RSA_OAEP_SHA1},
  {"rsa-oaep-sha256", YH_ALGO_RSA_OAEP_SHA256},
  {"rsa-oaep-sha384", YH_ALGO_RSA_OAEP_SHA384},
  {"rsa-oaep-sha512", YH_ALGO_RSA_OAEP_SHA512},
  {"rsa-pkcs1-decrypt", YH_ALGO_RSA_PKCS1_DECRYPT},
  {"rsa-pkcs1-sha1", YH_ALGO_RSA_PKCS1_SHA1},
  {"rsa-pkcs1-sha256", YH_ALGO_RSA_PKCS1_SHA256},
  {"rsa-pkcs1-sha384", YH_ALGO_RSA_PKCS1_SHA384},
  {"rsa-pkcs1-sha512", YH_ALGO_RSA_PKCS1_SHA512},
  {"rsa-pss-sha1", YH_ALGO_RSA_PSS_SHA1},
  {"rsa-pss-sha256", YH_ALGO_RSA_PSS_SHA256},
  {"rsa-pss-sha384", YH_ALGO_RSA_PSS_SHA384},
  {"rsa-pss-sha512", YH_ALGO_RSA_PSS_SHA512},
  {"rsa2048", YH_ALGO_RSA_2048},
  {"rsa3072", YH_ALGO_RSA_3072},
  {"rsa4096", YH_ALGO_RSA_4096},
  {"template-ssh", YH_ALGO_TEMPLATE_SSH},
};

static const struct {
  const char *name;
  yh_object_type type;
} yh_types[] = {
  {"authentication-key", YH_AUTHENTICATION_KEY},
  {"asymmetric-key", YH_ASYMMETRIC_KEY},
  {"hmac-key", YH_HMAC_KEY},
  {"opaque", YH_OPAQUE},
  {"otp-aead-key", YH_OTP_AEAD_KEY},
  {"template", YH_TEMPLATE},
  {"wrap-key", YH_WRAP_KEY},
};

static const struct {
  const char *name;
  yh_option option;
} yh_options[] = {
  {"command-audit", YH_OPTION_COMMAND_AUDIT},
  {"force-audit", YH_OPTION_FORCE_AUDIT},
  {"algorithm-toggle", YH_OPTION_ALGORITHM_TOGGLE},
  {"fips-mode", YH_OPTION_FIPS_MODE},
};

/// The object was generated on the device
#define YH_ORIGIN_GENERATED 0x01
/// The object was imported into the device
#define YH_ORIGIN_IMPORTED 0x02
/// The object was imported into the device under wrap. This is used in
/// combination with objects original 'origin'
#define YH_ORIGIN_IMPORTED_WRAPPED 0x10

/**
 * Return a string describing an error condition
 *
 * @param err #yh_rc error code
 *
 * @return String with descriptive error
 **/
const char *yh_strerror(yh_rc err);

/**
 * Set verbosity level when executing commands. Default verbosity is
 *#YH_VERB_QUIET
 *
 * This function may be called prior to global library initialization to set
 * the debug level
 *
 * @param connector If not NULL, the verbosity of the specific connector will
 * be set
 * @param verbosity The desired level of debug output
 *
 * @return #YHR_SUCCESS
 *
 * @see YH_VERB_QUIET, YH_VERB_INTERMEDIATE, YH_VERB_CRYPTO, YH_VERB_RAW,
 * YH_VERB_INFO, YH_VERB_ERR, YH_VERB_ALL
 **/
yh_rc yh_set_verbosity(yh_connector *connector, uint8_t verbosity);

/**
 * Get verbosity level when executing commands
 *
 * @param verbosity The verbosity level
 *
 * @return #YHR_SUCCESS if seccessful.
 *         #YHR_INVALID_PARAMETERS if verbosity is NULL
 *
 * @see YH_VERB_QUIET, YH_VERB_INTERMEDIATE, YH_VERB_CRYPTO, YH_VERB_RAW,
 * YH_VERB_INFO, YH_VERB_ERR, YH_VERB_ALL
 **/
yh_rc yh_get_verbosity(uint8_t *verbosity);

/**
 * Set file for debug output
 *
 * @param connector If not NULL, the debug messages will be written to the
 *specified output file
 * @param output The destination of the debug messages
 *
 * @return void
 **/
void yh_set_debug_output(yh_connector *connector, FILE *output);

/**
 * Global library initialization
 *
 * @return #YHR_SUCCESS
 **/
yh_rc yh_init(void);

/**
 * Global library clean up
 *
 * @return #YHR_SUCCESS
 **/
yh_rc yh_exit(void);

/**
 * Instantiate a new connector
 *
 * @param url URL associated with this connector
 * @param connector Connector to the device
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if either the URL or the connector are NULL.
 *         #YHR_GENERIC_ERROR if failed to load the backend.
 *         #YHR_MEMORY_ERROR if failed to allocate memory for the connector.
 *         #YHR_CONNECTION_ERROR if failed to create the connector
 */
yh_rc yh_init_connector(const char *url, yh_connector **connector);

/**
 * Set connector options.
 *
 * Note that backend options are not supported with winhttp or USB connectors
 *
 * @param connector Connector to set an option on
 * @param opt Option to set. See #yh_connector_option
 * @param val Value of the option. Type of value is specific to the given
 *option
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the connector or the value are NULL or if
 *the option is unknown. #YHR_CONNECTOR_ERROR if failed to set the option
 **/
yh_rc yh_set_connector_option(yh_connector *connector, yh_connector_option opt,
                              const void *val);

/**
 * Connect to the device through the specified connector
 *
 * @param connector Connector to the device
 * @param timeout Connection timeout in seconds
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the connector does not exist.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_connect(yh_connector *connector, int timeout);

/**
 * Disconnect from a connector
 *
 * @param connector Connector from which to disconnect
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the connector is NULL
 **/
yh_rc yh_disconnect(yh_connector *connector);

/**
 * Send a plain (unencrypted) message to the device through a connector
 *
 * @param connector Connector to the device
 * @param cmd Command to send. See #yh_cmd
 * @param data Data to send
 * @param data_len length of data to send
 * @param response_cmd Response command
 * @param response Response data
 * @param response_len Length of response data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if the actual response was longer than
 *response_len. See #yh_rc for other possible errors
 **/
yh_rc yh_send_plain_msg(yh_connector *connector, yh_cmd cmd,
                        const uint8_t *data, size_t data_len,
                        yh_cmd *response_cmd, uint8_t *response,
                        size_t *response_len);

/**
 * Send an encrypted message to the device over a session. The session has to be
 *authenticated
 *
 * @param session Session to send the message over
 * @param cmd Command to send
 * @param data Data to send
 * @param data_len Length of data to send
 * @param response_cmd Response command
 * @param response Response data
 * @param response_len Length of response data
 *
 * @return #YHR_SUCCESS if successful. See #yh_rc for possible errors
 **/
yh_rc yh_send_secure_msg(yh_session *session, yh_cmd cmd, const uint8_t *data,
                         size_t data_len, yh_cmd *response_cmd,
                         uint8_t *response, size_t *response_len);

/**
 * Create a session that uses an encryption key and a MAC key derived from a
 *password
 *
 * @param connector Connector to the device
 * @param authkey_id Object ID of the Authentication Key used to authenticate
 *the session
 * @param password Password used to derive the session encryption key and MAC
 *key
 * @param password_len Length of the password in bytes
 * @param recreate_session If true, the session will be recreated if expired.
 *This caches the password in memory
 * @param session The created session
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the connector, the password or the session
 *are NULL. #YHR_GENERIC_ERROR if failed to derive the session encryption key
 *and/or the MAC key or if PRNG related errors occur. #YHR_MEMORY_ERROR if
 *failed to allocate memory for the session. See #yh_rc for other possible
 *errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>
 **/
yh_rc yh_create_session_derived(yh_connector *connector, uint16_t authkey_id,
                                const uint8_t *password, size_t password_len,
                                bool recreate_session, yh_session **session);

/**
 * Create a session that uses the specified encryption key and MAC key to derive
 *session-specific keys
 *
 * @param connector Connector to the device
 * @param authkey_id Object ID of the Authentication Key used to authenticate
 *the session
 * @param key_enc Key used to derive the session encryption key
 * @param key_enc_len Length of key_enc
 * @param key_mac Key used to derive the session MAC keys
 * @param key_mac_len Length of key_mac
 * @param recreate_session If true, the session will be recreated if expired.
 *This caches the password in memory
 * @param session created session
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or incorrect.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 **/
yh_rc yh_create_session(yh_connector *connector, uint16_t authkey_id,
                        const uint8_t *key_enc, size_t key_enc_len,
                        const uint8_t *key_mac, size_t key_mac_len,
                        bool recreate_session, yh_session **session);

yh_rc yh_util_load_client_auth_module(const char *module, FILE *out);

yh_rc yh_util_list_client_auth_providers(FILE *out);

yh_rc yh_util_list_client_auth_keys(FILE *out);

yh_rc yh_util_list_client_asym_auth_keys(FILE *out);

yh_rc yh_util_generate_auth_key(const char *key_name, uint8_t *key, size_t len);

yh_rc yh_util_generate_asym_auth_key(const char *key_name, uint8_t *key,
                                     size_t len);

yh_rc yh_util_destroy_auth_key(const char *key);

/**
 * Create a session that uses named encryption keys from a platform-specific key
 *store to derive session-specific keys
 *
 * @param connector Connector to the device
 * @param authkey_id Object ID of the Authentication Key used to authenticate
 *the session
 * @param key_enc_name Name of key used to derive the session encryption key
 * @param key_mac_name Name of key used to derive the session MAC keys
 * @param session created session
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or incorrect.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 **/
yh_rc yh_create_session_ex(yh_connector *connector, uint16_t authkey_id,
                           const char *key_enc_name, const char *key_mac_name,
                           yh_session **session);

/**
 * Begin creating a session where the session keys are calculated outside the
 *library.
 *
 * This function must be followed by yh_finish_create_session() to set the
 * session keys.
 *
 * If host_challenge_len is 0 when calling this function an 8 byte random
 *challenge is generated, and symmetric authentication is assumed.
 *
 * For asymmetric authentication the host challenge must be provided.
 *
 * @param connector Connector to the device
 * @param authkey_id Object ID of the Authentication Key used to authenticate
 *the session
 * @param context pointer to where context data is saved
 * @param host_challenge Host challenge
 * @param host_challenge_len Length of host challenge
 * @param card_cryptogram Card cryptogram from the device
 * @param card_cryptogram_len Length of card cryptogram
 * @param session created session
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_MEMORY_ERROR if failed to allocate memory for the session.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>
 **/
yh_rc yh_begin_create_session(yh_connector *connector, uint16_t authkey_id,
                              uint8_t **context, uint8_t *host_challenge,
                              size_t *host_challenge_len,
                              uint8_t *card_cryptogram,
                              size_t *card_cryptogram_len,
                              yh_session **session);

/**
 * Finish creating a session.
 *
 * This function must be called after yh_begin_create_session().
 *
 * For symmetric authentication this function will authenticate the session
 * with the device using the provided sesion keys and card cryptogram.
 *
 * For asymmetric authentication the card cryptogram must be validated
 *externally.
 *
 * @param session The session created with yh_begin_create_session()
 * @param key_senc Session encryption key used to encrypt the messages exchanged
 *with the device
 * @param key_senc_len Lenght of the encryption key. Must be #YH_KEY_LEN
 * @param key_smac Session MAC key used for creating the authentication tag for
 *each message
 * @param key_smac_len Length of the MAC key. Must be #YH_KEY_LEN
 * @param key_srmac Session return MAC key used for creating the authentication
 *tag for each response message
 * @param key_srmac_len Length of the return MAC key. Must be #YH_KEY_LEN
 * @param card_cryptogram Card cryptogram
 * @param card_cryptogram_len Length of card cryptogram
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or any of the
 *key lengths are not #YH_KEY_LEN.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>
 **/
yh_rc yh_finish_create_session(yh_session *session, const uint8_t *key_senc,
                               size_t key_senc_len, const uint8_t *key_smac,
                               size_t key_smac_len, const uint8_t *key_srmac,
                               size_t key_srmac_len, uint8_t *card_cryptogram,
                               size_t card_cryptogram_len);

/**
 * Utility function that gets the value and algorithm of the device public key
 *
 * @param connector Connector to the device
 * @param device_pubkey Value of the public key
 * @param device_pubkey_len Length of the public key in bytes
 * @param algorithm Algorithm of the key.
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if the actual key length was bigger than
 *device_pubkey_len. See #yh_rc for other possible errors
 **/
yh_rc yh_util_get_device_pubkey(yh_connector *connector, uint8_t *device_pubkey,
                                size_t *device_pubkey_len,
                                yh_algorithm *algorithm);

/**
 * Utility function that derives an ec-p256 key pair from a password using the
 *following algorithm
 *
 * 1. Apply pkcs5_pbkdf2_hmac-sha256 on the password to derive a pseudo-random
 *private ec-p256 key
 * 2. Check that the derived key is a valid ec-p256 private key
 * 3. If not valid append a byte with the value 1 (2, 3, 4 etc for additional
 *failures) to the password and go to step 1
 * 4. Calculate the corresponding public key from the private key and the
 *ec-p256 curve paramaters
 *
 * @param password The password bytes
 * @param password_len The password length
 * @param privkey Value of the private key
 * @param privkey_len Length of the private key in bytes
 * @param pubkey Value of the public key
 * @param pubkey_len Length of the public key in bytes
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL. See #yh_rc for
 *other possible errors
 **/
yh_rc yh_util_derive_ec_p256_key(const uint8_t *password, size_t password_len,
                                 uint8_t *privkey, size_t privkey_len,
                                 uint8_t *pubkey, size_t pubkey_len);

/**
 * Utility function that generates a random ec-p256 key pair
 *
 * @param privkey Value of the private key
 * @param privkey_len Length of the private key in bytes
 * @param pubkey Value of the public key
 * @param pubkey_len Length of the public key in bytes
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL. See #yh_rc for
 *other possible errors
 **/
yh_rc yh_util_generate_ec_p256_key(uint8_t *privkey, size_t privkey_len,
                                   uint8_t *pubkey, size_t pubkey_len);

/**
 * Create a session that uses the specified asymmetric key to derive
 *session-specific keys.
 *
 * @param connector Connector to the device
 * @param authkey_id Object ID of the Asymmetric Authentication Key used to
 *authenticate the session
 * @param privkey Private key of the client, used to derive the session
 *encryption key and authenticate the client
 * @param privkey_len Length of the private key.
 * @param device_pubkey Public key of the device, used to derive the session
 *encryption key and authenticate the device
 * @param device_pubkey_len Length of the device public key.
 * @param session created session
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or incorrect.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 **/
yh_rc yh_create_session_asym(yh_connector *connector, uint16_t authkey_id,
                             const uint8_t *privkey, size_t privkey_len,
                             const uint8_t *device_pubkey,
                             size_t device_pubkey_len, yh_session **session);

/**
 * Create a session that uses the specified asymmetric key to derive
 *session-specific keys.
 *
 * @param connector Connector to the device
 * @param authkey_id Object ID of the Asymmetric Authentication Key used to
 *authenticate the session
 * @param privkey Name of the private key of the client, used to derive the
 *session encryption key and authenticate the client
 * @param device_pubkey Public key of the device, used to derive the session
 *encryption key and authenticate the device
 * @param device_pubkey_len Length of the device public key.
 * @param session created session
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or incorrect.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 **/
yh_rc yh_create_session_asym_ex(yh_connector *connector, uint16_t authkey_id,
                                const char *privkey,
                                const uint8_t *device_pubkey,
                                size_t device_pubkey_len, yh_session **session);

/**
 * Free data associated with the session
 *
 * @param session Pointer to the session to destroy
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Session.html">Session</a>
 **/
yh_rc yh_destroy_session(yh_session **session);

/**
 * Deprecated, use yh_begin_create_session instead.
 **/
yh_rc yh_begin_create_session_ext(yh_connector *connector, uint16_t authkey_id,
                                  uint8_t **context, uint8_t *card_cryptogram,
                                  size_t card_cryptogram_len,
                                  yh_session **session);

/**
 * Deprecated, use yh_finish_create_session instead.
 **/
yh_rc yh_finish_create_session_ext(yh_connector *connector, yh_session *session,
                                   const uint8_t *key_senc, size_t key_senc_len,
                                   const uint8_t *key_smac, size_t key_smac_len,
                                   const uint8_t *key_srmac,
                                   size_t key_srmac_len,
                                   uint8_t *card_cryptogram,
                                   size_t card_cryptogram_len);

/**
 * Deprecated, calling this function has no effect.
 **/
yh_rc yh_authenticate_session(yh_session *session);

// Utility and convenience functions below

/**
 * Get device version, device serial number, supported algorithms and available
 *log entries.
 *
 * @param connector Connector to the device
 * @param major Device major version number
 * @param minor Device minor version number
 * @param patch Device build version number
 * @param serial Device serial number
 * @param log_total Total number of log entries
 * @param log_used Number of written log entries
 * @param algorithms List of supported algorithms
 * @param n_algorithms Number of supported algorithms
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the connector is NULL.
 *         #YHR_BUFFER_TOO_SMALL if n_algorithms is smaller than the number of
 *actually supported algorithms. See #yh_rc for other possible errors.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Algorithms</a>
 **/
yh_rc yh_util_get_device_info(yh_connector *connector, uint8_t *major,
                              uint8_t *minor, uint8_t *patch, uint32_t *serial,
                              uint8_t *log_total, uint8_t *log_used,
                              yh_algorithm *algorithms, size_t *n_algorithms);

/**
 * List objects accessible from the session
 *
 * @param session Authenticated session to use
 * @param id Object ID to filter by (0 to not filter by ID)
 * @param type Object type to filter by (0 to not filter by type). See
 *#yh_object_type
 * @param domains Domains to filter by (0 to not filter by domain)
 * @param capabilities Capabilities to filter by (0 to not filter by
 *capabilities). See #yh_capabilities
 * @param algorithm Algorithm to filter by (0 to not filter by algorithm)
 * @param label Label to filter by
 * @param objects Array of objects returned
 * @param n_objects Max number of objects (will be set to number found on
 *return)
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if n_objects is smaller than the number of
 *objects found. See #yh_rc for other possible errors.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Objects</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Domain.html">Domains</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capabilities</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Algorithms</a>,
 * <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Label.html">Labels</a>
 **/
yh_rc yh_util_list_objects(yh_session *session, uint16_t id,
                           yh_object_type type, uint16_t domains,
                           const yh_capabilities *capabilities,
                           yh_algorithm algorithm, const char *label,
                           yh_object_descriptor *objects, size_t *n_objects);

/**
 * Get metadata of the object with the specified Object ID and Type
 *
 * @param session Authenticated session to use
 * @param id Object ID of the object to get
 * @param type Object type. See #yh_object_type
 * @param object Object information
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         See #yh_rc for other possible errors.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Objects</a>
 **/
yh_rc yh_util_get_object_info(yh_session *session, uint16_t id,
                              yh_object_type type,
                              yh_object_descriptor *object);

/**
 * Get the value of the public key with the specified Object ID
 *
 * @param session Authenticated session to use
 * @param id Object ID of the public key
 * @param data Value of the public key
 * @param data_len Length of the public key in bytes
 * @param algorithm Algorithm of the key
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if the actual key length was bigger than
 *data_len. See #yh_rc for other possible errors
 **/
yh_rc yh_util_get_public_key(yh_session *session, uint16_t id, uint8_t *data,
                             size_t *data_len, yh_algorithm *algorithm);

/**
 * Close a session
 *
 * @param session Session to close
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_close_session(yh_session *session);

/**
 * Sign data using RSA-PKCS#1v1.5
 *
 * <tt>in</tt> is either a raw hashed message (sha1, sha256, sha384 or sha512)
 *or that with correct digestinfo pre-pended
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the signing key
 * @param hashed true if data is only hashed
 * @param in data to sign
 * @param in_len length of data to sign
 * @param out signed data
 * @param out_len length of signed data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is not 20, 34, 48 or 64. See #yh_rc for other possible errors
 **/
yh_rc yh_util_sign_pkcs1v1_5(yh_session *session, uint16_t key_id, bool hashed,
                             const uint8_t *in, size_t in_len, uint8_t *out,
                             size_t *out_len);

/**
 * Sign data using RSA-PSS
 *
 * <tt>in</tt> is a raw hashed message (sha1, sha256, sha384 or sha512)
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the signing key
 * @param in Data to sign
 * @param in_len Length of data to sign
 * @param out Signed data
 * @param out_len Length of signed data
 * @param salt_len Length of salt
 * @param mgf1Algo Algorithm for mgf1 (mask generation function for PSS)
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is not 20, 34, 48 or 64. See #yh_rc for other possible errors
 *
 * @see <a href="https://tools.ietf.org/html/rfc8017#section-9.1">PSS
 *specifications</a>
 **/
yh_rc yh_util_sign_pss(yh_session *session, uint16_t key_id, const uint8_t *in,
                       size_t in_len, uint8_t *out, size_t *out_len,
                       size_t salt_len, yh_algorithm mgf1Algo);

/**
 * Sign data using ECDSA
 *
 * <tt>in</tt> is a raw hashed message, a truncated hash to the curve length or
 *a padded hash to the curve length
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the signing key
 * @param in Data to sign
 * @param in_len Length of data to sign
 * @param out Signed data
 * @param out_len Length of signed data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is not 20, 28, 34, 48, 64 or 66. See #yh_rc for other possible
 *errors
 **/
yh_rc yh_util_sign_ecdsa(yh_session *session, uint16_t key_id,
                         const uint8_t *in, size_t in_len, uint8_t *out,
                         size_t *out_len);

/**
 * Sign data using EdDSA
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the signing key
 * @param in Data to sign
 * @param in_len Length of data to sign
 * @param out Signed data
 * @param out_len Length of signed data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is bigger than YH_MSG_BUF_SIZE-2. See #yh_rc for other
 *possible errors
 **/
yh_rc yh_util_sign_eddsa(yh_session *session, uint16_t key_id,
                         const uint8_t *in, size_t in_len, uint8_t *out,
                         size_t *out_len);

/**
 * Sign data using HMAC
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the signing key
 * @param in Data to HMAC
 * @param in_len Length of data to hmac
 * @param out HMAC
 * @param out_len Length of HMAC
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is bigger than YH_MSG_BUF_SIZE-2. See #yh_rc for other
 *possible errors
 **/
yh_rc yh_util_sign_hmac(yh_session *session, uint16_t key_id, const uint8_t *in,
                        size_t in_len, uint8_t *out, size_t *out_len);

/**
 * Get a fixed number of pseudo-random bytes from the device
 *
 * @param session Authenticated session to use
 * @param len Length of pseudo-random data to get
 * @param out Pseudo-random data out
 * @param out_len Length of pseudo-random data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_get_pseudo_random(yh_session *session, size_t len, uint8_t *out,
                                size_t *out_len);

/**
 * Import an RSA key into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID the key. 0 if Object ID should be generated by
 *the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs specified as an unsigned int.
 *See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the key to import. Must be one of:
 *#YH_ALGO_RSA_2048, #YH_ALGO_RSA_3072 or #YH_ALGO_RSA_4096
 * @param p P component of the RSA key to import
 * @param q Q component of the RSA key to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not one of #YH_ALGO_RSA_2048, #YH_ALGO_RSA_3072 or #YH_ALGO_RSA_4096. See
 *#yh_rc for other possible errors
 **/
yh_rc yh_util_import_rsa_key(yh_session *session, uint16_t *key_id,
                             const char *label, uint16_t domains,
                             const yh_capabilities *capabilities,
                             yh_algorithm algorithm, const uint8_t *p,
                             const uint8_t *q);

/**
 * Import an Elliptic Curve key into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be generated
 *by the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs specified as
 *an unsigned int. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the key to import. Must be one of:
 *#YH_ALGO_EC_P224, #YH_ALGO_EC_P256, #YH_ALGO_EC_K256, #YH_ALGO_EC_BP256,
 *#YH_ALGO_EC_P384, #YH_ALGO_EC_BP384, #YH_ALGO_EC_BP512 or #YH_ALGO_EC_P521
 * @param s the EC key to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not one of #YH_ALGO_EC_P224, #YH_ALGO_EC_P256, #YH_ALGO_EC_K256,
 *#YH_ALGO_EC_BP256, #YH_ALGO_EC_P384, #YH_ALGO_EC_BP384, #YH_ALGO_EC_BP512 or
 *#YH_ALGO_EC_P521.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_import_ec_key(yh_session *session, uint16_t *key_id,
                            const char *label, uint16_t domains,
                            const yh_capabilities *capabilities,
                            yh_algorithm algorithm, const uint8_t *s);

/**
 * Import an ED key into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key will have. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs.  See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the key to import. Must be #YH_ALGO_EC_ED25519
 * @param k the ED key to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not #YH_ALGO_EC_ED25519. See #yh_rc for other possible errors
 **/
yh_rc yh_util_import_ed_key(yh_session *session, uint16_t *key_id,
                            const char *label, uint16_t domains,
                            const yh_capabilities *capabilities,
                            yh_algorithm algorithm, const uint8_t *k);

/**
 * Import an HMAC key into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the key. Maxium length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the key to import. Must be one of:
 *#YH_ALGO_HMAC_SHA1, #YH_ALGO_HMAC_SHA256, #YH_ALGO_HMAC_SHA384
 *or #YH_ALGO_HMAC_SHA512
 * @param key The HMAC key to import
 * @param key_len Length of the HMAC key to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_import_hmac_key(yh_session *session, uint16_t *key_id,
                              const char *label, uint16_t domains,
                              const yh_capabilities *capabilities,
                              yh_algorithm algorithm, const uint8_t *key,
                              size_t key_len);

/**
 * Generate an RSA key in the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm to use to generate the RSA key. Supported
 *algorithms: #YH_ALGO_RSA_2048, #YH_ALGO_RSA_3072 and #YH_ALGO_RSA_4096
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not one of #YH_ALGO_RSA_2048, #YH_ALGO_RSA_3072 or #YH_ALGO_RSA_4096.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_generate_rsa_key(yh_session *session, uint16_t *key_id,
                               const char *label, uint16_t domains,
                               const yh_capabilities *capabilities,
                               yh_algorithm algorithm);

/**
 * Generate an Elliptic Curve key in the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be generated
 *by the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm to use to generate the EC key. Supported
 *algorithm: #YH_ALGO_EC_P224, #YH_ALGO_EC_P256, #YH_ALGO_EC_K256,
 *#YH_ALGO_EC_BP256, #YH_ALGO_EC_P384, #YH_ALGO_EC_BP384, #YH_ALGO_EC_BP512 and
 *#YH_ALGO_EC_P521.
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not one of #YH_ALGO_EC_P224, #YH_ALGO_EC_P256, #YH_ALGO_EC_K256,
 *#YH_ALGO_EC_BP256, #YH_ALGO_EC_P384, #YH_ALGO_EC_BP384, #YH_ALGO_EC_BP512 or
 *#YH_ALGO_EC_P521.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_generate_ec_key(yh_session *session, uint16_t *key_id,
                              const char *label, uint16_t domains,
                              const yh_capabilities *capabilities,
                              yh_algorithm algorithm);

/**
 * Generate an ED key in the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be generated
 *by the device
 * @param label Label for the key. Maximum length #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the ED key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm to use to generate the ED key. Supported
 *algorithm: #YH_ALGO_EC_ED25519
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or the algorithm is
 *not #YH_ALGO_EC_ED25519.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_generate_ed_key(yh_session *session, uint16_t *key_id,
                              const char *label, uint16_t domains,
                              const yh_capabilities *capabilities,
                              yh_algorithm algorithm);

/**
 * Verify a generated HMAC
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the HMAC key
 * @param signature HMAC signature (20, 32, 48 or 64 bytes)
 * @param signature_len length of HMAC signature
 * @param data data to verify
 * @param data_len length of data to verify
 * @param verified true if verification succeeded
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>signature_len</tt> + <tt>data_len</tt> is too long.
 *         See #yh_rc for other possible errors
 *
 **/
yh_rc yh_util_verify_hmac(yh_session *session, uint16_t key_id,
                          const uint8_t *signature, size_t signature_len,
                          const uint8_t *data, size_t data_len, bool *verified);

/**
 * Generate an HMAC key in the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the key. Maximum length #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm to use to generate the HMAC key. Supported
 *algorithims: #YH_ALGO_HMAC_SHA1, #YH_ALGO_HMAC_SHA256, #YH_ALGO_HMAC_SHA384
 *and #YH_ALGO_HMAC_SHA512
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL.
 *         See #yh_rc for other possible errors
 *
 **/
yh_rc yh_util_generate_hmac_key(yh_session *session, uint16_t *key_id,
                                const char *label, uint16_t domains,
                                const yh_capabilities *capabilities,
                                yh_algorithm algorithm);

/**
 * Decrypt data that was encrypted using RSA-PKCS#1v1.5
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the RSA key to use for decryption
 * @param in Encrypted data
 * @param in_len Length of encrypted data
 * @param out Decrypted data
 * @param out_len Length of decrypted data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is bigger than #YH_MSG_BUF_SIZE-2.
 *         See #yh_rc for other possible errors
 *
 **/
yh_rc yh_util_decrypt_pkcs1v1_5(yh_session *session, uint16_t key_id,
                                const uint8_t *in, size_t in_len, uint8_t *out,
                                size_t *out_len);

/**
 * Decrypt data using RSA-OAEP
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the RSA key to use for decryption
 * @param in Encrypted data
 * @param in_len Length of encrypted data. Must be 256, 384 or 512
 * @param out Decrypted data
 * @param out_len Length of decrypted data
 * @param label Hash of OAEP label. Hash function must be SHA-1, SHA-256,
 *SHA-384 or SHA-512
 * @param label_len Length of hash of OAEP label. Must be 20, 32, 48 or 64
 * @param mgf1Algo MGF1 algorithm
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL.
 *         #YHR_WRONG_LENGTH if <tt>in_len</tt> or <tt>label_len</tt> are not
 *what expected.
 *         See #yh_rc for other possible errors
 *
 **/
yh_rc yh_util_decrypt_oaep(yh_session *session, uint16_t key_id,
                           const uint8_t *in, size_t in_len, uint8_t *out,
                           size_t *out_len, const uint8_t *label,
                           size_t label_len, yh_algorithm mgf1Algo);

/**
 * Derive an ECDH key from a private EC key on the device and a provided public
 *EC key
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the EC private key to use for ECDH derivation
 * @param in Public key of another EC key-pair
 * @param in_len Length of public key
 * @param out Shared secret ECDH key
 * @param out_len Length of the shared ECDH key
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS input parameters are NULL or if
 *<tt>in_len</tt> is bigger than #YH_MSG_BUF_SIZE-2.
 *         See #yh_rc for other possible errors
 *
 **/
yh_rc yh_util_derive_ecdh(yh_session *session, uint16_t key_id,
                          const uint8_t *in, size_t in_len, uint8_t *out,
                          size_t *out_len);

/**
 * Delete an object in the device
 *
 * @param session Authenticated session to use
 * @param id Object ID of the object to delete
 * @param type Type of object to delete. See #yh_object_type
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if session is NULL.
 *         See #yh_rc for other possible errors
 *
 **/
yh_rc yh_util_delete_object(yh_session *session, uint16_t id,
                            yh_object_type type);

/**
 * Export an object under wrap from the device
 *
 * @param session Authenticated session to use
 * @param wrapping_key_id Object ID of the Wrap Key to use to wrap the object
 * @param target_type Type of the object to be exported. See #yh_object_type
 * @param target_id Object ID of the object to be exported
 * @param out Wrapped data
 * @param out_len Length of wrapped data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_export_wrapped(yh_session *session, uint16_t wrapping_key_id,
                             yh_object_type target_type, uint16_t target_id,
                             uint8_t *out, size_t *out_len);

/**
 * Import a wrapped object into the device. The object should have been
 *previously exported by #yh_util_export_wrapped()
 *
 * @param session Authenticated session to use
 * @param wrapping_key_id Object ID of the Wrap Key to use to unwrap the object
 * @param in Wrapped data
 * @param in_len Length of wrapped data
 * @param target_type Type of the imported object
 * @param target_id Object ID of the imported object
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_import_wrapped(yh_session *session, uint16_t wrapping_key_id,
                             const uint8_t *in, size_t in_len,
                             yh_object_type *target_type, uint16_t *target_id);

/**
 * Import a Wrap Key into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID the Wrap Key. 0 if the Object ID should be generated
 *by the device
 * @param label Label of the Wrap Key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains where the Wrap Key will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the Wrap Key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the Wrap Key. Supported algorithms:
 *#YH_ALGO_AES128_CCM_WRAP, #YH_ALGO_AES192_CCM_WRAP and
 *#YH_ALGO_AES256_CCM_WRAP
 * @param delegated_capabilities Delegated capabilities of the Wrap Key. See
 *#yh_string_to_capabilities()
 * @param in the Wrap Key to import
 * @param in_len Length of the Wrap Key to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL, <tt>in_len</tt>
 *is not what expected based on the algorithm and if the algorithms is not one
 *of #YH_ALGO_AES128_CCM_WRAP, #YH_ALGO_AES192_CCM_WRAP or
 *#YH_ALGO_AES256_CCM_WRAP.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_import_wrap_key(yh_session *session, uint16_t *key_id,
                              const char *label, uint16_t domains,
                              const yh_capabilities *capabilities,
                              yh_algorithm algorithm,
                              const yh_capabilities *delegated_capabilities,
                              const uint8_t *in, size_t in_len);

/**
 * Generate a Wrap Key that can be used for export, import, wrap data and unwrap
 *data in the device.
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Wrap Key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the Wrap Key. Maximum length #YH_OBJ_LABEL_LEN
 * @param domains Domains where the Wrap Key will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the Wrap Key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm used to generate the Wrap Key
 * @param delegated_capabilities Delegated capabilitites of the Wrap Key. See
 *#yh_string_to_capabilities()
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 *
 * @see yh_object_type
 **/
yh_rc yh_util_generate_wrap_key(yh_session *session, uint16_t *key_id,
                                const char *label, uint16_t domains,
                                const yh_capabilities *capabilities,
                                yh_algorithm algorithm,
                                const yh_capabilities *delegated_capabilities);

/**
 * Get audit logs from the device.
 *
 * When audit enforce is set, if the log buffer is full, no new operations
 *(other than authentication operations) can be performed unless the log entries
 *are read by this command and then the log index is set by calling
 *#yh_util_set_log_index().
 *
 * @param session Authenticated session to use
 * @param unlogged_boot Number of unlogged boot events. Used if the log buffer
 *is full and audit enforce is set
 * @param unlogged_auth Number of unlogged authentication events. Used if the
 *log buffer is full and audit enforce is set
 * @param out Log entries on the device
 * @param n_items Number of log entries
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if <tt>n_items</tt> is smaller than the actual
 *number of retrieved log entries.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_get_log_entries(yh_session *session, uint16_t *unlogged_boot,
                              uint16_t *unlogged_auth, yh_log_entry *out,
                              size_t *n_items);

/**
 * Set the index of the last extracted log entry.
 *
 * This function should be called after #yh_util_get_log_entries() to inform the
 *device what the last extracted log entry is so new logs can be written. This
 *is used when forced auditing is enabled.
 *
 * @param session Authenticated session to use
 * @param index index to set. Should be the same index as the last entry
 *extracted using #yh_util_get_log_entries()
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_set_log_index(yh_session *session, uint16_t index);

/**
 * Get an #YH_OPAQUE object (like an X.509 certificate) from the device
 *
 * @param session Authenticated session to use
 * @param object_id Object ID of the Opaque object
 * @param out the retrieved Opaque object
 * @param out_len Length of the retrieved Opaque object
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_get_opaque(yh_session *session, uint16_t object_id, uint8_t *out,
                         size_t *out_len);

/**
 * Import an #YH_OPAQUE object into the device
 *
 * @param session Authenticated session to use
 * @param object_id Object ID of the Opaque object. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the Opaque object. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains the Opaque object will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the Opaque object. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm of the Opaque object
 * @param in the Opaque object to import
 * @param in_len Length of the Opaque object to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or
 *<tt>in_len</tt> is too big.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_import_opaque(yh_session *session, uint16_t *object_id,
                            const char *label, uint16_t domains,
                            const yh_capabilities *capabilities,
                            yh_algorithm algorithm, const uint8_t *in,
                            size_t in_len);

/**
 * Sign an SSH Certificate request. The function produces a signature that can
 *then be used to produce the SSH Certificate
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key used to sign the request
 * @param template_id Object ID of the template to use as a certificate template
 * @param sig_algo Signature algorithm to use to sign the certificate request
 * @param in Certificate request
 * @param in_len Length of the certificate request
 * @param out Signature
 * @param out_len Length of the signature
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or
 *<tt>in_len</tt> is too big.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_sign_ssh_certificate(yh_session *session, uint16_t key_id,
                                   uint16_t template_id, yh_algorithm sig_algo,
                                   const uint8_t *in, size_t in_len,
                                   uint8_t *out, size_t *out_len);

/**
 * Import an #YH_AUTHENTICATION_KEY into the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the imported key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See #yh_string_to_capabilities()
 * @param delegated_capabilities Delegated capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param key_enc Long lived encryption key of the Authentication Key to import
 * @param key_enc_len Length of the encryption key. Must be #YH_KEY_LEN
 * @param key_mac Long lived MAC key of the Authentication Key to import
 * @param key_mac_len Length of the MAC key. Must be #YH_KEY_LEN
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>key_enc_len</tt> or <tt>key_mac_len</tt> are not the expected values.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 **/
yh_rc yh_util_import_authentication_key(
  yh_session *session, uint16_t *key_id, const char *label, uint16_t domains,
  const yh_capabilities *capabilities,
  const yh_capabilities *delegated_capabilities, const uint8_t *key_enc,
  size_t key_enc_len, const uint8_t *key_mac, size_t key_mac_len);

/**
 * Import an #YH_AUTHENTICATION_KEY with long lived keys derived from a password
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key. 0 if the Object ID should be generated by
 *the device
 * @param label Label of the key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains to which the key belongs. See #yh_string_to_domains()
 * @param capabilities Capabilities of the key. See #yh_string_to_capabilities()
 * @param delegated_capabilities Delegated capabilities of the key. See
 *#yh_string_to_capabilities()
 * @param password Password used to derive the long lived encryption key and MAC
 *key of the Athentication Key
 * @param password_len Length of password
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 **/
yh_rc yh_util_import_authentication_key_derived(
  yh_session *session, uint16_t *key_id, const char *label, uint16_t domains,
  const yh_capabilities *capabilities,
  const yh_capabilities *delegated_capabilities, const uint8_t *password,
  size_t password_len);

/**
 * Replace the long lived encryption key and MAC key associated with an
 *#YH_AUTHENTICATION_KEY in the device
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key to replace
 * @param key_enc New long lived encryption key
 * @param key_enc_len Length of the new encryption key. Must be #YH_KEY_LEN
 * @param key_mac New long lived MAC key
 * @param key_mac_len Length of the new MAC key. Must be #YH_KEY_LEN
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>key_enc_len</tt> or <tt>key_mac_len</tt> are not the expected values.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 **/
yh_rc yh_util_change_authentication_key(yh_session *session, uint16_t *key_id,
                                        const uint8_t *key_enc,
                                        size_t key_enc_len,
                                        const uint8_t *key_mac,
                                        size_t key_mac_len);

/**
 * Replace the long lived encryption key and MAC key associated with an
 *#YH_AUTHENTICATION_KEY in the device with keys derived from a password
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key to replace
 * @param password Password to derive the new encryption key and MAC key
 * @param password_len Length of password
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Authentication
 *Key</a>
 *
 **/
yh_rc yh_util_change_authentication_key_derived(yh_session *session,
                                                uint16_t *key_id,
                                                const uint8_t *password,
                                                size_t password_len);

/**
 * Get a #YH_TEMPLATE object from the device
 *
 * @param session Authenticated session to use
 * @param object_id Object ID of the Template to get
 * @param out The retrieved Template
 * @param out_len Length of the retrieved Template
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_get_template(yh_session *session, uint16_t object_id,
                           uint8_t *out, size_t *out_len);

/**
 * Import a #YH_TEMPLATE object into the device
 *
 * @param session Authenticated session to use
 * @param object_id Object ID of the Template. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the Template. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains the Template will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the Template. See
 *#yh_string_to_capabilities
 * @param algorithm Algorithm of the Template
 * @param in Template to import
 * @param in_len Length of the Template to import
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>in_len</tt> is too big.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_import_template(yh_session *session, uint16_t *object_id,
                              const char *label, uint16_t domains,
                              const yh_capabilities *capabilities,
                              yh_algorithm algorithm, const uint8_t *in,
                              size_t in_len);

/**
 * Create a Yubico OTP AEAD using the provided data
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Otp-aead Key to use
 * @param key OTP key
 * @param private_id OTP private id
 * @param out The created AEAD
 * @param out_len Length of the created AEAD
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_create_otp_aead(yh_session *session, uint16_t key_id,
                              const uint8_t *key, const uint8_t *private_id,
                              uint8_t *out, size_t *out_len);

/**
 * Create OTP AEAD from random data
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Otp-aead Key to use
 * @param out The created AEAD
 * @param out_len Length of the created AEAD
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_randomize_otp_aead(yh_session *session, uint16_t key_id,
                                 uint8_t *out, size_t *out_len);

/**
 * Decrypt a Yubico OTP and return counters and time information.
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the key used for decryption
 * @param aead AEAD as created by #yh_util_create_otp_aead() or
 *#yh_util_randomize_otp_aead()
 * @param aead_len Length of AEAD
 * @param otp OTP
 * @param useCtr OTP use counter
 * @param sessionCtr OTP session counter
 * @param tstph OTP timestamp high
 * @param tstpl OTP timestamp low
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_decrypt_otp(yh_session *session, uint16_t key_id,
                          const uint8_t *aead, size_t aead_len,
                          const uint8_t *otp, uint16_t *useCtr,
                          uint8_t *sessionCtr, uint8_t *tstph, uint16_t *tstpl);

/**
 * Rewrap an OTP AEAD from one #YH_OTP_AEAD_KEY to another.
 *
 * @param session Authenticated session to use
 * @param id_from Object ID of the AEAD Key to wrap from.
 * @param id_to Object ID of the AEAD Key to wrap to.
 * @param aead_in AEAD to unwrap
 * @param in_len Length of AEAD
 * @param aead_out The created AEAD
 * @param out_len Length of output AEAD
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/

yh_rc yh_util_rewrap_otp_aead(yh_session *session, uint16_t id_from,
                              uint16_t id_to, const uint8_t *aead_in,
                              size_t in_len, uint8_t *aead_out,
                              size_t *out_len);

/**
 * Import an #YH_OTP_AEAD_KEY used for Yubico OTP Decryption
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the AEAD Key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the AEAD Key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains the AEAD Key will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the AEAD Key. See
 *#yh_string_to_capabilities()
 * @param nonce_id Nonce ID
 * @param in AEAD Key to import
 * @param in_len Length of AEAD Key to import. Must be 16, 24 or 32
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>in_len</tt> is not one of 16, 24 or 32.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_import_otp_aead_key(yh_session *session, uint16_t *key_id,
                                  const char *label, uint16_t domains,
                                  const yh_capabilities *capabilities,
                                  uint32_t nonce_id, const uint8_t *in,
                                  size_t in_len);

/**
 * Generate an #YH_OTP_AEAD_KEY for Yubico OTP decryption in the device.
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the AEAD Key. 0 if the Object ID should be
 *generated by the device
 * @param label Label of the AEAD Key. Maximum length is #YH_OBJ_LABEL_LEN
 * @param domains Domains the AEAD Key will be operating within. See
 *#yh_string_to_domains()
 * @param capabilities Capabilities of the AEAD Key. See
 *#yh_string_to_capabilities()
 * @param algorithm Algorithm used to generate the AEAD Key. Supported
 *algorithms: #YH_ALGO_AES128_YUBICO_OTP, #YH_ALGO_AES192_YUBICO_OTP and
 *#YH_ALGO_AES256_YUBICO_OTP
 * @param nonce_id Nonce ID
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_generate_otp_aead_key(yh_session *session, uint16_t *key_id,
                                    const char *label, uint16_t domains,
                                    const yh_capabilities *capabilities,
                                    yh_algorithm algorithm, uint32_t nonce_id);

/**
 * Get attestation of an Asymmetric Key in the form of an X.509 certificate
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Asymmetric Key to attest
 * @param attest_id Object ID for the key used to sign the attestation
 *certificate
 * @param out The attestation certificate
 * @param out_len Length of the attestation certificate
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_sign_attestation_certificate(yh_session *session, uint16_t key_id,
                                           uint16_t attest_id, uint8_t *out,
                                           size_t *out_len);

/**
 * Set a device-global option
 *
 * @param session Authenticated session to use
 * @param option Option to set. See #yh_option
 * @param len Length of option value
 * @param val Option value
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if <tt>session</tt> or <tt>val</tt> are NULL
 *or if <tt>len</tt> is too long.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_set_option(yh_session *session, yh_option option, size_t len,
                         uint8_t *val);

/**
 * Get a device-global option
 *
 * @param session Authenticated session to use
 * @param option Option to get. See #yh_option
 * @param out Option value
 * @param out_len Length of option value
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_get_option(yh_session *session, yh_option option, uint8_t *out,
                         size_t *out_len);

/**
 * Report currently free storage. This is reported as free records, free pages
 *and page size.
 *
 * @param session Authenticated session to use
 * @param total_records Total number of records
 * @param free_records Number of free records
 * @param total_pages Total number of pages
 * @param free_pages Number of free pages
 * @param page_size Page size in bytes
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_get_storage_info(yh_session *session, uint16_t *total_records,
                               uint16_t *free_records, uint16_t *total_pages,
                               uint16_t *free_pages, uint16_t *page_size);

/**
 * Encrypt (wrap) data using a #YH_WRAP_KEY.
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Wrap Key to use
 * @param in Data to wrap
 * @param in_len Length of data to wrap
 * @param out Wrapped data
 * @param out_len Length of the wrapped data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>in_len</tt> is too big.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_wrap_data(yh_session *session, uint16_t key_id, const uint8_t *in,
                        size_t in_len, uint8_t *out, size_t *out_len);

/**
 * Decrypt (unwrap) data using a #YH_WRAP_KEY.
 *
 * @param session Authenticated session to use
 * @param key_id Object ID of the Wrap Key to use
 * @param in Wrapped data
 * @param in_len Length of wrapped data
 * @param out Unwrapped data
 * @param out_len Length of unwrapped data
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if
 *<tt>in_len</tt> is too big.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_unwrap_data(yh_session *session, uint16_t key_id,
                          const uint8_t *in, size_t in_len, uint8_t *out,
                          size_t *out_len);

/**
 * Blink the LED of the device to identify it
 *
 * @param session Authenticated session to use
 * @param seconds Number of seconds to blink
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_blink_device(yh_session *session, uint8_t seconds);

/**
 * Factory reset the device. Resets and reboots the device, deletes all Objects
 *and restores the default #YH_AUTHENTICATION_KEY.
 *
 * @param session Authenticated session to use
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if the session is NULL.
 *         See #yh_rc for other possible errors
 **/
yh_rc yh_util_reset_device(yh_session *session);

/**
 * Get the session ID
 *
 * @param session Authenticated session to use
 * @param sid Session ID
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 **/
yh_rc yh_get_session_id(yh_session *session, uint8_t *sid);

/**
 * Check if the connector has a device connected
 *
 * @param connector Connector currently in use
 *
 * @return True if the connector is not NULL and there is a device connected to
 *it. False otherwise
 **/
bool yh_connector_has_device(yh_connector *connector);

/**
 * Get the connector version
 *
 * @param connector Connector currently in use
 * @param major Connector major version
 * @param minor Connector minor version
 * @param patch Connector patch version
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 **/
yh_rc yh_get_connector_version(yh_connector *connector, uint8_t *major,
                               uint8_t *minor, uint8_t *patch);

/**
 * Get connector address
 *
 * @param connector Connector currently in use
 * @param address Pointer to the connector address as string
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 **/
yh_rc yh_get_connector_address(yh_connector *connector, char **const address);

/**
 * Convert capability string to byte array
 *
 * @param capability String of capabilities separated by ',', ':' or '|'
 * @param result Array of #yh_capabilities
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if <tt>capability</tt> is too big
 *
 * @par Examples:
 *
 *  * "get-opaque" => {"\x00\x00\x00\x00\x00\x00\x00\x01"}
 *  * "sign-hmac:verify-hmac|exportable-under-wrap," =>
 *{"\x00\x00\x00\x00\x00\xc1\x00\x00"}
 *  * ",,unwrap-data|:wrap-data,,," => {"\x00\x00\x00\x60\x00\x00\x00\x00"}
 *  * "0x7fffffffffffffff" => {"\x7f\xff\xff\xff\xff\xff\xff\xff"}
 *  * "0xffffffffffffffff" => {"\xff\xff\xff\xff\xff\xff\xff\xff"}
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capability</a>
 **/
yh_rc yh_string_to_capabilities(const char *capability,
                                yh_capabilities *result);

/**
 * Convert an array of #yh_capabilities into strings separated by ','
 *
 * @param num Array of #yh_capabilities
 * @param result Array of the capabilies as strings
 * @param n_result Number of elements in result
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *         #YHR_BUFFER_TOO_SMALL if <tt>n_result</tt> is too small
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capability</a>
 **/
yh_rc yh_capabilities_to_strings(const yh_capabilities *num,
                                 const char *result[], size_t *n_result);

/**
 * Check if a capability is set
 *
 * @param capabilities Array of #yh_capabilities
 * @param capability Capability to check as a string.
 *
 * @return True if the <tt>capability</tt> is in <tt>capabilities</tt>. False
 *otherwise
 *
 * @par Code sample
 *
 *     char *capabilities_str = "sign-pkcs,decrypt-pkcs,set-option";
 *     yh_capabilities capabilities = {{0}};
 *     yh_string_to_capabilities(capabilities_str, &capabilities);
 *     //yh_check_capability(&capabilities, "something") => false
 *     //yh_check_capability(&capabilities, "sign-pss") => false
 *     //yh_check_capability(&capabilities, "decrypt-pkcs") => true
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capability</a>
 **/
bool yh_check_capability(const yh_capabilities *capabilities,
                         const char *capability);

/**
 * Merge two sets of capabilities. The resulting set of capabilities contain all
 *capabilities from both arrays
 *
 * @param a Array of #yh_capabilities
 * @param b Array of #yh_capabilities
 * @param result Resulting array of #yh_capabilities
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capability</a>
 **/
yh_rc yh_merge_capabilities(const yh_capabilities *a, const yh_capabilities *b,
                            yh_capabilities *result);

/**
 * Filter one set of capabilities with another. The resulting set of
 *capabilities contains only the capabilities that exist in both sets of input
 *capabilities
 *
 * @param capabilities Array of #yh_capabilities
 * @param filter Array of #yh_capabilities
 * @param result Resulting array of #yh_capabilities
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Capability.html">Capability</a>
 **/
yh_rc yh_filter_capabilities(const yh_capabilities *capabilities,
                             const yh_capabilities *filter,
                             yh_capabilities *result);

/**
 * Check if an algorithm is a supported RSA algorithm.
 *
 * Supported RSA algorithms: #YH_ALGO_RSA_2048, #YH_ALGO_RSA_3072 and
 *#YH_ALGO_RSA_4096
 *
 * @param algorithm Algorithm to check. See #yh_algorithm
 *
 * @return True if the algorithm is one of the supported RSA algorithms . False
 *otherwise
 **/
bool yh_is_rsa(yh_algorithm algorithm);

/**
 * Check if an algorithm is a supported Elliptic Curve algorithm.
 *
 * Supported EC algorithms: #YH_ALGO_EC_P224, #YH_ALGO_EC_P256,
 *#YH_ALGO_EC_P384, #YH_ALGO_EC_P521, #YH_ALGO_EC_K256, #YH_ALGO_EC_BP256,
 *#YH_ALGO_EC_BP384 and #YH_ALGO_EC_BP512
 *
 * @param algorithm Algorithm to check. See #yh_algorithm
 *
 * @return True if the algorithm is one of the supported EC algorithms. False
 *otherwise
 **/
bool yh_is_ec(yh_algorithm algorithm);

/**
 * Check if an algorithm is a supported ED algorithm.
 *
 * Supported ED algorithms: #YH_ALGO_EC_ED25519
 *
 * @param algorithm algorithm. See #yh_algorithm
 *
 * @return True if the algorithm is #YH_ALGO_EC_ED25519. False otherwise
 **/
bool yh_is_ed(yh_algorithm algorithm);

/**
 * Check if algorithm is a supported HMAC algorithm.
 *
 * Supported HMAC algorithms: #YH_ALGO_HMAC_SHA1, #YH_ALGO_HMAC_SHA256,
 *#YH_ALGO_HMAC_SHA384 and #YH_ALGO_HMAC_SHA512
 *
 * @param algorithm Algorithm to check. See #yh_algorithm
 *
 * @return True if the algorithm is one of the supported HMAC algorithms. False
 *otherwise
 **/
bool yh_is_hmac(yh_algorithm algorithm);

/**
 * Get the expected key length of a key generated by the given algorithm
 *
 * @param algorithm Algorithm to check. See #yh_algorithm
 * @param result Expected bitlength of a key generated by the algorithm
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if <tt>result</tt> is NULL or if the
 *algorithm is no supported by YubiHSM 2. For a list of supported algorithms,
 *see #yh_algorithm
 **/
yh_rc yh_get_key_bitlength(yh_algorithm algorithm, size_t *result);

/**
 * Convert an algorithm to its string representation.
 *
 * @param algo Algorithm to convert. See #yh_algorithm
 * @param result The algorithm as a String. "Unknown" if the algorithm is not
 *supported by YubiHSM 2.
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if <tt>result</tt> is NULL.
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Algorithms</a>
 **/
yh_rc yh_algo_to_string(yh_algorithm algo, char const **result);

/**
 * Convert a string to an algorithm's numeric value
 *
 * @param string Algorithm as string. See #yh_algorithm
 * @param algo Algorithm numeric value
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if the
 *algorithm is not supported by YubiHSM 2.
 *
 * @par Code sample
 *
 *     yh_algorithm algorithm;
 *     //yh_string_to_algo(NULL, &algorithm) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_algo("something", NULL) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_algo("something", &algorithm) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_algo("rsa-pkcs1-sha1", &algorithm) =>
 *YH_ALGO_RSA_PKCS1_SHA1
 *     //yh_string_to_algo("rsa2048", &algorithm) => YH_ALGO_RSA_2048
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html">Algorithms</a>
 **/
yh_rc yh_string_to_algo(const char *string, yh_algorithm *algo);

/**
 * Convert a #yh_object_type to its string representation
 *
 * @param type Type to convert. See #yh_object_type
 * @param result The type as a String. "Unknown" if the type was not recognized
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if <tt>result</tt> is NULL.
 *
 * @par Code sample
 *
 *     const char *string;
 *     //yh_type_to_string(0, NULL) => YHR_INVALID_PARAMETERS
 *     //yh_type_to_string(99, &string) => string="Unknown"
 *     //yh_type_to_string(YH_OPAQUE, &string) => string="opaque"
 *     //yh_type_to_string(YH_AUTHENTICATION_KEY, &string) =>
 *string="authentication-key"
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Object</a>
 **/
yh_rc yh_type_to_string(yh_object_type type, char const **result);

/**
 * Convert a string to a type's numeric value
 *
 * @param string Type as a String. See #yh_object_type
 * @param type Type numeric value
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if the type
 *was not recognized.
 *
 * @par Code sample
 *
 *     yh_object_type type;
 *     //yh_string_to_type(NULL, &type) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_type("something", NULL) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_type("something", &type) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_type("opaque", &type) => type=YH_OPAQUE
 *     //yh_string_to_type("authentication-key", &type) =>
 *type=YH_AUTHENTICATION_KEY
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Object.html">Object</a>
 **/
yh_rc yh_string_to_type(const char *string, yh_object_type *type);

/**
 * Convert a string to an option's numeric value
 *
 * @param string Option as string. See #yh_option
 * @param option Option numeric value
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL or if the option
 *was not recognized.
 *
 * @par Code sample
 *
 *     yh_option option;
 *     //yh_string_to_option(NULL, &option) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_option("something", NULL) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_option("something", &option) => YHR_INVALID_PARAMETERS
 *     //yh_string_to_option("force-audit", &option) =>
 *option=YH_OPTION_FORCE_AUDIT
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Options.html">Options</a>
 **/
yh_rc yh_string_to_option(const char *string, yh_option *option);

/**
 * Verify an array of log entries
 *
 * @param logs Array of log entries
 * @param n_items number of log entries
 * @param last_previous_log Optional pointer to the entry before the first entry
 *in logs
 *
 * @return True if verification succeeds. False otherwise
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Logs.html">Logs</a>
 **/
bool yh_verify_logs(yh_log_entry *logs, size_t n_items,
                    yh_log_entry *last_previous_log);

/**
 * Convert a string to a domain's numeric value.
 *
 * The domains string can contain one or several domains separated by ',', ':'
 *or
 *'|'. Each domain can be written in decimal or hex format
 *
 * @param domains String of domains
 * @param result Resulting parsed domains as an unsigned int
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_INVALID_PARAMETERS if input parameters are NULL, if the domains
 *string is does not contains the expected values
 *
 * @par Examples
 *
 *  * "1" => 1
 *  * "1,2:3,4|5,6;7,8,9,10,11,12,13,14,15,16" => 0xffff
 *  * "1,16" => 0x8001
 *  * "16" => 0x8000
 *  * "16,15" => 0xc000
 *  * "1,0xf" => 0x4001
 *  * "0x1,0x2" => 3
 *  * "0x8888" => 0x8888
 *  * "0" => 0
 *  * "all" => 0xffff
 *  * "2" => 2
 *  * "2:4" => 10
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Domain.html">Domains</a>
 **/
yh_rc yh_string_to_domains(const char *domains, uint16_t *result);

/**
 * Convert domains parameter to its String representation
 *
 * @param domains Encoded domains
 * @param string Domains as a string
 * @param max_len Maximum length of the string
 *
 * @return #YHR_SUCCESS if successful.
 *         #YHR_BUFFER_TOO_SMALL if <tt>max_len</tt> is too small
 *
 * @par Examples
 *
 *  * 1 => "1"
 *  * 0x8001 => "1:16"
 *  * 0, ""
 *  * 0xffff => "1:2:3:4:5:6:7:8:9:10:11:12:13:14:15:16"
 *
 * @see <a
 *href="https://developers.yubico.com/YubiHSM2/Concepts/Domain.html">Domains</a>
 **/
yh_rc yh_domains_to_string(uint16_t domains, char *string, size_t max_len);
#ifdef __cplusplus
}
#endif

#ifdef _MSC_VER
#pragma strict_gs_check(on)
#endif

#endif
