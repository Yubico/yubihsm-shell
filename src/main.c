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

#include <yubihsm.h>

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>

#include "util.h"
#include "commands.h"

#include <openssl/evp.h>

//#include <ctype.h>

#define PROMPT "yubihsm> "

#define ARGS_BUFFER_SIZE 4096

#define COMPLETION_CANDIDATES 256
#define MAX_COMMAND_NAME 32
#define MAX_ARGUMENTS 32

#define LOCAL_CONNECTOR_URL "http://127.0.0.1:12345"

#include "yubihsm-shell.h"

#define SPACES " \f\n\r\t\v"

#ifdef __WIN32
#include <windows.h>

// TODO: cheat on windows, cheat better?
#define S_ISLNK S_ISREG
#else
#include <editline/readline.h>
#include <histedit.h>

History *g_hist;
#endif

#define LIB_SUCCEED_OR_DIE(x, s)                                               \
  if ((x) != YHR_SUCCESS) {                                                    \
    fprintf(stderr, s "%s\n", yh_strerror(x));                                 \
    rc = EXIT_FAILURE;                                                         \
    break;                                                                     \
  }

#define COM_SUCCEED_OR_DIE(x, s)                                               \
  if ((x) != 0) {                                                              \
    fprintf(stderr, s "\n");                                                   \
    rc = EXIT_FAILURE;                                                         \
    break;                                                                     \
  }

static bool calling_device = false;
static yubihsm_context ctx = {0, 0, 0, {0}, 0, 0, fmt_nofmt, fmt_nofmt, 0, 0};

int yh_com_help(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_history(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_quit(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_set_informat(yubihsm_context *ctx, Argument *argv, cmd_format fmt);
int yh_com_set_outformat(yubihsm_context *ctx, Argument *argv, cmd_format fmt);

typedef struct Command Command;

// NOTE(adma): supported values for the argument list are as follow
// u: unsigned integer (either decimal or hex if starts with 0x)
// w: unsigned short
// b: unsigned byte
// f: out filename
// F: in filename
// s: string
// e: session
struct Command {
  char *name;            /* Command name to match against    */
  CommandFunction *func; /* Documentation for the function   */
  char *args;            /* Argument string                  */
  cmd_format in_fmt;     /* Default input format for command */
  cmd_format out_fmt;    /* Default output format for command */
  char *doc;             /* Function to call to do the job   */
  Command *subcommands;  /* List of subcommands              */
  Command *next;         /* Pointer to next command          */
};

typedef Command *CommandList;

// NOTE(adma): push command to list and return the new head
Command *register_command(CommandList list, Command command) {

  Command *c = calloc(1, sizeof(Command));

  assert(strlen(command.name) <= MAX_COMMAND_NAME);

  memcpy(c, &command, sizeof(Command));
  c->next = list;

  return c;
}

void register_subcommand(Command *parent, Command command) {

  Command *c = malloc(sizeof(Command));

  if (c == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    exit(EXIT_FAILURE);
  }
  memcpy(c, &command, sizeof(Command));
  c->next = parent->subcommands;
  parent->subcommands = c;
}

CommandList msort_list(CommandList list) {

  Command *left;
  Command *right;
  Command *e;

  int in_size;
  int left_size;
  int right_size;

  // NOTE(adma): do nothing on an empty list
  if (!list) {
    return NULL;
  }

  in_size = 1;

  while (1) {
    Command *tail = NULL;
    left = list;
    list = NULL;

    int n_merges = 0;

    while (left != NULL) {
      n_merges++;

      right = left;
      left_size = 0;
      for (int i = 0; i < in_size; i++) {
        left_size++;
        right = right->next;

        if (right == NULL) {
          break;
        }
      }

      right_size = in_size;

      while (left_size > 0 || (right_size > 0 && right)) {

        if (left_size == 0) {
          e = right;
          right = right->next;
          right_size--;
        } else if (right_size == 0 || !right) {
          e = left;
          left = left->next;
          left_size--;
        } else if (strcmp(left->name, right->name) <= 0) {
          e = left;
          left = left->next;
          left_size--;
        } else {
          e = right;
          right = right->next;
          right_size--;
        }

        if (tail) {
          tail->next = e;
        } else {
          list = e;
        }

        tail = e;
      }

      left = right;
    }

    if (tail != NULL) {
      tail->next = NULL;
    }

    if (n_merges <= 1) {
      return list;
    }

    in_size *= 2;
  }
}

void create_command_list(CommandList *c) {

  // NOTE(adma): initialize
  *c = NULL;

  *c = register_command(*c, (Command){"audit", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Deal with audit log", NULL,
                                      NULL});
  register_subcommand(*c, (Command){"get", yh_com_audit, "e:session,F:file=-",
                                    fmt_ASCII, fmt_nofmt, "Extract log entries",
                                    NULL, NULL});
  register_subcommand(*c, (Command){"set", yh_com_set_log_index,
                                    "e:session,w:index", fmt_nofmt, fmt_nofmt,
                                    "Set the log index", NULL, NULL});
  *c = register_command(*c, (Command){"connect", yh_com_connect, NULL,
                                      fmt_nofmt, fmt_nofmt,
                                      "Connect to a connector", NULL, NULL});
  *c = register_command(*c, (Command){"debug", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Change debug settings", NULL,
                                      NULL});
  register_subcommand(*c, (Command){"all", yh_com_debug_all, NULL, fmt_nofmt,
                                    fmt_nofmt, "Enable all debug messages",
                                    NULL, NULL});
  register_subcommand(*c,
                      (Command){"crypto", yh_com_debug_crypto, NULL, fmt_nofmt,
                                fmt_nofmt, "Toggle crypto debug messages", NULL,
                                NULL});
  register_subcommand(*c, (Command){"error", yh_com_debug_error, NULL,
                                    fmt_nofmt, fmt_nofmt,
                                    "Toggle error debug messages", NULL, NULL});
  register_subcommand(*c, (Command){"info", yh_com_debug_info, NULL, fmt_nofmt,
                                    fmt_nofmt, "Toggle info debug messages",
                                    NULL, NULL});
  register_subcommand(*c, (Command){"intermediate", yh_com_debug_intermediate,
                                    NULL, fmt_nofmt, fmt_nofmt,
                                    "Toggle intermediate debug messages", NULL,
                                    NULL});
  register_subcommand(*c, (Command){"none", yh_com_debug_none, NULL, fmt_nofmt,
                                    fmt_nofmt, "Disable all debug messages",
                                    NULL, NULL});
  register_subcommand(*c, (Command){"raw", yh_com_debug_raw, NULL, fmt_nofmt,
                                    fmt_nofmt, "Toggle raw debug messages",
                                    NULL, NULL});
  *c = register_command(*c, (Command){"decrypt", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Decrypt data", NULL, NULL});
  register_subcommand(*c, (Command){"pkcs1v1_5", yh_com_decrypt_pkcs1v1_5,
                                    "e:session,w:key_id,i:data=-", fmt_binary,
                                    fmt_base64,
                                    "Decrypt data using RSAES-PKCS#1v1.5", NULL,
                                    NULL});
  register_subcommand(
    *c,
    (Command){"oaep", yh_com_decrypt_oaep,
              "e:session,w:key_id,a:algorithm,i:data=-,s:label=", fmt_binary,
              fmt_base64, "Decrypt data using RSAES-OAEP", NULL, NULL});
  register_subcommand(*c,
                      (Command){"aesccm", yh_com_decrypt_aesccm,
                                "e:session,w:key_id,i:data=-", fmt_base64,
                                fmt_binary, "Decrypt data using Yubico-AES-CCM",
                                NULL, NULL});
  *c = register_command(*c, (Command){"derive", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Drive data", NULL, NULL});
  register_subcommand(*c, (Command){"ecdh", yh_com_derive_ecdh,
                                    "e:session,w:key_id,i:pubkey=-", fmt_PEM,
                                    fmt_hex, "Perform a ECDH key exchange",
                                    NULL, NULL});

  *c = register_command(*c, (Command){"encrypt", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Encrypt data", NULL, NULL});
  register_subcommand(*c,
                      (Command){"aesccm", yh_com_encrypt_aesccm,
                                "e:session,w:key_id,i:data=-", fmt_binary,
                                fmt_base64, "Encrypt data using Yubico-AES-CCM",
                                NULL, NULL});
  *c =
    register_command(*c, (Command){"disconnect", yh_com_disconnect, NULL,
                                   fmt_nofmt, fmt_nofmt,
                                   "Disconnect from a connector", NULL, NULL});
  *c =
    register_command(*c,
                     (Command){"echo", yh_com_echo, "e:session,b:byte,w:count",
                               fmt_nofmt, fmt_nofmt,
                               "Send an ECHO command over a given session",
                               NULL, NULL});
  *c = register_command(*c, (Command){"generate", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Generate key", NULL, NULL});
  register_subcommand(*c, (Command){"asymmetric", yh_com_generate_asymmetric,
                                    "e:session,w:key_id,s:label,d:domains,c:"
                                    "capabilities,a:algorithm",
                                    fmt_nofmt, fmt_nofmt,
                                    "Generate an asymmetric key", NULL, NULL});
  register_subcommand(*c, (Command){"hmackey", yh_com_generate_hmac,
                                    "e:session,w:key_id,s:label,d:domains,c:"
                                    "capabilities,a:algorithm",
                                    fmt_nofmt, fmt_nofmt, "Generate HMAC key",
                                    NULL, NULL});
  register_subcommand(
    *c, (Command){"wrapkey", yh_com_generate_wrap,
                  "e:session,w:key_id,s:label,d:domains,c:"
                  "capabilities,c:delegated_capabilities,a:algorithm",
                  fmt_nofmt, fmt_nofmt, "Generate wrap key", NULL, NULL});
  register_subcommand(*c, (Command){"otpaeadkey", yh_com_generate_otp_aead_key,
                                    "e:session,w:key_id,s:label,d:domains,c:"
                                    "capabilities,a:algorithm,u:nonce_id",
                                    fmt_nofmt, fmt_nofmt,
                                    "Generate OTP AEAD key", NULL, NULL});
  *c = register_command(*c, (Command){"get", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Retrieve data", NULL, NULL});
  register_subcommand(*c, (Command){"opaque", yh_com_get_opaque,
                                    "e:session,w:object_id,F:file=-", fmt_nofmt,
                                    fmt_binary, "Get an opaque object", NULL,
                                    NULL});
  register_subcommand(*c, (Command){"option", yh_com_get_option,
                                    "e:session,o:option", fmt_nofmt,
                                    fmt_nofmt, // FIXME: output
                                    "Get a global option value", NULL, NULL});
  register_subcommand(*c,
                      (Command){"random", yh_com_get_random,
                                "e:session,w:count,F:out=-", fmt_nofmt, fmt_hex,
                                "Get pseudo-random bytes", NULL, NULL});
  register_subcommand(*c, (Command){"storage", yh_com_get_storage, "e:session",
                                    fmt_nofmt, fmt_nofmt, "Get storages stats",
                                    NULL, NULL});
  register_subcommand(*c, (Command){"pubkey", yh_com_get_pubkey,
                                    "e:session,w:key_id,F:file=-", fmt_nofmt,
                                    fmt_PEM, "Get a public key", NULL, NULL});
  register_subcommand(*c,
                      (Command){"objectinfo", yh_com_get_object_info,
                                "e:session,w:id,t:type", fmt_nofmt, fmt_nofmt,
                                "Get information about an object", NULL, NULL});
  register_subcommand(*c,
                      (Command){"wrapped", yh_com_get_wrapped,
                                "e:session,w:wrapkey_id,t:type,w:id,F:file=-",
                                fmt_nofmt, fmt_base64,
                                "Get an object under wrap", NULL, NULL});
  register_subcommand(*c, (Command){"deviceinfo", yh_com_get_device_info, NULL,
                                    fmt_nofmt, fmt_nofmt,
                                    "Extract the version number, serial number "
                                    "and supported algorithms",
                                    NULL, NULL});
  register_subcommand(*c, (Command){"template", yh_com_get_template,
                                    "e:session,w:object_id,F:out=-", fmt_nofmt,
                                    fmt_base64, "Get a template object", NULL,
                                    NULL});

  *c =
    register_command(*c, (Command){"help", yh_com_help, "s:command=", fmt_nofmt,
                                   fmt_nofmt, "Display help text", NULL, NULL});
  *c =
    register_command(*c, (Command){"history", yh_com_history, NULL, fmt_nofmt,
                                   fmt_nofmt, "Display the command history",
                                   NULL, NULL});
  *c =
    register_command(*c, (Command){"list", yh_com_noop, NULL, fmt_nofmt,
                                   fmt_nofmt, "List information", NULL, NULL});
  register_subcommand(*c, (Command){"capabilities", yh_com_list_capabilities,
                                    NULL, fmt_nofmt, fmt_nofmt,
                                    "Prints a list of possible capabilities",
                                    NULL, NULL});
  register_subcommand(*c, (Command){"algorithms", yh_com_list_algorithms, NULL,
                                    fmt_nofmt, fmt_nofmt,
                                    "Prints a list of possible algorithms",
                                    NULL, NULL});
  register_subcommand(*c,
                      (Command){"types", yh_com_list_types, NULL, fmt_nofmt,
                                fmt_nofmt, "Prints a list of possible types",
                                NULL, NULL});
  register_subcommand(*c, (Command){"sessions", yh_com_list_sessions, NULL,
                                    fmt_nofmt, fmt_nofmt,
                                    "List the open session", NULL, NULL});
  register_subcommand(*c, (Command){"objects", yh_com_list_objects,
                                    "e:session,w:id=0,t:type=any,d:domains=0,c:"
                                    "capabilities=0,a:algorithm=any,s:label=",
                                    fmt_nofmt, fmt_nofmt,
                                    "List objects according to filter", NULL,
                                    NULL});
  *c =
    register_command(*c,
                     (Command){"plain", yh_com_noop, NULL, fmt_nofmt, fmt_nofmt,
                               "Send unencrypted and unauthenticated commands",
                               NULL, NULL});
  register_subcommand(*c, (Command){"echo", yh_com_pecho, "b:byte,w:count",
                                    fmt_nofmt, fmt_nofmt,
                                    "Send a plain echo command", NULL, NULL});
  *c = register_command(*c, (Command){"put", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Store data", NULL, NULL});
  register_subcommand(*c, (Command){"asymmetric", yh_com_put_asymmetric,
                                    "e:session,w:key_id,s:label,d:domains,c:"
                                    "capabilities,i:key=-",
                                    fmt_PEM, fmt_nofmt,
                                    "Store an asymmetric key", NULL, NULL});
  register_subcommand(*c, (Command){"authkey", yh_com_put_authentication,
                                    "e:session,w:key_id,s:label,d:domains,c:"
                                    "capabilities,c:delegated_capabilities,i:"
                                    "password=-",
                                    fmt_password, fmt_nofmt,
                                    "Store an authentication key", NULL, NULL});
  register_subcommand(*c, (Command){"opaque", yh_com_put_opaque,
                                    "e:session,w:object_id,s:label,d:domains,c:"
                                    "capabilities,a:algorithm,i:data=-",
                                    fmt_binary, fmt_nofmt,
                                    "Store an opaque object", NULL, NULL});
  register_subcommand(*c,
                      (Command){"option", yh_com_put_option,
                                "e:session,o:option,i:data", fmt_hex, fmt_nofmt,
                                "Set a global option value", NULL, NULL});
  register_subcommand(*c, (Command){"hmackey", yh_com_put_hmac,
                                    "e:session,w:key_id,s:label,d:domains,c:"
                                    "capabilities,a:algorithm,i:key",
                                    fmt_hex, fmt_nofmt, "Store a HMAC key",
                                    NULL, NULL});
  register_subcommand(*c,
                      (Command){"wrapkey", yh_com_put_wrapkey,
                                "e:session,w:key_id,s:label,d:domains,c:"
                                "capabilities,c:delegated_capabilities,i:key",
                                fmt_hex, fmt_nofmt, "Store a wrapping key",
                                NULL, NULL});
  register_subcommand(*c, (Command){"wrapped", yh_com_put_wrapped,
                                    "e:session,w:wrapkey_id,i:data=-",
                                    fmt_base64, fmt_nofmt,
                                    "Store a wrapped object", NULL, NULL});
  register_subcommand(*c, (Command){"template", yh_com_put_template,
                                    "e:session,w:object_id,s:label,d:domains,c:"
                                    "capabilities,a:algorithm,i:data=-",
                                    fmt_base64, fmt_nofmt,
                                    "Store a template object", NULL, NULL});
  register_subcommand(*c, (Command){"otpaeadkey", yh_com_put_otp_aead_key,
                                    "e:session,w:key_id,s:label,d:domains,c:"
                                    "capabilities,u:nonce_id,i:key",
                                    fmt_hex, fmt_nofmt, "Store a OTP AEAD key",
                                    NULL, NULL});
  *c = register_command(*c,
                        (Command){"quit", yh_com_quit, NULL, fmt_nofmt,
                                  fmt_nofmt, "Quit yubihsm-shell", NULL, NULL});
  *c = register_command(*c,
                        (Command){"exit", yh_com_quit, NULL, fmt_nofmt,
                                  fmt_nofmt, "Quit yubihsm-shell", NULL, NULL});
  *c =
    register_command(*c, (Command){"session", yh_com_noop, NULL, fmt_nofmt,
                                   fmt_nofmt, "Manage sessions", NULL, NULL});
  register_subcommand(*c, (Command){"close", yh_com_close_session, "e:session",
                                    fmt_nofmt, fmt_nofmt,
                                    "Close a session with a connector", NULL,
                                    NULL});
  register_subcommand(*c, (Command){"open", yh_com_open_session,
                                    "w:authkey,i:password=-", fmt_password,
                                    fmt_nofmt,
                                    "Open a session with a device using a "
                                    "specific Authentication Key",
                                    NULL, NULL});
  *c = register_command(*c, (Command){"sign", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Sign data", NULL, NULL});
  register_subcommand(
    *c, (Command){"ecdsa", yh_com_sign_ecdsa,
                  "e:session,w:key_id,a:algorithm,i:data=-,F:out=-", fmt_binary,
                  fmt_base64, "Sign data using ECDSA", NULL, NULL});
  register_subcommand(
    *c, (Command){"eddsa", yh_com_sign_eddsa,
                  "e:session,w:key_id,a:algorithm,i:data=-,F:out=-", fmt_binary,
                  fmt_base64, "Sign data using EDDSA", NULL, NULL});
  register_subcommand(
    *c, (Command){"pkcs1v1_5", yh_com_sign_pkcs1v1_5,
                  "e:session,w:key_id,a:algorithm,i:data=-,F:out=-", fmt_binary,
                  fmt_base64, "Sign data using RSASSA-PKCS#1v1.5", NULL, NULL});
  register_subcommand(
    *c, (Command){"pss", yh_com_sign_pss,
                  "e:session,w:key_id,a:algorithm,i:data=-,F:out=-", fmt_binary,
                  fmt_base64, "Sign data using RSASSA-PSS", NULL, NULL});
  *c =
    register_command(*c, (Command){"hmac", yh_com_hmac,
                                   "e:session,w:key_id,i:data=-,F:out=-",
                                   fmt_hex, fmt_hex, "Hmac data", NULL, NULL});
  *c = register_command(*c,
                        (Command){"reset", yh_com_reset, "e:session", fmt_nofmt,
                                  fmt_nofmt, "Reset device", NULL, NULL});
  *c = register_command(*c, (Command){"delete", yh_com_delete,
                                      "e:session,w:id,t:type", fmt_nofmt,
                                      fmt_nofmt, "Delete data", NULL, NULL});
  *c =
    register_command(*c, (Command){"certify", yh_com_sign_ssh_certificate,
                                   "e:session,w:key_id,w:template_id,a:"
                                   "algorithm,i:infile=-,F:outfile=-",
                                   fmt_binary,
                                   fmt_binary, // TODO: correct default formats?
                                   "Sign SSH certificates", NULL, NULL});
  *c =
    register_command(*c,
                     (Command){"benchmark", yh_com_benchmark,
                               "e:session,u:count,w:key_id=0,a:algorithm=any",
                               fmt_nofmt, fmt_nofmt, "Run a set of benchmarks",
                               NULL, NULL});
  *c = register_command(*c, (Command){"otp", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "OTP commands", NULL, NULL});
  register_subcommand(*c,
                      (Command){"aead_create", yh_com_otp_aead_create,
                                "e:session,w:key_id,i:key,i:private_id,F:aead",
                                fmt_hex, fmt_binary, "Create an OTP AEAD", NULL,
                                NULL});
  register_subcommand(*c, (Command){"aead_random", yh_com_otp_aead_random,
                                    "e:session,w:key_id,F:aead", fmt_nofmt,
                                    fmt_binary, "Create a random OTP AEAD",
                                    NULL, NULL});
  register_subcommand(*c, (Command){"decrypt", yh_com_otp_decrypt,
                                    "e:session,w:key_id,s:otp,i:aead",
                                    fmt_binary, fmt_nofmt,
                                    "Decrypt an OTP with AEAD", NULL, NULL});
  *c = register_command(*c, (Command){"attest", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Attest device objects", NULL,
                                      NULL});
  register_subcommand(*c,
                      (Command){"asymmetric",
                                yh_com_sign_attestation_certificate,
                                "e:session,w:key_id,w:attest_id=0", fmt_nofmt,
                                fmt_PEM, "Sign attestation certificate", NULL,
                                NULL});
  *c = register_command(*c, (Command){"keepalive", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Change keepalive settings",
                                      NULL, NULL});

  register_subcommand(*c, (Command){"on", yh_com_keepalive_on, NULL, fmt_nofmt,
                                    fmt_nofmt, "Enable keepalive", NULL, NULL});
  register_subcommand(*c,
                      (Command){"off", yh_com_keepalive_off, NULL, fmt_nofmt,
                                fmt_nofmt, "Disable keepalive", NULL, NULL});

  *c =
    register_command(*c, (Command){"set", yh_com_noop, NULL, fmt_nofmt,
                                   fmt_nofmt, "Set preferences", NULL, NULL});

  register_subcommand(*c, (Command){"informat", yh_com_set_informat, "I:format",
                                    fmt_nofmt, fmt_nofmt, "Set input format",
                                    NULL, NULL});
  register_subcommand(*c, (Command){"outformat", yh_com_set_outformat,
                                    "I:format", fmt_nofmt, fmt_nofmt,
                                    "Set output format", NULL, NULL});
  register_subcommand(*c, (Command){"cacert", yh_com_set_cacert, "s:file",
                                    fmt_nofmt, fmt_nofmt,
                                    "Set CA cert to use for https to connector",
                                    NULL, NULL});
  register_subcommand(*c, (Command){"proxy", yh_com_set_proxy, "s:proxy",
                                    fmt_nofmt, fmt_nofmt,
                                    "Set proxyserver to use for connector",
                                    NULL, NULL});
  *c =
    register_command(*c, (Command){"blink", yh_com_blink,
                                   "e:session,b:seconds=10", fmt_nofmt,
                                   fmt_nofmt, "Blink the device", NULL, NULL});

  *c = register_command(*c, (Command){"change", yh_com_noop, NULL, fmt_nofmt,
                                      fmt_nofmt, "Change objects", NULL, NULL});

  register_subcommand(*c,
                      (Command){"authkey", yh_com_change_authentication_key,
                                "e:session,w:key_id,i:password=-", fmt_password,
                                fmt_nofmt, "Change an authentication key", NULL,
                                NULL});

  *c = msort_list(*c);

  for (Command *t = *c; t != NULL; t = t->next) {
    if (t->subcommands != NULL) {
      t->subcommands = msort_list(t->subcommands);
    }
  }
}

// NOTE(adma): the prototype for el functions is fixed, no way to pass
// in parameters, we must use globals
CommandList g_commands;

bool g_running = true;

// NOTE(adma): Print the command history
// argc = 0
int yh_com_history(yubihsm_context *ctx, Argument *argv, cmd_format fmt) {

  UNUSED(fmt);
  UNUSED(ctx);
  UNUSED(argv);

#ifndef __WIN32
  HistEvent ev;

  int rv;

  for (rv = history(g_hist, &ev, H_LAST); rv != -1;
       rv = history(g_hist, &ev, H_PREV)) {
    fprintf(ctx->out, "%4d %s", ev.num, ev.str);
  }
#endif

  return 0;
}

static const char *fmt_to_string(cmd_format fmt) {
  for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); i++) {
    if (formats[i].format == fmt) {
      return formats[i].name;
    }
  }

  return "No format";
}

// NOTE(adma): Print information about a command
// argc = 1
// arg 0: s:command
int yh_com_help(yubihsm_context *ctx, Argument *argv, cmd_format fmt) {

  UNUSED(fmt);
  UNUSED(ctx);
  bool match = false;

  // TODO(adma): once we have optional commands we can have a real help
  for (Command *command = g_commands; command; command = command->next) {
    if (strncmp(argv[0].s, command->name, strlen(argv[0].s)) == 0) {
      match = true;
      printf("%-25s%s\n", command->name, command->doc);
      if (strlen(argv[0].s)) {
        if (command->args) {
          printf("%-5s%s", "", command->args);
          if (command->in_fmt != fmt_nofmt) {
            printf(" (default input format: %s)",
                   fmt_to_string(command->in_fmt));
          }
          printf("\n");
        }
        for (Command *subcommand = command->subcommands; subcommand;
             subcommand = subcommand->next) {
          printf("%-5s%-25s%s", "", subcommand->name, subcommand->doc);
          if (subcommand->args) {
            if (subcommand->in_fmt != fmt_nofmt) {
              printf(" (default input format: %s)",
                     fmt_to_string(subcommand->in_fmt));
            }
            printf("\n%-30s%s\n", "", subcommand->args);
          } else {
            printf("\n");
          }
        }
      }
    }
  }

  if (match == false) {
    printf("Help for command %s not found\n", argv[0].s);
  }
  return 0;
}

// NOTE(adma): Quit
// argc = 0
int yh_com_quit(yubihsm_context *ctx, Argument *argv, cmd_format fmt) {

  UNUSED(fmt);
  UNUSED(ctx);
  UNUSED(argv);

  g_running = false;

  return 0;
}

static bool probe_session(yubihsm_context *ctx, int index) {
  if (ctx->sessions[index]) {
    uint8_t data = 0xff;
    uint8_t response[YH_MSG_BUF_SIZE];
    size_t response_len = sizeof(response);
    yh_cmd response_cmd;

    // silently ignore transmit errors..?
    if (yh_send_secure_msg(ctx->sessions[index], YHC_ECHO, &data, 1,
                           &response_cmd, response,
                           &response_len) == YHR_SUCCESS) {
      if (response_cmd != YHC_ECHO_R) {
        yh_destroy_session(&ctx->sessions[index]);
        ctx->sessions[index] = NULL;
        return false;
      }
    }
    return true;
  } else {
    return false;
  }
}

#ifdef __WIN32
static void timer_handler(void *lpParam __attribute__((unused)),
                          unsigned char TimerOrWaitFired
                          __attribute__((unused))) {
#else
static void timer_handler(int signo __attribute__((unused))) {
#endif

  if (calling_device == true || ctx.connector == NULL) {
    return;
  }
  for (int i = 0; i < YH_MAX_SESSIONS; i++) {
    probe_session(&ctx, i);
  }
}

static int set_keepalive(uint16_t seconds) {

#ifdef __WIN32
  HANDLE timer;
  static HANDLE timerQueue = NULL;

  if (timerQueue != NULL) {
    DeleteTimerQueue(timerQueue);
  }
  timerQueue = CreateTimerQueue();
  if (timerQueue == NULL) {
    fprintf(stderr, "Failed to setup timer\n");
    return 1;
  }
  CreateTimerQueueTimer(&timer, timerQueue, timer_handler, NULL, seconds * 1000,
                        seconds * 1000, 0);
  if (timer == NULL) {
    fprintf(stderr, "Failed to start time\n");
    return 1;
  }
#else
  struct itimerval itimer;
  itimer.it_interval.tv_sec = seconds;
  itimer.it_interval.tv_usec = 0;
  itimer.it_value.tv_sec = seconds;
  itimer.it_value.tv_usec = 0;
  if (setitimer(ITIMER_REAL, &itimer, NULL) != 0) {
    fprintf(stderr, "Failed to setup timer\n");
    return 1;
  }
#endif

  fprintf(stderr, "Session keepalive set up to run every %d seconds\n",
          seconds);

  return 0;
}

// NOTE: Enable keepalive
// argc = 0
int yh_com_keepalive_on(yubihsm_context *ctx, Argument *argv, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(fmt);

  return set_keepalive(15);
}

// NOTE: Disable keepalive
// argc = 0
int yh_com_keepalive_off(yubihsm_context *ctx, Argument *argv, cmd_format fmt) {

  UNUSED(ctx);
  UNUSED(argv);
  UNUSED(fmt);

  return set_keepalive(0);
}

int yh_com_set_informat(yubihsm_context *ctx, Argument *argv, cmd_format fmt) {
  UNUSED(fmt);

  if (strcasecmp(argv[0].s, "default") == 0) {
    ctx->in_fmt = fmt_nofmt;
    return 0;
  }
  for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); i++) {
    if (strcasecmp(argv[0].s, formats[i].name) == 0) {
      ctx->in_fmt = formats[i].format;
      return 0;
    }
  }
  fprintf(stderr, "Failed to parse input format\n");
  return -1;
}

int yh_com_set_outformat(yubihsm_context *ctx, Argument *argv, cmd_format fmt) {
  UNUSED(fmt);

  if (strcasecmp(argv[0].s, "default") == 0) {
    ctx->out_fmt = fmt_nofmt;
    return 0;
  }
  for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); i++) {
    if (strcasecmp(argv[0].s, formats[i].name) == 0) {
      if (formats[i].format == fmt_password) {
        break;
      }
      ctx->out_fmt = formats[i].format;
      return 0;
    }
  }
  fprintf(stderr, "Failed to parse output format\n");
  return -1;
}

void find_lcp(const char *items[], int n_items, const char **lcp,
              int *lcp_len) {

  int min = 0;
  int max = 0;

  if (items == NULL || n_items == 0) {
    *lcp = NULL;
    *lcp_len = 0;
  }

  for (int i = 1; i < n_items; i++) {
    if (strcmp(items[i], items[min]) < 0) {
      min = i;
    } else if (strcmp(items[i], items[max]) > 0) {
      max = i;
    }
  }

  *lcp = items[min];
  for (unsigned int i = 0; i < strlen(items[min]) && i < strlen(items[max]);
       i++) {
    if (items[min][i] != items[max][i]) {
      *lcp_len = i;

      return;
    }
  }

  *lcp_len = strlen(items[min]);
}

int tokenize(char *line, char **toks, int max_toks, int *cursorc, int *cursoro,
             const char *space) {
  int i;
  int tok = 0;
  int length = strlen(line);
  int start_of_word = 0;
  enum states { SPACE, WORD, QUOTE } state = SPACE;
  toks[0] = line; // set up as fall-through

  for (i = 0; i <= length; i++) {
    char c = line[i];
    if (cursorc && i == *cursorc && tok > 0) {
      if (state == SPACE) {
        *cursoro = 0;
        *cursorc = tok;
      } else {
        *cursoro = i - start_of_word;
        *cursorc = tok - 1;
      }
    }
    if (c == '\0') {
      break;
    }
    if (tok >= max_toks) {
      return -1;
    }
    switch (state) {
      case SPACE: {
        bool found = false;
        for (size_t j = 0; j < strlen(space); j++) {
          if (c == space[j]) {
            found = true;
            break;
          }
        }
        if (found) {
          break;
        }
        if (c == '"') {
          state = QUOTE;
          start_of_word = i + 1;
        } else if (c == '#') {
          return tok;
        } else {
          state = WORD;
          start_of_word = i;
        }
        toks[tok++] = line + start_of_word;
      } break;
      case QUOTE:
        if (c == '"') {
          line[i] = '\0';
          state = SPACE;
        }
        break;
      case WORD:
        for (size_t j = 0; j < strlen(space); j++) {
          if (c == space[j]) {
            line[i] = '\0';
            state = SPACE;
          }
        }
        break;
    }
  }
  return tok;
}

#ifndef __WIN32
static int compare_strings(const void *a, const void *b) {
  return strcmp(*(char *const *) a, *(char *const *) b);
}

unsigned char complete_arg(EditLine *el, const char *arg, char *line,
                           int cursoro) {

  const char *candidates[COMPLETION_CANDIDATES];
  int n_candidates = 0;
  struct winsize w;
  const LineInfo *li = el_line(el);
  ioctl(fileno(stdout), TIOCGWINSZ, &w);
  int lines = (li->cursor - li->buffer + strlen(PROMPT)) / w.ws_col;

  switch (arg[0]) {
    case 'u':
      printf("\nnumber");

      break;

    case 'w':
      printf("\nword");

      break;

    case 'b':
      printf("\nbyte");

      break;

    case 'i':
      printf("\ninput data");

      break;

    case 'F':
      printf("\noutput filename");

      break;

    case 's':
      printf("\nstring");

      break;

    case 'k':
      printf("\nkey");

      break;

    case 'e':
      printf("\nsession");

      break;

    case 'd':
      printf("\ndomains");

      break;

    case 'c': {
      char *toks[COMPLETION_CANDIDATES];
      int cursorc = cursoro;
      int num_toks =
        tokenize(line, toks, COMPLETION_CANDIDATES, &cursorc, &cursoro, ":,;|");
      if (cursorc == num_toks) {
        toks[cursorc] = "";
      }
      for (size_t i = 0; i < sizeof(yh_capability) / sizeof(yh_capability[0]);
           i++) {
        if (strncasecmp(toks[cursorc], yh_capability[i].name,
                        strlen(toks[cursorc])) == 0) {
          candidates[n_candidates++] = yh_capability[i].name;
          assert(n_candidates < COMPLETION_CANDIDATES);
        }
      }
    } break;

    case 'a':
      for (uint16_t i = 0; i < sizeof(yh_algorithms) / sizeof(yh_algorithms[0]);
           i++) {
        if (strncasecmp(line, yh_algorithms[i].name, strlen(line)) == 0) {
          candidates[n_candidates++] = yh_algorithms[i].name;
          assert(n_candidates < COMPLETION_CANDIDATES);
        }
      }

      break;

    case 't':
      for (uint16_t i = 0; i < sizeof(yh_types) / sizeof(yh_types[0]); i++) {
        if (strncasecmp(line, yh_types[i].name, strlen(line)) == 0) {
          candidates[n_candidates++] = yh_types[i].name;
          assert(n_candidates < COMPLETION_CANDIDATES);
        }
      }

      break;

    case 'o':
      for (uint16_t i = 0; i < sizeof(yh_options) / sizeof(yh_options[0]);
           i++) {
        if (strncasecmp(line, yh_options[i].name, strlen(line)) == 0) {
          candidates[n_candidates++] = yh_options[i].name;
          assert(n_candidates < COMPLETION_CANDIDATES);
        }
      }

      break;

    case 'I':
      for (uint16_t i = 0; i < sizeof(formats) / sizeof(formats[0]); i++) {
        if (strncasecmp(line, formats[i].name, strlen(line)) == 0) {
          candidates[n_candidates++] = formats[i].name;
          assert(n_candidates < COMPLETION_CANDIDATES);
        }
      }

      break;

    case '\0':
      // NOTE(adma): completing an empty string, we reached the end, do
      // nothing

      return CC_ERROR;

    default:

      printf("\nunknown type");

      break;
  }

  switch (n_candidates) {
    case 0: {
      int i = 1;

      while (arg[i] != '\0' && arg[i] != ',') {
        i++;
      }

      printf("%*.*s\n", i, i - 1, arg + 1);
    } break;

    case 1:
      el_insertstr(el, candidates[0] + cursoro);

      return CC_REDISPLAY;

    default: {
      const char *lcp;
      int lcp_len;

      qsort(candidates, n_candidates, sizeof(char *), compare_strings);

      find_lcp(candidates, n_candidates, &lcp, &lcp_len);

      if (cursoro == lcp_len) {
        // NOTE(adma): we already have lcp_len characters typed on
        // the prompt, display all the possible matches
        printf("\n");
        for (int i = 0; i < n_candidates; i++) {
          printf("%s\n", candidates[i]);
        }
      } else {
        // NOTE(adma): we found an lcp, autocomplete with that
        char prefix[MAX_COMMAND_NAME];
        strcpy(prefix, lcp + cursoro);
        prefix[lcp_len - cursoro] = '\0';

        el_insertstr(el, prefix);
        return CC_REDISPLAY;
      }
    }
  }

  for (int i = 0; i < lines; i++) {
    printf("\n");
  }
  return CC_REDISPLAY;
}

unsigned char complete_command(EditLine *el, Command *to_complete,
                               const char *line, int cursoro) {

  const char *candidates[COMPLETION_CANDIDATES];
  int n_candidates = 0;

  // NOTE(adma): try to autocomplete the current command/subcomand
  for (Command *command = to_complete; command; command = command->next) {
    if (strncmp(line, command->name, strlen(line)) == 0) {
      // printf("%s\n", command->name);

      candidates[n_candidates++] = command->name;
      assert(n_candidates < COMPLETION_CANDIDATES);
    } else if (n_candidates != 0) {
      // NOTE(adma): the list is sorted no point in continuing,
      // bail out
      break;
    }
  }
  // printf("Found %d candidates\n", n_candidates);
  switch (n_candidates) {
    case 0:
      // NOTE(adma): no matches, do nothing

      return CC_ERROR;

    case 1:
      // NOTE(adma): only one match, autocomplete!
      el_insertstr(el, candidates[0] + cursoro);
      el_insertstr(el, " ");

      return CC_REDISPLAY;

    default: {
      // NOTE(adma): several matches, find longest common prefix
      const char *lcp;
      int lcp_len;

      find_lcp(candidates, n_candidates, &lcp, &lcp_len);

      if (cursoro == lcp_len) {
        // NOTE(adma): we already have lcp_len characters typed on
        // the prompt, display all the possible matches
        printf("\n");
        for (int i = 0; i < n_candidates; i++) {
          printf("%s\n", candidates[i]);
        }
      } else {
        // NOTE(adma): we found an lcp, autocomplete with that
        char prefix[MAX_COMMAND_NAME];
        strcpy(prefix, lcp + cursoro);
        prefix[lcp_len - cursoro] = '\0';

        el_insertstr(el, prefix);
      }
    }
      return CC_REDISPLAY;
  }
}

unsigned char yubihsm_complete(EditLine *el, int ch) {

  UNUSED(ch);

  const LineInfo *li;

  int argc, cursorc, cursoro;
  char *argv[64];
  char data[ARGS_BUFFER_SIZE + 1] = {0};

  li = el_line(el);

  cursorc = li->cursor - li->buffer;
  if (li->lastchar - li->buffer > 1024) {
    return CC_REDISPLAY;
  }
  memcpy(data, li->buffer, li->lastchar - li->buffer);

  argc = tokenize(data, argv, 64, &cursorc, &cursoro, SPACES);

  // printf("\nargc %d, cursorc: %d, cursoro: %d\n", argc, cursorc, cursoro);

  if (argc == 0) {
    // NOTE(adma): no prompt, don't even bother with finding a match,
    // just show all commands, one per line
    printf("\n");
    for (Command *command = g_commands; command; command = command->next) {
      printf("%s\n", command->name);
    }
    return CC_REDISPLAY;
  } else {
    int i = 0;
    Command *command = g_commands;
    Command *to_complete = NULL;
    char *args = "";

    bool completing_args = false;

    while (i < cursorc) {
      // NOTE(adma): match the first n-1 items
      if (completing_args == false) {
        // NOTE(adma): match subcommands
        if (strncmp(argv[i], command->name, strlen(argv[i])) == 0) {
          // printf("\nmatched %s\n", command->name);
          to_complete = command;
          // to_complete_position = i;
          if (command->subcommands != NULL) {
            // NOTE(adma): if we were matching subcommands, keep
            // matching subcommands if any
            command = command->subcommands;
          } else {
            // NOTE(adma): start matching arguments otherwise
            completing_args = true;
            if (command->args != NULL) {
              args = command->args;
            } else {
              // NOTE(adma): there are no args for this command
              break;
            }
          }
          i++; // NOTE(adma): next word
        } else {
          command = command->next;
          if (command == NULL) {
            // NOTE(adma): command not found
            break;
          }
        }
      } else {
        // NOTE(adma): match arguments
        while (*args != '\0' && *args != ',') {
          args++;
        }
        if (*args == ',') {
          args++;
          i++; // NOTE(adma): next word
        } else {
          break;
        }
      }
    }

    if (to_complete && cursorc != 0) {
      // NOTE(adma): 0 has a bit of a special meaning since the cursor
      // is after the last letter of the first word and we still want
      // to autocomplete commands and not subcommands nor args in that
      // case
      to_complete = to_complete->subcommands;
    }

    if (argc == cursorc) {
      if (to_complete && completing_args == false) {
        // NOTE(adma): cursor is after a command but there is no more
        // text to match, show all subcommands
        printf("\n");
        for (Command *command = to_complete; command; command = command->next) {
          printf("%s\n", command->name);
        }
        return CC_REDISPLAY;
      } else {
        // NOTE(adma): or show the current argument
        return complete_arg(el, args, "", 0);
      }
    } else {
      if (completing_args == false) {
        if (to_complete == NULL) {
          to_complete = g_commands;
        }
        return complete_command(el, to_complete, argv[i], cursoro);
      } else {
        return complete_arg(el, args, argv[i], cursoro);
      }
    }
  }

  return CC_ERROR;
}

static char *prompt(EditLine *el) {

  UNUSED(el);

  return PROMPT;
}
#endif

static FILE *open_file(const char *name, bool input) {
  if (input) {
    if (strcmp(name, "-") == 0) {
      return stdin;
    } else {
      return fopen(name, "rb");
    }
  } else {
    if (strcmp(name, "-") == 0) {
      return stdout;
    } else {
      return fopen(name, "ab");
    }
  }
}

static bool get_input_data(const char *name, uint8_t *out, size_t *len,
                           cmd_format fmt) {
  size_t data_len;
  struct stat sb;
  int st_res = stat(name, &sb);
  if (strcmp(name, "-") == 0 || strncasecmp(name, "file:", 5) == 0 ||
      (st_res == 0 && S_ISREG(sb.st_mode))) {
    data_len = *len;
    bool ret = false;
    FILE *file;
    if (strncasecmp(name, "file:", 5) == 0) {
      name += 5;
    }
    file = open_file(name, true);
    if (!file) {
      return false;
    }
    if (file == stdin && fmt == fmt_password) {
      if (EVP_read_pw_string((char *) out, *len, "Enter password: ", 0) == 0) {
        data_len = strlen((char *) out);
        ret = true;
      }
    } else if (read_file(file, out, &data_len)) {
      ret = true;
    }
    if (file != stdin) {
      fclose(file);
    }
    if (ret == false) {
      return ret;
    }
  } else {
    if (strlen(name) < *len) {
      memcpy(out, name, strlen(name));
      data_len = strlen(name);
    } else {
      return false;
    }
  }

  switch (fmt) {
    case fmt_base64:
      if (base64_decode((char *) out, out, len)) {
        return true;
      }
      break;

    case fmt_hex:
      if (hex_decode((char *) out, out, len)) {
        return true;
      }
      break;
    case fmt_password:
      // If the password was read from a file, strip off \r\n
      if (out[data_len - 1] == '\n') {
        data_len--;
      }
      if (out[data_len - 1] == '\r') {
        data_len--;
      }
      out[data_len] = '\0';
      *len = data_len;
      return true;

    case fmt_binary: // these all require no extra work, just pass data on.
    case fmt_PEM:
    case fmt_ASCII:
      *len = data_len;
      return true;

    case fmt_nofmt:
    default:
      return false;
  }

  return false;
}

int validate_arg(yubihsm_context *ctx, char type, const char *value,
                 Argument *parsed, cmd_format fmt) {

  char buffer[ARGS_BUFFER_SIZE + 1];

  memset(buffer, 0x0, sizeof(buffer));

  switch (type) {
    case 'b':   // byte
    case 'w':   // word
    case 'e':   // session
    case 'u': { // unsigned long
      uint32_t max = 0;
      if (type == 'b') {
        max = UCHAR_MAX;
      } else if (type == 'w' || type == 'e') {
        max = USHRT_MAX;
      } else if (type == 'u') {
        max = UINT_MAX;
      }
      // NOTE(adma): check that is a positive number in dec, hex or oct
      errno = 0;
      char *endptr;
      unsigned long num = strtoul(value, &endptr, 0);

      if ((errno == ERANGE || num > max) || (errno != 0 && num == 0)) {
        return -1;
      }

      if (endptr == value) {
        return -1;
      }

      if (type == 'b') {
        parsed->b = (uint8_t) num;
      } else if (type == 'e') {
        if (num >= YH_MAX_SESSIONS || !probe_session(ctx, num)) {
          return -1;
        }
        parsed->e = ctx->sessions[num];
      } else if (type == 'w') {
        parsed->w = (uint16_t) num;
      } else if (type == 'u') {
        parsed->d = (uint32_t) num;
      }
      parsed->len = 1; // NOTE(adma): doesn't really have a meaning

    } break;

    case 'F':
      parsed->s = value;
      parsed->len = strlen(value);

      ctx->out = open_file(value, false);
      if (!ctx->out) {
        return -1;
      }

      break;

    case 'i':
      parsed->x = calloc(ARGS_BUFFER_SIZE + 1, 1);
      if (parsed->x == NULL) {
        return -1;
      }
      parsed->len = ARGS_BUFFER_SIZE;
      if (get_input_data(value, parsed->x, &parsed->len, fmt) == false) {
        return -1;
      }
      break;

    case 'I':
    case 's':
      // NOTE(adma): strings are pretty much always OK
      parsed->s = value;
      parsed->len = strlen(value);

      break;

    case 'k':
      if (strcmp(value, "stdin:") == 0) {
        if (EVP_read_pw_string(buffer, ARGS_BUFFER_SIZE,
                               "Enter hex key: ", 0) != 0) {
          return -1;
        }
        value = buffer;
      }
    case 'd':
      if (yh_string_to_domains(value, &parsed->w) != YHR_SUCCESS) {
        return -1;
      }
      break;
    case 'c':
      if (yh_string_to_capabilities(value, &parsed->c) != YHR_SUCCESS) {
        return -1;
      }
      break;

    case 'a':
      if (yh_string_to_algo(value, &parsed->a) != YHR_SUCCESS) {
        return -1;
      }
      break;

    case 't':
      if (yh_string_to_type(value, &parsed->t) != YHR_SUCCESS) {
        return -1;
      }
      break;

    case 'o':
      if (yh_string_to_option(value, &parsed->o) != YHR_SUCCESS) {
        return -1;
      }
      break;

    default:
      // NOTE(adma): unknown type
      return -1;
  }

  return 0;
}

int validate_and_call(yubihsm_context *ctx, CommandList l, const char *line) {

  int argc = 0;
  char *argv[64];
  int i = 0;

  char data[ARGS_BUFFER_SIZE + 1];

  char arg_data[ARGS_BUFFER_SIZE + 1] = {0};

  Command *command = l;

  bool completing_args = false;

  const char *args = "";

  Argument arguments[MAX_ARGUMENTS] = {{{0}, 0, 0}};
  int n_arguments = 0;

  bool invalid_arg = false;

  int match;

  bool found = false;

  CommandFunction *func = NULL;

  memset(data, 0x0, sizeof(data));
  memset(arg_data, 0x0, sizeof(data));

  if (strlen(line) > ARGS_BUFFER_SIZE) {
    printf("Command too long\n");
    return 0;
  }

  strcpy(data, line);

  argc = tokenize(data, argv, 64, NULL, NULL, SPACES);

  while (i < argc) {
    // NOTE(adma): match the first n-1 items
    if (completing_args == false) {
      // NOTE(adma): match subcommands
      match = strncmp(argv[i], command->name, strlen(argv[i]));
      if (match == 0) {
        if (command->subcommands != NULL) {
          // NOTE(adma): if we were matching subcommands, keep
          // matching subcommands if any
          command = command->subcommands;
        } else {
          // NOTE(adma): start matching arguments otherwise. Also keep
          // track of the function because that's the one we want to
          // call later on
          completing_args = true;
          func = command->func;
          if (command->args != NULL) {
            char *arg_toks[64];

            args = command->args;
            strncpy(arg_data, args,
                    ARGS_BUFFER_SIZE); // since tokenize() modifies the buffer..
            int num_args = tokenize(arg_data, arg_toks, 64, NULL, NULL, ",");
            if (num_args + 1 + i !=
                argc) { // some arguments might have default values
              for (int j = 0; j < num_args; j++) {
                if (j < argc - 1 - i) {
                  continue;
                }
                char *str = strchr(arg_toks[j], '=');
                if (str == NULL) {
                  break;
                }
                str++;
                argv[j + 1 + i] = str;
                argc++;
              }
            }
          } else {
            // NOTE(adma): there are no args for this command
            found = true;
            break;
          }
        }
        i++; // NOTE(adma): next word
      } else {
        // NOTE(adma): command not found
        command = command->next;
        if (match < 0 || command == NULL) {
          command = NULL;
          break;
        }
      }
    } else {
      // NOTE(adma): match arguments
      if (validate_arg(ctx, *args, argv[i], arguments + n_arguments++,
                       ctx->in_fmt != fmt_nofmt ? ctx->in_fmt
                                                : command->in_fmt) != 0) {
        invalid_arg = true;
        break;
      }
      while (*args != '\0' && *args != ',') {
        args++;
      }
      if (*args == ',') {
        args++;
        i++; // NOTE(adma): next word
      } else {
        found = true;
        break;
      }
    }
  }

  if (found == true) {
    func(ctx, arguments,
         ctx->out_fmt == fmt_nofmt ? command->out_fmt : ctx->out_fmt);

    for (int i = 0; i < n_arguments; i++) {
      if (arguments[i].x != NULL) {
        free(arguments[i].x);
        arguments[i].x = NULL;
      }
    }
    // NOTE: if ctx->in or ctx->out is changed, close and return state,
    // otherwise the next command that needs a file might get sad.
    if (ctx->out != stdout) {
      fclose(ctx->out);
      ctx->out = stdout;
    }
  } else {
    if (invalid_arg == true) {
      char arg[ARGS_BUFFER_SIZE + 1];
      memset(arg, 0x0, sizeof(arg));
      strncpy(arg, args, ARGS_BUFFER_SIZE);
      char *end = strchr(args, ',');
      if (end) {
        arg[end - args] = '\0';
      }
      printf("Invalid argument %d: %s (%s)\n", i, argv[i], arg);
    } else if (command == NULL) {
      printf("Command %s%s%s not found\n", argv[0], i ? " " : "",
             i ? argv[1] : "");
    } else if (*args != '\0' || argc - 1 == 0) {
      printf("Incomplete command\n");
      for (int i = 0; i < argc; i++) {
        arguments[i].s = argv[i];
      }
      yh_com_help(NULL, arguments, fmt_nofmt);
    }
  }

  return 0;
}

static int parse_configured_connectors(yubihsm_context *ctx, char **connectors,
                                       int n_connectors) {

  ctx->n_connectors = 0;
  ctx->connector_list = NULL;

  if (n_connectors == 0) {
    return 0;
  }

  ctx->connector_list = calloc(n_connectors, sizeof(char *));
  if (ctx->connector_list == NULL) {
    return -1;
  }

  for (int i = 0; i < n_connectors; i++) {
    ctx->connector_list[i] = strdup(connectors[i]);
    if (ctx->connector_list[i] == NULL) {
      goto pcc_failure;
    }
    ctx->n_connectors++;
  }

  return 0;

pcc_failure:
  for (int i = 0; i < ctx->n_connectors; i++) {
    free(ctx->connector_list[i]);
    ctx->connector_list = NULL;
  }

  free(ctx->connector_list);
  ctx->connector_list = NULL;
  ctx->n_connectors = 0;

  return -1;
}

int main(int argc, char *argv[]) {

  yh_rc yrc;
  int comrc;

  int rc = EXIT_SUCCESS;

  struct gengetopt_args_info args_info;

  struct stat sb;
  struct cmdline_parser_params params;

  ctx.out = stdout;

  cmdline_parser_params_init(&params);
  params.initialize = 1;
  params.check_required = 0;

  if (cmdline_parser(argc, argv, &args_info) != 0) {
    return EXIT_FAILURE;
  }

  if (stat(args_info.config_file_arg, &sb) == 0) {
    if (S_ISREG(sb.st_mode) || S_ISLNK(sb.st_mode)) {
      params.initialize = 0;
      if (cmdline_parser_config_file(args_info.config_file_arg, &args_info,
                                     &params) != 0) {
        return EXIT_FAILURE;
      }
    }
  }

  if (cmdline_parser_required(&args_info, argv[0]) != 0) {
    return EXIT_FAILURE;
  }

  if (parse_configured_connectors(&ctx, args_info.connector_arg,
                                  args_info.connector_given) == -1) {
    fprintf(stderr, "Unable to parse connector list");
    rc = EXIT_FAILURE;
    goto main_exit;
  }

  if (getenv("DEBUG") != NULL) {
    args_info.verbose_arg = YH_VERB_ALL;
  }
  yh_set_verbosity(ctx.connector, args_info.verbose_arg);

  yrc = yh_init();
  if (yrc != YHR_SUCCESS) {
    fprintf(stderr, "Failed to initialize libyubihsm\n");
    rc = EXIT_FAILURE;
    goto main_exit;
  }

#ifdef USE_YKYH
  ykyh_rc ykyhrc;
  ykyhrc = ykyh_init(&ctx.state, 1); // TODO(adma): do something about verbosity
  if (ykyhrc != YKYHR_SUCCESS) {
    fprintf(stderr, "Failed to initialize libykyh\n");
    rc = EXIT_FAILURE;
    goto main_exit;
  }
#endif

  if (ctx.n_connectors == 0) {
    fprintf(stderr, "Using default connector URL: %s\n", LOCAL_CONNECTOR_URL);

    ctx.connector_list = calloc(1, sizeof(char *));
    if (ctx.connector_list == NULL) {
      fprintf(stderr, "Failed to allocate memory\n");
      rc = EXIT_FAILURE;
      goto main_exit;
    }

    ctx.connector_list[0] = strdup(LOCAL_CONNECTOR_URL);
    if (ctx.connector_list[0] == NULL) {
      fprintf(stderr, "Failed to allocate memory\n");
      rc = EXIT_FAILURE;
      goto main_exit;
    }

    ctx.n_connectors = 1;
  }

  if (args_info.cacert_given) {
    ctx.cacert = strdup(args_info.cacert_arg);
  }
  if (args_info.proxy_given) {
    ctx.proxy = strdup(args_info.proxy_arg);
  }

#ifndef __WIN32
  struct sigaction act;
  memset(&act, 0, sizeof(act));
  act.sa_handler = timer_handler;
  act.sa_flags = SA_RESTART;
  sigaction(SIGALRM, &act, NULL);

  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGALRM);
  sigprocmask(SIG_UNBLOCK, &set, NULL);
#endif

  if (args_info.action_given) {
    uint8_t buf[4096] = {0};

    ctx.out = open_file(args_info.out_arg, false);
    if (ctx.out == NULL) {
      fprintf(stderr, "Unable to open output file %s\n", args_info.out_arg);
      rc = EXIT_FAILURE;
      goto main_exit;
    }

    yh_com_connect(&ctx, NULL, fmt_nofmt);

    bool requires_session = false;
    for (unsigned i = 0; i < args_info.action_given; i++) {
      switch (args_info.action_arg[i]) {
        case action_arg_getMINUS_deviceMINUS_info:
          requires_session = false;
          break;

        default:
          requires_session = true;
      }

      if (requires_session == true) {
        break;
      }
    }

    Argument arg[7];

    if (requires_session == true) {
      arg[0].w = args_info.authkey_arg;
      arg[1].x = buf;
      arg[1].len = sizeof(buf);
      if (get_input_data(args_info.password_given ? args_info.password_arg : "-",
                         arg[1].x, &arg[1].len, fmt_password) == false) {
        fprintf(stderr, "Failed to get password\n");
        rc = EXIT_FAILURE;
        goto main_exit;
      }

      comrc = yh_com_open_session(&ctx, arg, fmt_nofmt);
      if (comrc != 0) {
        fprintf(stderr, "Failed to open session\n");
        rc = EXIT_FAILURE;
        goto main_exit;
      }
    }

    for (unsigned i = 0; i < YH_MAX_SESSIONS; i++) {
      if (ctx.sessions[i] != NULL) {
        arg[0].e = ctx.sessions[i];
      }
    }

    switch (args_info.informat_arg) {
      case informat_arg_base64:
        ctx.in_fmt = fmt_base64;
        break;
      case informat_arg_binary:
        ctx.in_fmt = fmt_binary;
        break;
      case informat_arg_PEM:
        ctx.in_fmt = fmt_PEM;
        break;
      case informat_arg_password:
        ctx.in_fmt = fmt_password;
        break;
      case informat_arg_hex:
        ctx.in_fmt = fmt_hex;
        break;
      case informat__NULL:
      case informat_arg_default:
      default:
        ctx.in_fmt = fmt_nofmt;
        break;
    }

    switch (args_info.outformat_arg) {
      case outformat_arg_base64:
        ctx.out_fmt = fmt_base64;
        break;
      case outformat_arg_binary:
        ctx.out_fmt = fmt_binary;
        break;
      case outformat_arg_PEM:
        ctx.out_fmt = fmt_PEM;
        break;
      case outformat_arg_hex:
        ctx.out_fmt = fmt_hex;
        break;
      case outformat__NULL:
      case outformat_arg_default:
      default:
        ctx.out_fmt = fmt_nofmt;
        break;
    }

    calling_device = true;

    for (unsigned i = 0; i < args_info.action_given; i++) {
      switch (args_info.action_arg[i]) {
        case action_arg_decryptMINUS_pkcs1v15: {
          arg[1].w = args_info.object_id_arg;
          arg[2].x = buf;
          arg[2].len = sizeof(buf);
          if (get_input_data(args_info.in_arg, arg[2].x, &arg[2].len,
                             ctx.in_fmt == fmt_nofmt ? fmt_binary
                                                     : ctx.in_fmt) == false) {
            fprintf(stderr, "Failed to get input data\n");
            rc = EXIT_FAILURE;
            break;
          }
          comrc =
            yh_com_decrypt_pkcs1v1_5(&ctx, arg,
                                     ctx.out_fmt == fmt_nofmt ? fmt_binary
                                                              : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to decrypt data");
        } break;

        case action_arg_deriveMINUS_ecdh: {
          arg[1].w = args_info.object_id_arg;
          arg[2].x = buf;
          arg[2].len = sizeof(buf);
          if (get_input_data(args_info.in_arg, arg[2].x, &arg[2].len,
                             ctx.in_fmt == fmt_nofmt ? fmt_binary
                                                     : ctx.in_fmt) == false) {
            fprintf(stderr, "Failed to get input data\n");
            rc = EXIT_FAILURE;
            break;
          }
          comrc = yh_com_derive_ecdh(&ctx, arg,
                                     ctx.out_fmt == fmt_nofmt ? fmt_hex
                                                              : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to perform ECDH key exchange");
        } break;

        case action_arg_decryptMINUS_oaep:
        case action_arg_decryptMINUS_aesccm:
        case action_arg_encryptMINUS_aesccm:
          LIB_SUCCEED_OR_DIE(YHR_GENERIC_ERROR, "Command not implemented: ");

        case action_arg_generateMINUS_asymmetricMINUS_key: {
          if (args_info.algorithm_given == 0) {
            fprintf(stderr, "Missing argument algorithm\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          arg[2].s = args_info.label_arg;
          arg[2].len = strlen(args_info.label_arg);
          yrc = yh_string_to_domains(args_info.domains_arg, &arg[3].w);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse domains: ");

          memset(&arg[4].c, 0, sizeof(yh_capabilities));
          yrc =
            yh_string_to_capabilities(args_info.capabilities_arg, &arg[4].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          yrc = yh_string_to_algo(args_info.algorithm_arg, &arg[5].a);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse algorithm: ");

          comrc = yh_com_generate_asymmetric(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to generate asymmetric key");
        } break;

        case action_arg_generateMINUS_hmacMINUS_key: {
          if (args_info.algorithm_given == 0) {
            fprintf(stderr, "Missing argument algorithm\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          arg[2].s = args_info.label_arg;
          arg[2].len = strlen(args_info.label_arg);
          yrc = yh_string_to_domains(args_info.domains_arg, &arg[3].w);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse domains: ");

          memset(&arg[4].c, 0, sizeof(yh_capabilities));
          yrc =
            yh_string_to_capabilities(args_info.capabilities_arg, &arg[4].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          yrc = yh_string_to_algo(args_info.algorithm_arg, &arg[5].a);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse algorithm: ");

          comrc = yh_com_generate_hmac(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to generate hmac key");
        } break;

        case action_arg_generateMINUS_wrapMINUS_key: {
          if (args_info.algorithm_given == 0) {
            fprintf(stderr, "Missing argument algorithm\n");
            rc = EXIT_FAILURE;
            break;
          }

          if (args_info.delegated_given == 0) {
            fprintf(stderr, "Missing delegated capabilities\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          arg[2].s = args_info.label_arg;
          arg[2].len = strlen(args_info.label_arg);
          yrc = yh_string_to_domains(args_info.domains_arg, &arg[3].w);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse domains: ");

          memset(&arg[4].c, 0, sizeof(yh_capabilities));
          yrc =
            yh_string_to_capabilities(args_info.capabilities_arg, &arg[4].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          yrc = yh_string_to_algo(args_info.algorithm_arg, &arg[5].a);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse algorithm: ");

          memset(&arg[6].c, 0, sizeof(yh_capabilities));
          yrc = yh_string_to_capabilities(args_info.delegated_arg, &arg[6].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          comrc = yh_com_generate_wrap(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to generate wrap key");
        } break;

        case action_arg_generateMINUS_otpMINUS_aeadMINUS_key: {
          if (args_info.algorithm_given == 0) {
            fprintf(stderr, "Missing argument algorithm\n");
            rc = EXIT_FAILURE;
            break;
          }

          if (args_info.nonce_given == 0) {
            fprintf(stderr, "Missing argument nonce\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          arg[2].s = args_info.label_arg;
          arg[2].len = strlen(args_info.label_arg);
          yrc = yh_string_to_domains(args_info.domains_arg, &arg[3].w);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse domains: ");

          memset(&arg[4].c, 0, sizeof(yh_capabilities));
          yrc =
            yh_string_to_capabilities(args_info.capabilities_arg, &arg[4].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          yrc = yh_string_to_algo(args_info.algorithm_arg, &arg[5].a);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse algorithm: ");

          arg[6].d = args_info.nonce_arg;

          comrc = yh_com_generate_otp_aead_key(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to generate otp key");
        } break;

        case action_arg_getMINUS_opaque: {
          arg[1].w = args_info.object_id_arg;

          comrc = yh_com_get_opaque(&ctx, arg,
                                    ctx.out_fmt == fmt_nofmt ? fmt_binary
                                                             : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to get opaque object");
        } break;

        case action_arg_getMINUS_pseudoMINUS_random: {
          arg[1].w = args_info.count_arg;

          comrc =
            yh_com_get_random(&ctx, arg,
                              ctx.out_fmt == fmt_nofmt ? fmt_hex : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to get random bytes");
        } break;

        case action_arg_getMINUS_storageMINUS_info:
          comrc = yh_com_get_storage(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to get storage stats");
          break;

        case action_arg_getMINUS_publicMINUS_key: {
          arg[1].w = args_info.object_id_arg;
          arg[2].s = args_info.out_arg;
          arg[2].len = strlen(args_info.out_arg);

          comrc =
            yh_com_get_pubkey(&ctx, arg,
                              ctx.out_fmt == fmt_nofmt ? fmt_PEM : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to get public key");
        } break;

        case action_arg_getMINUS_objectMINUS_info: {
          if (args_info.object_type_given == 0) {
            fprintf(stderr, "Missing argument object type\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          yrc = yh_string_to_type(args_info.object_type_arg, &arg[2].t);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse type: ");

          comrc = yh_com_get_object_info(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to get object info");
        } break;

        case action_arg_getMINUS_wrapped: {
          if (args_info.object_type_given == 0) {
            fprintf(stderr, "Missing argument object-type\n");
            rc = EXIT_FAILURE;
            break;
          }

          if (args_info.wrap_id_given == 0) {
            fprintf(stderr, "Missing argument wrap-id\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          yrc = yh_string_to_type(args_info.object_type_arg, &arg[2].t);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse type: ");

          arg[3].w = args_info.wrap_id_arg;

          arg[4].s = args_info.out_arg;
          arg[4].len = strlen(args_info.out_arg);

          comrc = yh_com_get_wrapped(&ctx, arg,
                                     ctx.out_fmt == fmt_nofmt ? fmt_base64
                                                              : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to get wrapped object");
        } break;

        case action_arg_getMINUS_deviceMINUS_info:
          comrc = yh_com_get_device_info(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to get device info");
          break;

        case action_arg_getMINUS_template: {
          arg[1].w = args_info.object_id_arg;

          comrc = yh_com_get_template(&ctx, arg,
                                      ctx.out_fmt == fmt_nofmt ? fmt_base64
                                                               : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to get template object");
        } break;

        case action_arg_listMINUS_objects: {
          if (args_info.algorithm_given == 0) {
            fprintf(stderr, "Missing argument algorithm\n");
            rc = EXIT_FAILURE;
            break;
          }

          if (args_info.object_type_given == 0) {
            fprintf(stderr, "Missing argument object-type\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          yrc = yh_string_to_type(args_info.object_type_arg, &arg[2].t);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse type: ");

          yrc = yh_string_to_domains(args_info.domains_arg, &arg[3].w);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse domains: ");

          memset(&arg[4].c, 0, sizeof(yh_capabilities));
          yrc =
            yh_string_to_capabilities(args_info.capabilities_arg, &arg[4].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          yrc = yh_string_to_algo(args_info.algorithm_arg, &arg[5].a);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse algorithm: ");

          arg[6].s = args_info.label_arg;
          arg[6].len = strlen(args_info.label_arg);

          comrc = yh_com_list_objects(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to list objects");
        } break;

        case action_arg_putMINUS_authenticationMINUS_key: {
          if (args_info.new_password_given == 0) {
            fprintf(stderr, "Missing argument new-password\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          arg[2].s = args_info.label_arg;
          arg[2].len = strlen(args_info.label_arg);
          yrc = yh_string_to_domains(args_info.domains_arg, &arg[3].w);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse domains: ");

          memset(&arg[4].c, 0, sizeof(yh_capabilities));
          yrc =
            yh_string_to_capabilities(args_info.capabilities_arg, &arg[4].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          memset(&arg[5].c, 0, sizeof(yh_capabilities));
          yrc = yh_string_to_capabilities(args_info.delegated_arg, &arg[5].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          arg[6].x = (uint8_t *) args_info.new_password_arg;
          arg[6].len = strlen(args_info.new_password_arg);

          comrc = yh_com_put_authentication(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to store authentication key");
        } break;

        case action_arg_putMINUS_asymmetricMINUS_key: {
          arg[1].w = args_info.object_id_arg;
          arg[2].s = args_info.label_arg;
          arg[2].len = strlen(args_info.label_arg);

          yrc = yh_string_to_domains(args_info.domains_arg, &arg[3].w);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse domains: ");

          memset(&arg[4].c, 0, sizeof(yh_capabilities));
          yrc =
            yh_string_to_capabilities(args_info.capabilities_arg, &arg[4].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          arg[5].x = buf;
          arg[5].len = sizeof(buf);
          if (get_input_data(args_info.in_arg, arg[5].x, &arg[5].len,
                             ctx.in_fmt == fmt_nofmt ? fmt_PEM : ctx.in_fmt) ==
              false) {
            fprintf(stderr, "Failed to get input data\n");
            rc = EXIT_FAILURE;
            break;
          }
          comrc = yh_com_put_asymmetric(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to store asymmetric key");
        } break;

        case action_arg_putMINUS_opaque: {
          if (args_info.algorithm_given == 0) {
            fprintf(stderr, "Missing argument algorithm\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          arg[2].s = args_info.label_arg;
          arg[2].len = strlen(args_info.label_arg);

          yrc = yh_string_to_domains(args_info.domains_arg, &arg[3].w);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse domains: ");

          memset(&arg[4].c, 0, sizeof(yh_capabilities));
          yrc =
            yh_string_to_capabilities(args_info.capabilities_arg, &arg[4].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          yrc = yh_string_to_algo(args_info.algorithm_arg, &arg[5].a);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse algorithm: ");

          arg[6].x = buf;
          arg[6].len = sizeof(buf);
          if (get_input_data(args_info.in_arg, arg[6].x, &arg[6].len,
                             ctx.in_fmt == fmt_nofmt ? fmt_binary
                                                     : ctx.in_fmt) == false) {
            fprintf(stderr, "Failed to get input data\n");
            rc = EXIT_FAILURE;
            break;
          }

          comrc = yh_com_put_opaque(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to store opaque object");
        } break;

        case action_arg_setMINUS_option:
          LIB_SUCCEED_OR_DIE(YHR_GENERIC_ERROR, "Command not implemented: ");

        case action_arg_putMINUS_hmacMINUS_key:
          LIB_SUCCEED_OR_DIE(YHR_GENERIC_ERROR, "Command not implemented: ");
          // TODO(adma): this requires a hex parser

        case action_arg_putMINUS_wrapMINUS_key: {

          if (args_info.delegated_given == 0) {
            fprintf(stderr, "Missing delegated capabilities\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;

          arg[2].s = args_info.label_arg;
          arg[2].len = strlen(args_info.label_arg);

          yrc = yh_string_to_domains(args_info.domains_arg, &arg[3].w);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse domains: ");

          memset(&arg[4].c, 0, sizeof(yh_capabilities));
          yrc =
            yh_string_to_capabilities(args_info.capabilities_arg, &arg[4].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          memset(&arg[5].c, 0, sizeof(yh_capabilities));
          yrc = yh_string_to_capabilities(args_info.delegated_arg, &arg[5].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          arg[6].x = buf;
          arg[6].len = sizeof(buf);
          if (get_input_data(args_info.in_arg, arg[6].x, &arg[6].len,
                             ctx.in_fmt == fmt_nofmt ? fmt_hex : ctx.in_fmt) ==
              false) {
            fprintf(stderr, "Failed to get input data\n");
            rc = EXIT_FAILURE;
            break;
          }

          comrc = yh_com_put_wrapkey(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to put wrapkey");
        } break;

        case action_arg_putMINUS_wrapped: {
          if (args_info.wrap_id_given == 0) {
            fprintf(stderr, "Missing argument wrap-id\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.wrap_id_arg;
          arg[2].x = buf;
          arg[2].len = sizeof(buf);
          if (get_input_data(args_info.in_arg, arg[2].x, &arg[2].len,
                             ctx.in_fmt == fmt_nofmt ? fmt_base64
                                                     : ctx.in_fmt) == false) {
            fprintf(stderr, "Failed to get input data\n");
            rc = EXIT_FAILURE;
            break;
          }

          comrc = yh_com_put_wrapped(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to store wrapped object");
        } break;

        case action_arg_putMINUS_template: {
          if (args_info.algorithm_given == 0) {
            fprintf(stderr, "Missing argument algorithm\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          arg[2].s = args_info.label_arg;
          arg[2].len = strlen(args_info.label_arg);

          yrc = yh_string_to_domains(args_info.domains_arg, &arg[3].w);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse domains: ");

          memset(&arg[4].c, 0, sizeof(yh_capabilities));
          yrc =
            yh_string_to_capabilities(args_info.capabilities_arg, &arg[4].c);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse capabilities: ");

          yrc = yh_string_to_algo(args_info.algorithm_arg, &arg[5].a);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse algorithm: ");

          arg[6].x = buf;
          arg[6].len = sizeof(buf);
          if (get_input_data(args_info.in_arg, arg[6].x, &arg[6].len,
                             ctx.in_fmt == fmt_nofmt ? fmt_binary
                                                     : ctx.in_fmt) == false) {
            fprintf(stderr, "Failed to get input data\n");
            rc = EXIT_FAILURE;
            break;
          }

          comrc = yh_com_put_template(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to store template object");
        } break;

        case action_arg_putMINUS_otpMINUS_aeadMINUS_key:
          LIB_SUCCEED_OR_DIE(YHR_GENERIC_ERROR, "Command not implemented: ");
          // TODO(adma): this requires a hex parser

        case action_arg_signMINUS_eddsa:
        case action_arg_signMINUS_ecdsa: {
          if (args_info.algorithm_given == 0) {
            fprintf(stderr, "Missing argument algorithm\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          yrc = yh_string_to_algo(args_info.algorithm_arg, &arg[2].a);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse algorithm: ");

          arg[3].x = buf;
          arg[3].len = sizeof(buf);
          if (get_input_data(args_info.in_arg, arg[3].x, &arg[3].len,
                             ctx.in_fmt == fmt_nofmt ? fmt_binary
                                                     : ctx.in_fmt) == false) {
            fprintf(stderr, "Failed to get input data\n");
            rc = EXIT_FAILURE;
            break;
          }

          if (args_info.action_arg[i] == action_arg_signMINUS_ecdsa) {
            comrc = yh_com_sign_ecdsa(&ctx, arg,
                                      ctx.out_fmt == fmt_nofmt ? fmt_base64
                                                               : ctx.out_fmt);
          } else {
            comrc = yh_com_sign_eddsa(&ctx, arg,
                                      ctx.out_fmt == fmt_nofmt ? fmt_base64
                                                               : ctx.out_fmt);
          }

          COM_SUCCEED_OR_DIE(comrc, "Unable to sign data");
        } break;

        case action_arg_signMINUS_pkcs1v15: {
          if (args_info.algorithm_given == 0) {
            fprintf(stderr, "Missing argument algorithm\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          yrc = yh_string_to_algo(args_info.algorithm_arg, &arg[2].a);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse algorithm: ");

          arg[3].x = buf;
          arg[3].len = sizeof(buf);
          if (get_input_data(args_info.in_arg, arg[3].x, &arg[3].len,
                             ctx.in_fmt == fmt_nofmt ? fmt_binary
                                                     : ctx.in_fmt) == false) {
            fprintf(stderr, "Failed to get input data\n");
            rc = EXIT_FAILURE;
            break;
          }

          comrc = yh_com_sign_pkcs1v1_5(&ctx, arg,
                                        ctx.out_fmt == fmt_nofmt ? fmt_base64
                                                                 : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to sign data");
        } break;

        case action_arg_signMINUS_pss: {
          if (args_info.algorithm_given == 0) {
            fprintf(stderr, "Missing argument algorithm\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          yrc = yh_string_to_algo(args_info.algorithm_arg, &arg[2].a);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse algorithm: ");

          arg[3].x = buf;
          arg[3].len = sizeof(buf);
          if (get_input_data(args_info.in_arg, arg[3].x, &arg[3].len,
                             ctx.in_fmt == fmt_nofmt ? fmt_binary
                                                     : ctx.in_fmt) == false) {
            fprintf(stderr, "Failed to get input data\n");
            rc = EXIT_FAILURE;
            break;
          }

          comrc = yh_com_sign_pss(&ctx, arg,
                                  ctx.out_fmt == fmt_nofmt ? fmt_base64
                                                           : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to sign data");
        } break;

        case action_arg_signMINUS_hmac:
          LIB_SUCCEED_OR_DIE(YHR_GENERIC_ERROR, "Command not implemented: ");
          // TODO(adma): this requires a hex parser

        case action_arg_reset: {
          comrc = yh_com_reset(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to reset device");
        } break;

        case action_arg_deleteMINUS_object: {
          if (args_info.object_type_given == 0) {
            fprintf(stderr, "Missing argument object type\n");
            rc = EXIT_FAILURE;
            break;
          }

          yrc = yh_string_to_type(args_info.object_type_arg, &arg[2].t);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse type: ");
          arg[1].w = args_info.object_id_arg;

          comrc = yh_com_delete(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to delete object");
        } break;

        case action_arg_signMINUS_sshMINUS_certificate: {
          if (args_info.template_id_given == 0) {
            fprintf(stderr, "Missing argument template-id\n");
            rc = EXIT_FAILURE;
            break;
          }

          if (args_info.algorithm_given == 0) {
            fprintf(stderr, "Missing argument algorithm\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          arg[2].w = args_info.template_id_arg;
          yrc = yh_string_to_algo(args_info.algorithm_arg, &arg[3].a);
          LIB_SUCCEED_OR_DIE(yrc, "Unable to parse algorithm: ");

          arg[4].x = buf;
          arg[4].len = sizeof(buf);
          if (get_input_data(args_info.in_arg, arg[4].x, &arg[4].len,
                             ctx.in_fmt == fmt_nofmt ? fmt_binary
                                                     : ctx.in_fmt) ==
              false) { // TODO: correct format?
            fprintf(stderr, "Failed to get input data\n");
            rc = EXIT_FAILURE;
            break;
          }

          comrc =
            yh_com_sign_ssh_certificate(&ctx, arg,
                                        ctx.out_fmt == fmt_nofmt ? fmt_binary
                                                                 : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to get ssh certificate");
        } break;

        case action_arg_benchmark:
          LIB_SUCCEED_OR_DIE(YHR_GENERIC_ERROR, "Command not implemented: ");

        case action_arg_createMINUS_otpMINUS_aead:
          LIB_SUCCEED_OR_DIE(YHR_GENERIC_ERROR, "Command not implemented: ");
          // TODO(adma): this requires a hex parser

        case action_arg_randomizeMINUS_otpMINUS_aead: {
          arg[1].w = args_info.object_id_arg;
          arg[2].s = args_info.out_arg;
          arg[2].len = strlen(args_info.out_arg);

          comrc =
            yh_com_otp_aead_random(&ctx, arg,
                                   ctx.out_fmt == fmt_nofmt ? fmt_binary
                                                            : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to get aead from random");
        } break;

        case action_arg_decryptMINUS_otp:
          LIB_SUCCEED_OR_DIE(YHR_GENERIC_ERROR, "Command not implemented: ");
          // TODO(adma): this requires a hex parser

        case action_arg_signMINUS_attestationMINUS_certificate: {
          if (args_info.attestation_id_given == 0) {
            fprintf(stderr, "Missing argument attestation-id\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.object_id_arg;
          arg[2].w = args_info.attestation_id_arg;

          comrc = yh_com_sign_attestation_certificate(&ctx, arg,
                                                      ctx.out_fmt == fmt_nofmt
                                                        ? fmt_PEM
                                                        : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to attest asymmetric key");
        } break;

        case action_arg_getMINUS_logs: {
          comrc =
            yh_com_audit(&ctx, arg,
                         ctx.out_fmt == fmt_nofmt ? fmt_ASCII : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to extract logs");
        } break;

        case action_arg_setMINUS_logMINUS_index: {
          if (args_info.log_index_given == 0) {
            fprintf(stderr, "Missing argument log-index\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.log_index_arg;

          comrc = yh_com_set_log_index(&ctx, arg,
                                       ctx.out_fmt == fmt_nofmt ? fmt_ASCII
                                                                : ctx.out_fmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to set log index");
        } break;

        case action_arg_blinkMINUS_device: {
          if(args_info.duration_arg < 0 || args_info.duration_arg > 0xff) {
            fprintf(stderr, "Duration must be in [0, 256]\n");
            rc = EXIT_FAILURE;
            break;
          }

          arg[1].w = args_info.duration_arg;

          comrc = yh_com_blink(&ctx, arg, fmt_nofmt);
          COM_SUCCEED_OR_DIE(comrc, "Unable to blink device");
        } break;

        case action__NULL:
          printf("ERROR !%u \n", args_info.action_given);
          rc = EXIT_FAILURE;
      }

      if (rc == EXIT_FAILURE) {
        break;
      }
    }

    calling_device = false;

    if (requires_session == true) {
      yh_util_close_session(arg[0].e);
    }

  } else {
    int num;
#ifndef __WIN32
    EditLine *el;

    HistEvent ev;

    g_hist = history_init();

    history(g_hist, &ev, H_SETSIZE, 100); // NOTE(adma): 100 history items

    el = el_init(*argv, stdin, stdout, stderr);

    el_set(el, EL_EDITOR, "emacs");

#ifdef EL_PROMPT_ESC
    el_set(el, EL_PROMPT_ESC, prompt, '\1'); /* Set the prompt function */
#else
    el_set(el, EL_PROMPT, prompt); /* Set the prompt function */
#endif /* EL_PROMPT_ESC */

    el_set(el, EL_HIST, history, g_hist);

    /* Add a user-defined function    */
    el_set(el, EL_ADDFN, "yh_complete", "Complete argument", yubihsm_complete);

    /* Bind tab to it         */
    el_set(el, EL_BIND, "^I", "yh_complete", NULL);

    el_source(el, NULL); // NOTE(adma): source the user's defaults file
#endif

    create_command_list(&g_commands);

    while (g_running == true) {
#ifdef __WIN32
      fprintf(stdout, PROMPT);
      char data[1025];
      char *buf = fgets(data, sizeof(data), stdin);
      if (buf) {
        num = strlen(buf);
      }
#else
      const char *buf = el_gets(el, &num);
#endif

      if (buf == NULL) {
        // NOTE(adma): got Ctrl-D
        yh_com_quit(NULL, NULL, fmt_nofmt);
        fprintf(stdout, "\n");
      } else if (num > 0 && buf[0] != '\n' && buf[0] != '\r') {
#ifndef __WIN32
        history(g_hist, &ev, H_ENTER, buf);
#endif
        calling_device = true;
        validate_and_call(&ctx, g_commands, buf);
        calling_device = false;
      }
    }

#ifndef __WIN32
    el_end(el);
    history_end(g_hist);
#endif
  }

main_exit:

  cmdline_parser_free(&args_info);

  if (ctx.out != stdout && ctx.out != NULL) {
    fclose(ctx.out);
  }

  if (ctx.cacert) {
    free(ctx.cacert);
  }
  if (ctx.proxy) {
    free(ctx.proxy);
  }

  yh_exit();

#ifdef USE_YKYH
  ykyh_done(ctx.state); // TODO(adma): more consistent naming
  ctx.state = NULL;
#endif

  return rc;
}
