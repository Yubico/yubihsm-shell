/*
 * Copyright 2026 Yubico AB
 * Copyright 2026 Eastwdd (d/b/a CS Play)
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

// Test that yh_connect() distinguishes an endpoint that answers but fails
// the TLS handshake (YHR_CONNECTION_ERROR) from an endpoint where nothing
// is listening (YHR_CONNECTOR_NOT_FOUND). Only loopback sockets are used.

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "yubihsm.h"

static int open_loopback_listener(uint16_t *port) {
  struct sockaddr_in addr = {0};
  socklen_t addr_len = sizeof(addr);
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  assert(fd >= 0);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  assert(bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == 0);
  assert(listen(fd, 1) == 0);
  assert(getsockname(fd, (struct sockaddr *) &addr, &addr_len) == 0);
  *port = ntohs(addr.sin_port);

  return fd;
}

// Accept connections and answer with plaintext so that a TLS client fails
// its handshake immediately instead of timing out.
static pid_t start_plaintext_responder(int listen_fd) {
  pid_t pid = fork();
  assert(pid >= 0);
  if (pid == 0) {
    // Self-destruct so that a failing parent cannot leave an orphan
    // responder behind keeping the test runner waiting for output.
    alarm(30);
    for (;;) {
      int conn = accept(listen_fd, NULL, NULL);
      if (conn < 0) {
        continue;
      }
      const char response[] = "HTTP/1.0 200 OK\r\n\r\nplaintext\r\n";
      if (write(conn, response, sizeof(response) - 1) < 0) {
        // Nothing to do, the connection is closed below either way.
      }
      close(conn);
    }
  }
  return pid;
}

static yh_rc connect_to(const char *url) {
  yh_connector *connector = NULL;
  yh_rc yrc = yh_init_connector(url, &connector);
  assert(yrc == YHR_SUCCESS);
  yrc = yh_connect(connector, 5);
  yh_disconnect(connector);
  return yrc;
}

static void test_tls_handshake_failure(void) {
  uint16_t port = 0;
  int listen_fd = open_loopback_listener(&port);
  pid_t responder = start_plaintext_responder(listen_fd);
  char url[64];

  int n = snprintf(url, sizeof(url), "https://127.0.0.1:%u", port);
  assert(n > 0 && (size_t) n < sizeof(url));
  assert(connect_to(url) == YHR_CONNECTION_ERROR);

  kill(responder, SIGKILL);
  waitpid(responder, NULL, 0);
  close(listen_fd);
}

static void test_nothing_listening(void) {
  uint16_t port = 0;
  int listen_fd = open_loopback_listener(&port);
  char url[64];

  // Close the listener so that connections to the port are refused.
  close(listen_fd);

  int n = snprintf(url, sizeof(url), "http://127.0.0.1:%u", port);
  assert(n > 0 && (size_t) n < sizeof(url));
  assert(connect_to(url) == YHR_CONNECTOR_NOT_FOUND);

  n = snprintf(url, sizeof(url), "https://127.0.0.1:%u", port);
  assert(n > 0 && (size_t) n < sizeof(url));
  assert(connect_to(url) == YHR_CONNECTOR_NOT_FOUND);
}

int main(void) {
  (void) signal(SIGPIPE, SIG_IGN);
  // Bound the whole test so that it fails instead of hanging.
  alarm(60);
  assert(yh_init() == YHR_SUCCESS);

  test_tls_handshake_failure();
  test_nothing_listening();

  assert(yh_exit() == YHR_SUCCESS);
  return 0;
}
