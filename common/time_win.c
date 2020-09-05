//
// Created by aveen on 2020-08-24.
//

#include "time_win.h"
#include <winsock2.h>

int gettimeofday_win(struct timeval *__restrict tv) {
  // There's no equivalent implementation of gettimeofday() on Window
  struct timespec ts;
  timespec_get(&ts, TIME_UTC);
  tv->tv_sec = ts.tv_sec;
  tv->tv_usec = ts.tv_nsec;
  return 0;
}
