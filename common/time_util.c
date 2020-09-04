//
// Created by aveen on 2020-08-24.
//

#include "time_util.h"

#ifdef _MSVC
#include <winsock2.h>
#include <time.h>
#endif

int get_time_of_day(struct timeval *__restrict tv, struct timezone *tz) {
  // There's no equivalent implementation of gettimeofday() on Windows
#ifdef _MSVC
  struct timespec ts;
  timespec_get(&ts, TIME_UTC);
  tv->tv_sec = ts.tv_sec;
  tv->tv_usec = ts.tv_nsec;
  return 0;
#else
  return gettimeofday(tv, tz);
#endif
}
