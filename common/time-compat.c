//
// Created by aveen on 2020-08-24.
//

#include "time-compat.h"
#include "../lib/yubihsm-config.h"

#ifdef __WIN32
#include <windows.h>
#include <winsock2.h>
#endif
#include <time.h>


int get_time_of_day (struct timeval *__restrict tv, struct timezone * tz) {
  // There's no equivalent implementation of gettimeofday() on Windows
#ifdef __WIN32
  unsigned __int64 epoch = 116444736000000000Ui64;
  FILETIME    file_time;
  SYSTEMTIME  system_time;
  ULARGE_INTEGER ularge;

  GetSystemTime(&system_time);
  SystemTimeToFileTime(&system_time, &file_time);
  ularge.LowPart = file_time.dwLowDateTime;
  ularge.HighPart = file_time.dwHighDateTime;

  tv->tv_sec = ((ularge.QuadPart - epoch) / 10000000L);
  tv->tv_usec = (system_time.wMilliseconds * 1000);

  return 0;
#else
  return gettimeofday(tv, tz);
#endif
}

