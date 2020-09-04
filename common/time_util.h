//
// Created by aveen on 2020-08-24.
//

#ifndef YUBIHSM_SHELL_TIME_UTIL_H
#define YUBIHSM_SHELL_TIME_UTIL_H

#include "../lib/platform-config.h"

#ifndef _MSVC
#include <sys/time.h>
#endif

int get_time_of_day(struct timeval *__restrict tv, struct timezone *tz);

#endif // YUBIHSM_SHELL_TIME_UTIL_H
