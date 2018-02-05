#pragma once

#ifdef WIN32

#include <time.h>

#ifdef _MSC_VER
#define localtime_r(src, dst) localtime_s(dst, src)
#else
#define localtime_r(src, dst) ({ \
struct tm *tmp_tm; \
pthread_testcancel(); \
tmp_tm = localtime((src));\
if(tmp_tm) { \
    *(dst) = *tmp_tm; \
    tmp_tm = (dst); \
} \
tmp_tm; })
#endif

#endif
