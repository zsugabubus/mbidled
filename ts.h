#ifndef MBIDLED_TIME_H
#define MBIDLED_TIME_H

#include <time.h>

static long const MSEC_PER_SEC = 1000;
static long const NSEC_PER_MSEC = 1000000;

static inline void
ts_set_ms(struct timespec *ts, long ms)
{
	ts->tv_sec = ms / MSEC_PER_SEC;
	ts->tv_nsec = (ms % MSEC_PER_SEC) * NSEC_PER_MSEC;
}

static inline long
ts_sub_ms(struct timespec const *later, struct timespec const *earlier)
{
	return
		(later->tv_sec - earlier->tv_sec) * MSEC_PER_SEC +
		(later->tv_nsec - earlier->tv_nsec) / NSEC_PER_MSEC;
}

#endif
