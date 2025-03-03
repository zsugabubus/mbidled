#ifndef MBIDLED_H
#define MBIDLED_H

#include <stddef.h>

extern char const *opt_cmd;
extern int opt_verbose;

void mb_log(int level, char const *format, ...);

#define container_of(ptr, base, member) \
	(base *)(/* typeof(ptr) == typeof(base->member) */ \
		 (char *)(ptr - &((base *)0)->member + &((base *)0)->member) - \
		 offsetof(base, member) \
	)

static inline void *
oom(void *p)
{
	if (p == NULL)
		abort();
	return p;
}

#define snprintf_safe(buf, ...) \
	do { \
		if (snprintf(buf, sizeof buf, __VA_ARGS__) >= (int)sizeof buf) \
			abort(); \
	} while (0)

#endif
