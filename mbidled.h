#ifndef MBIDLED_H
#define MBIDLED_H

#include <stddef.h>

extern char const *opt_cmd;
extern int opt_reaction_time;
extern int opt_rerun_delay;
extern int opt_verbose;

void print_log(int priority, char const *message);

#define container_of(ptr, base, member) (base *)( \
	/* typeof(ptr) == typeof(base->member) */ \
	(char *)(ptr - &((base *)0)->member + &((base *)0)->member) \
	- offsetof(base, member) \
)

#define ASSERT(c) do { \
	if (!(c)) \
		abort(); \
} while (0)

#define ASSERT_SNPRINTF(buf, ...) \
	ASSERT(snprintf(buf, sizeof buf, __VA_ARGS__) < (int)sizeof buf)

#endif
