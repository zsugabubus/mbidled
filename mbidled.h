#ifndef MBIDLED_H
#define MBIDLED_H

#include <stddef.h>

extern char const *opt_config;
extern char const *opt_cmd;
extern int opt_reaction_time;
extern int opt_rerun_delay;
extern int opt_verbose;

void print_vlog(int priority, char const *format, va_list ap);
void print_log(int priority, char const *format, ...);
void print_log_context(int priority, char const *group, char const *name);

#define container_of(ptr, base, member) (base *)( \
	/* typeof(ptr) == typeof(base->member) */ \
	(char *)(ptr - &((base *)0)->member + &((base *)0)->member) \
	- offsetof(base, member) \
)

#define ASSERT(c) do { \
	if (!(c)) { \
		fprintf(stderr, "Assertion failed at %s:%u. That's all we know.", __FILE__, __LINE__); \
		abort(); \
	} \
} while (0)

#define ASSERT_SNPRINTF(buf, ...) \
	ASSERT((int)sizeof buf > snprintf(buf, sizeof buf, __VA_ARGS__))

#endif
