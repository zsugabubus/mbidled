#ifndef MBIDLED_CHANNEL_H
#define MBIDLED_CHANNEL_H

#include <sys/queue.h>
#include <ev.h>

struct mbconfig;
struct mbconfig_channel;
struct mbconfig_store;
struct channel_mailbox;

struct channel {
#ifdef EV_MULTIPLICITY
	struct ev_loop *loop;
#endif
	struct mbconfig *mb_config;
	struct mbconfig_channel *mb_chan;

	LIST_HEAD(, channel_mailbox) boxes;
};

void channel_open(EV_P_ struct mbconfig *mb_config, struct mbconfig_channel *mb_chan);
void channel_notify_change(struct channel *chan, struct mbconfig_store *mb_store,
		char const *mailbox);
void channel_vlog(struct channel const *chan, int priority,
		char const *group, char const *name,
		char const *format, va_list ap);

void imap_open_store(struct channel *chan, struct mbconfig_store *mb_store);
void maildir_open_store(struct channel *chan, struct mbconfig_store *mb_store);

#define DEFINE_CHANNEL_STORE_LOGGER(prefix, name) \
	static void \
	prefix##_vlog(struct channel *chan, char const *mailbox_name, int priority, char const *format, va_list ap) \
	{ \
		channel_vlog(chan, priority, name, mailbox_name, format, ap); \
	} \
 \
	static void \
	prefix##_log(struct channel *chan, int priority, char const *format, ...) \
	{ \
		va_list ap; \
		va_start(ap, format); \
		prefix##_vlog(chan, NULL, priority, format, ap); \
		va_end(ap); \
	} \
 \
	static void \
	store_log(struct prefix##_store *store, int priority, char const *format, ...) \
	{ \
		va_list ap; \
		va_start(ap, format); \
		prefix##_vlog(store->chan, store->mailbox, priority, format, ap); \
		va_end(ap); \
	}

#endif
