#ifndef MBIDLED_CHANNEL_H
#define MBIDLED_CHANNEL_H

#include <ev.h>
#include <sys/queue.h>

struct mbconfig;
struct mbconfig_channel;
struct mbconfig_store;
struct channel_mailbox;

struct channel {
#ifdef EV_MULTIPLICITY
	struct ev_loop *loop;
#endif
	struct mbconfig const *mb_config;
	struct mbconfig_channel const *mb_chan;

	LIST_HEAD(, channel_mailbox) boxes;
};

void channel_open(EV_P_ struct mbconfig const *mb_config, struct mbconfig_channel const *mb_chan);
void channel_notify_change(
	struct channel *chan, struct mbconfig_store const *mb_store, char const *mailbox
);

void imap_open_store(struct channel *chan, struct mbconfig_store const *mb_store);
void maildir_open_store(struct channel *chan, struct mbconfig_store const *mb_store);

void channel_log(struct channel const *chan, int level, char const *format, ...);
void channel_store_log(
	struct channel const *chan, char const *store_name, char const *mailbox, int level,
	char const *format, va_list ap
);

#define DEFINE_CHANNEL_STORE_LOGGER(store, store_name) \
	static void store##_log( \
		struct store##_store const *store, int level, char const *format, ... \
	) \
	{ \
		va_list ap; \
		va_start(ap, format); \
		channel_store_log(store->chan, store_name, store->mailbox, level, format, ap); \
		va_end(ap); \
	}

#endif
