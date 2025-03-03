#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>

#include "channel.h"
#include "mbconfig.h"
#include "mbidled.h"

struct maildir_store {
	struct channel *chan;
	struct mbconfig_store const *mb_store;
	char *mailbox;

	char cur_path[PATH_MAX];
	char new_path[PATH_MAX];
	ev_stat cur_watcher;
	ev_stat new_watcher;
};

DEFINE_CHANNEL_STORE_LOGGER(maildir, "Maildir")

static void
maildir_notify_change(struct maildir_store *store)
{
	maildir_log(store, LOG_DEBUG, "Changed");
	channel_notify_change(store->chan, store->mb_store, store->mailbox);
}

static void
cur_stat_cb(EV_P_ ev_stat *w, int revents)
{
	(void)revents;
	struct maildir_store *store = container_of(w, struct maildir_store, cur_watcher);
	maildir_notify_change(store);
}

static void
new_stat_cb(EV_P_ ev_stat *w, int revents)
{
	(void)revents;
	struct maildir_store *store = container_of(w, struct maildir_store, new_watcher);
	maildir_notify_change(store);
}

static void
maildir_open_mailbox(
	struct channel *chan, struct mbconfig_store const *mb_store, char const *mailbox_path,
	char const *mailbox
)
{
	char tmp[PATH_MAX];
	snprintf_safe(tmp, "%s/cur", mailbox_path);
	if (access(tmp, X_OK)) {
		channel_log(chan, LOG_DEBUG, "%s: Not a maildir", mailbox_path);
		return;
	}

	if (!mbconfig_patterns_test(&chan->mb_chan->patterns, mailbox)) {
		channel_log(chan, LOG_DEBUG, "Mailbox [%s] not matched", mailbox);
		return;
	}

	struct maildir_store *store = oom(malloc(sizeof *store));

	store->chan = chan;
	store->mb_store = mb_store;
	store->mailbox = oom(strdup(mailbox));

	maildir_log(store, LOG_INFO, "Watching");

	int poll_interval = chan->mb_chan->mbidled.start_interval;

	strcpy(store->cur_path, tmp);
	ev_stat_init(&store->cur_watcher, cur_stat_cb, store->cur_path, poll_interval);
	ev_stat_start(chan->loop, &store->cur_watcher);

	snprintf_safe(store->new_path, "%s/new", mailbox_path);
	ev_stat_init(&store->new_watcher, new_stat_cb, store->new_path, poll_interval);
	ev_stat_start(chan->loop, &store->new_watcher);

	/* Bring other side up-to-date. */
	maildir_notify_change(store);
}

void
maildir_open_store(struct channel *chan, struct mbconfig_store const *mb_store)
{
	assert(mb_store->type == MBCONFIG_STORE_MAILDIR);
	struct mbconfig_maildir_store *mb_maildir_store = mb_store->maildir_store;

	if (mb_maildir_store->inbox)
		maildir_open_mailbox(chan, mb_store, mb_maildir_store->inbox, "INBOX");

	/* Path is a prefix in fact. Go to parent and scan all files. */
	char maildir_path[PATH_MAX];
	snprintf_safe(maildir_path, "%s", mb_maildir_store->path);
	char *slash = strrchr(maildir_path, '/');
	if (slash)
		*slash = '\0';

	DIR *dir = opendir(maildir_path);
	if (!dir)
		return;

	for (struct dirent *dent; (dent = readdir(dir));) {
		char mailbox_path[PATH_MAX];
		snprintf_safe(mailbox_path, "%s/%s", maildir_path, dent->d_name);
		/* Inbox requires special handling. */
		if (mb_maildir_store->inbox && !strcmp(mb_maildir_store->inbox, mailbox_path))
			continue;
		maildir_open_mailbox(chan, mb_store, mailbox_path, dent->d_name);
	}

	closedir(dir);
}
