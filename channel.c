#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "channel.h"
#include "mbconfig.h"
#include "mbidled.h"

struct channel_mailbox {
	LIST_ENTRY(channel_mailbox) link;
	struct channel *chan;
	char *mailbox;

	int rerun;
	enum {
		STATE_WAIT,
		STATE_RUNNING,
		STATE_TERMINATED,
	} state;
	union {
		ev_timer timeout_watcher;
		ev_child child_watcher;
	};
};

static void
channel_store_open(struct channel *chan, struct mbconfig_store *mb_store)
{
	switch (mb_store->type) {
	case MBCONFIG_STORE_IMAP:
		imap_open_store(chan, mb_store);
		break;

	case MBCONFIG_STORE_MAILDIR:
		maildir_open_store(chan, mb_store);
		break;

	default:
		abort();
	}
}

void
channel_log(struct channel *chan, int priority, char const *format, ...)
{
	char buf[1024];
	int n;
	n = snprintf(buf, sizeof buf, "Channel [%s]: ", chan->mb_chan->name);
	if ((int)sizeof buf < n)
		n = (int)sizeof buf;

	va_list ap;
	va_start(ap, format);
	vsnprintf(buf + n, sizeof buf - n, format, ap);
	va_end(ap);

	print_log(priority, buf);
}

void
channel_store_log(struct channel const *chan, char const *store_name, char const *mailbox,
		int priority, char const *format, va_list ap)
{
	char buf[1024];
	int n;
	n = snprintf(buf, sizeof buf, "Channel [%s]: %s [%s]: ",
			chan->mb_chan->name, store_name, mailbox);
	if ((int)sizeof buf < n)
		n = (int)sizeof buf;

	vsnprintf(buf + n, sizeof buf - n, format, ap);

	print_log(priority, buf);
}

void
channel_open(EV_P_ struct mbconfig *mb_config, struct mbconfig_channel *mb_chan)
{
	struct channel *chan;
	ASSERT(chan = malloc(sizeof *chan));

	chan->loop = loop;
	chan->mb_config = mb_config,
	chan->mb_chan = mb_chan;
	LIST_INIT(&chan->boxes);

	if (MBCONFIG_SYNC_PUSH & mb_chan->sync)
		channel_store_open(chan, &mb_chan->near);
	else
		channel_log(chan, LOG_DEBUG, "Not watching Near");

	if (MBCONFIG_SYNC_PULL & mb_chan->sync)
		channel_store_open(chan, &mb_chan->far);
	else
		channel_log(chan, LOG_DEBUG, "Not watching Far");
}

static void channel_mailbox_run_sync(struct channel_mailbox *);

static void
channel_mailbox_destroy(struct channel_mailbox *box)
{
	free(box->mailbox);
	LIST_REMOVE(box, link);
	free(box);
}

static void
start_timeout_cb(EV_P_ ev_timer *w, int revents)
{
	(void)revents;
	struct channel_mailbox *box = container_of(w, struct channel_mailbox, timeout_watcher);

	channel_mailbox_run_sync(box);
}

static void
interval_timeout_cb(EV_P_ ev_timer *w, int revents)
{
	(void)revents;
	struct channel_mailbox *box = container_of(w, struct channel_mailbox, timeout_watcher);

	if (box->rerun) {
		box->rerun = 0;
		channel_log(box->chan, LOG_DEBUG, "Re-run command");
		channel_mailbox_run_sync(box);
	} else {
		channel_mailbox_destroy(box);
	}
}

static void
child_cb(EV_P_ ev_child *w, int revents)
{
	(void)revents;
	ev_child_stop(EV_A_ w);
	struct channel_mailbox *box = container_of(w, struct channel_mailbox, child_watcher);

	box->state = STATE_TERMINATED;
	ev_timer_init(&box->timeout_watcher, interval_timeout_cb,
			box->chan->mb_chan->mbidled.start_interval, 0);
	ev_timer_start(EV_A_ &box->timeout_watcher);

	int ok = WIFEXITED(w->rstatus) && WEXITSTATUS(w->rstatus) == EXIT_SUCCESS;
	int level = ok ? LOG_INFO : LOG_ERR;
	channel_log(box->chan, level, "Mailbox [%s] command terminated with %s",
			box->mailbox,
			ok ? "success" : "failure");
}

static void
channel_mailbox_run_sync(struct channel_mailbox *box)
{
	struct channel *chan = box->chan;
	channel_log(chan, LOG_DEBUG, "Syncing mailbox [%s]...", box->mailbox);

	box->state = STATE_RUNNING;

	pid_t pid = fork();
	if (!pid) {
		if (!opt_verbose)
			dup2(open("/dev/null", O_WRONLY | O_CLOEXEC), STDOUT_FILENO);
		if (setenv("MBIDLED_CONFIG", chan->mb_config->filename, 1) ||
		    setenv("MBIDLED_CHANNEL", chan->mb_chan->name, 1) ||
		    setenv("MBIDLED_MAILBOX", box->mailbox, 1) ||
		    execl("/bin/sh", "sh", opt_verbose ? "-xc" : "-c", opt_cmd, NULL))
			channel_log(chan, LOG_ERR, "exec() failed: %s", strerror(errno));
		_exit(EXIT_FAILURE);
	} else if (pid < 0) {
		channel_log(chan, LOG_ERR, "fork() failed: %s", strerror(errno));
		channel_log(chan, LOG_ERR, "Could not spawn mbsync command");
		channel_mailbox_destroy(box);
		return;
	}

	ev_child_init(&box->child_watcher, child_cb, pid, 0);
	ev_child_start(chan->loop, &box->child_watcher);
	ev_set_priority(&box->child_watcher, EV_MINPRI);
}

void
channel_notify_change(struct channel *chan, struct mbconfig_store *store,
		char const *mailbox)
{
	int far = store == chan->mb_chan->far.store;
	int from = far
		? MBCONFIG_PROPAGATE_FAR
		: MBCONFIG_PROPAGATE_NEAR;

	struct channel_mailbox *box;
	LIST_FOREACH(box, &chan->boxes, link) {
		if (strcmp(box->mailbox, mailbox))
			continue;

		char const *action;
		switch (box->state) {
		case STATE_WAIT:
			/* Gather early changes. */
			action = "Ignore early change";
			break;

		case STATE_RUNNING:
			if (!(chan->mb_chan->mbidled.strict_propagate & from)) {
				action = "Not propagating change";
				break;
			}
			/* FALLTHROUGH */
		case STATE_TERMINATED:
			action = "Change registered";
			box->rerun = 1;
			break;
		}

		char const *store_name;
		switch (store->type) {
		case MBCONFIG_STORE_IMAP:
			store_name = store->imap_store->name;
			break;

		case MBCONFIG_STORE_MAILDIR:
			store_name = store->maildir_store->name;
			break;

		default:
			abort();
		}
		channel_log(box->chan, LOG_DEBUG, "%s from [%s:%s]",
				action,
				store_name,
				mailbox);
		return;
	}

	ASSERT(box = malloc(sizeof *box));

	LIST_INSERT_HEAD(&chan->boxes, box, link);
	box->chan = chan;
	ASSERT(box->mailbox = strdup(mailbox));

	box->rerun = 0;
	box->state = STATE_WAIT;
	ev_timer_init(&box->timeout_watcher, start_timeout_cb,
			chan->mb_chan->mbidled.start_timeout, 0);
	ev_timer_start(chan->loop, &box->timeout_watcher);
}
