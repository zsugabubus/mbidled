#include <assert.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>

#include "channel.h"
#include "mbconfig.h"
#include "mbidled.h"

static char const NAMESPACE[] = "INBOX.";

struct imap_store {
	struct channel *chan;
	struct mbconfig_store *mb_store;
	char *mailbox;
	int list_mailboxes;

	ev_timer timeout_watcher;
	ev_io io_watcher;

	enum {
		STATE_GROUND,
		STATE_CONNECTING,
		STATE_CONNECTED,
		STATE_CONNECTING_SSL,
		STATE_ESTABLISHED_SSL,
		STATE_ESTABLISHED,
		STATE_IMAP,
		STATE_DISCONNECTED,
		STATE_ERROR,
		STATE_RESET,
	} state;
	enum {
		CAP_IDLE = 1 << 0,
		CAP_LOGINDISABLED = 1 << 1,
	} cap;
	BIO *bio;

	enum cmd {
		CMD_NONE,
		CMD_CAPABILITY,
		CMD_LOGIN,
		CMD_LIST,
		CMD_EXAMINE,
		CMD_IDLE,
		CMD_LOGOUT,
	} cmd;
	int cmd_tag;
	int seq_num;
};

DEFINE_CHANNEL_STORE_LOGGER(imap, "IMAP")

static void do_poll(struct imap_store *store);

static void
io_cb(EV_P_ ev_io *w, int revents)
{
	(void)revents;
	struct imap_store *store = container_of(w, struct imap_store, io_watcher);

	if (revents & EV_READ)
		do_poll(store);

	BIO_flush(store->bio);

	int new_events =
		(BIO_wpending(store->bio) ? EV_WRITE : 0) |
		EV_READ;
	if (new_events != ((EV_READ | EV_WRITE) & store->io_watcher.events)) {
		ev_io_stop(EV_A_ &store->io_watcher);
		ev_io_modify(&store->io_watcher, new_events);
		ev_io_start(EV_A_ &store->io_watcher);
	}
}

static void
timeout_cb(EV_P_ ev_timer *w, int revents)
{
	(void)revents;
	struct imap_store *store = container_of(w, struct imap_store, timeout_watcher);

	store->state = STATE_GROUND;
	do_poll(store);
}

static void
imap_open_mailbox(struct channel *chan, struct mbconfig_store *mb_store,
		char const *mailbox)
{
	struct imap_store *store;
	ASSERT(store = malloc(sizeof *store));

	store->chan = chan;
	store->mb_store = mb_store;
	ASSERT(store->mailbox = strdup(mailbox));

	store->list_mailboxes = !strcmp(store->mailbox, "INBOX");

	store_log(store, LOG_INFO, "Watching");

	ev_init(&store->io_watcher, io_cb);
	ev_init(&store->timeout_watcher, timeout_cb);

	store->state = STATE_GROUND;
	do_poll(store);
}

static void
imap_try_open_mailbox(struct channel *chan, struct mbconfig_store *mb_store,
		char const *mailbox)
{
	if (!mbconfig_patterns_test(&chan->mb_chan->patterns, mailbox)) {
		imap_log(chan, LOG_DEBUG, "Mailbox [%s] not matched", mailbox);
		return;
	}

	imap_open_mailbox(chan, mb_store, mailbox);
}

void
imap_open_store(struct channel *chan, struct mbconfig_store *mb_store)
{
	assert(MBCONFIG_STORE_IMAP == mb_store->type);
	imap_open_mailbox(chan, mb_store, "INBOX");
}

static void
write_cmdf(struct imap_store *store, enum cmd cmd, char const *fmt, ...)
{
	++store->seq_num;

	BIO_printf(store->bio, "%" PRIu32 " ", store->seq_num);

	va_list ap;
	va_start(ap, fmt);
	for (char const *from = fmt;;) {
		char const *to = strchr(from, '%');
		if (!to)
			to = from + strlen(from);
		int n = (int)(to - from);

		BIO_write(store->bio, from, n);

		if (!*to)
			break;

		char const *arg = va_arg(ap, char *);

		switch (to[1]) {
		case 's':
			BIO_puts(store->bio, arg);
			break;

		case 'q':
			for (char const *s = arg;;) {
				int skip = s != arg;
				size_t n = strcspn(s + skip, "\"\\");
				size_t len = skip + n;
				if (len) {
					BIO_write(store->bio, s, len);
					s += len;
				}
				if (!*s)
					break;
				BIO_write(store->bio, "\\", 1);
			}
			break;

		default:
			abort();
		}

		from = to + 2;
	}
	va_end(ap);

	BIO_write(store->bio, "\r\n", 2);

	store->cmd = cmd;
	store->cmd_tag = store->seq_num;
}

static void
imap_notify_change(struct imap_store *store)
{
	store_log(store, LOG_DEBUG, "Changed");
	channel_notify_change(store->chan, store->mb_store, store->mailbox);
}

static void
feed(struct imap_store *store, char *line)
{
	store_log(store, LOG_DEBUG, "S: %s", line);

	if ('*' == *line || '+' == *line) switch (store->cmd) {
	case CMD_NONE:
		if (strncmp(line, "* OK ", 5)) {
			store_log(store, LOG_ERR, "OK expected.");
			store->state = STATE_ERROR;
			return;
		}

		write_cmdf(store, CMD_CAPABILITY,
				"CAPABILITY");
		return;

	case CMD_CAPABILITY:
		if (strncmp(line, "* CAPABILITY ", 13))
			/* Ignore. */
			return;
		line += 13;

		store->cap = 0;
		if (strstr(line, " IDLE"))
			store->cap |= CAP_IDLE;
		if (strstr(line, " LOGINDISABLED"))
			store->cap |= CAP_LOGINDISABLED;
		return;

	case CMD_LIST:
		if (strncmp(line, "* LIST ", 7))
			/* Ignore. */
			return;
		line += 7;

	{
		/* Simple and stupid. */
		char const *mailbox = strstr(line, NAMESPACE);
		if (mailbox) {
			mailbox += sizeof NAMESPACE - 1;
			imap_try_open_mailbox(store->chan, store->mb_store, mailbox);
		}
	}

		return;

	case CMD_IDLE:
		if (!('0' <= line[2] && line[2] <= '9'))
			/* Ignore. */
			return;

		imap_notify_change(store);
		return;

	default:
		/* Ignore. */
		return;
	}

	int line_tag = strtol(line, &line, 10);
	if (line_tag != store->cmd_tag) {
		store_log(store, LOG_ERR, "Received response with unknown tag %d", line_tag);
		return;
	}

	if (memcmp(line, " OK ", 4)) {
		store_log(store, LOG_ERR, "OK expected.");
		store->state = STATE_ERROR;
		return;
	}

	switch (store->cmd) {
	case CMD_CAPABILITY:
		if (!(CAP_IDLE & store->cap)) {
			store_log(store, LOG_ERR, "IDLE not supported.");
			store->state = STATE_ERROR;
			return;
		}

		if (CAP_LOGINDISABLED & store->cap) {
			store_log(store, LOG_ERR, "LOGIN disabled by the server.");
			store->state = STATE_ERROR;
			return;
		}

		struct mbconfig_imap_account *mb_account =
			store->mb_store->imap_store->account;

		store_log(store, LOG_DEBUG, "Logging in...");
		if (!mb_account->login_auth) {
			store_log(store, LOG_ERR, "LOGIN disabled by the user.");
			store->state = STATE_ERROR;
			return;
		}

		mbconfig_eval_cmd_option(&mb_account->user, mb_account->user_cmd);
		mbconfig_eval_cmd_option(&mb_account->pass, mb_account->pass_cmd);

		if (!mb_account->user || !mb_account->pass) {
			store_log(store, LOG_ERR, "Missing User and/or Pass.");
			store->state = STATE_ERROR;
			return;
		}

		write_cmdf(store, CMD_LOGIN,
				"LOGIN \"%q\" \"%q\"",
				mb_account->user,
				mb_account->pass);
		break;

	case CMD_LOGIN:
		store_log(store, LOG_NOTICE, "Logged in.");

		if (store->list_mailboxes) {
			write_cmdf(store, CMD_LIST,
					"LIST \"%q\" \"%q\"",
					NAMESPACE,
					"*");
			break;
		case CMD_LIST:
			store->list_mailboxes = 0;
		}

		write_cmdf(store, CMD_EXAMINE,
				"EXAMINE \"%q%q\"",
				!strcmp(store->mailbox, "INBOX")
					? ""
					: NAMESPACE,
				store->mailbox);
		break;

	case CMD_EXAMINE:
		write_cmdf(store, CMD_IDLE,
				"IDLE");

		/* Bring other side up-to-date. */
		imap_notify_change(store);
		break;

	default:
		/* Ignore unneeded completion responses. */
		break;
	}
}

static BIO *
create_transport(struct imap_store *store)
{
	struct mbconfig_imap_account *mb_account =
		store->mb_store->imap_store->account;

	SSL_CTX *ctx = NULL;
	BIO *chain = NULL, *bio = NULL;

	if (!(bio = BIO_new(BIO_f_buffer())))
		goto fail;
	chain = BIO_push(chain, bio), bio = NULL;

	if (MBCONFIG_SSL_IMAPS == mb_account->ssl) {
		if (!(ctx = SSL_CTX_new(TLS_client_method())) ||
		    (mb_account->system_certs &&
		     1 != SSL_CTX_set_default_verify_paths(ctx)) ||
		    (mb_account->cert_file &&
		     1 != X509_STORE_load_locations(
				SSL_CTX_get_cert_store(ctx),
				mb_account->cert_file, NULL)))
			goto fail;

		/* Continue handshake even if certificate seems invalid.
		 * Errored certificate will be checked against certificates
		 * explicitly trusted by the user. */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		SSL_CTX_set_options(ctx, mb_account->ssl_versions);

		SSL *ssl = NULL;
		if (!(bio = BIO_new_ssl(ctx, 1 /* Client. */)) ||
		    1 != BIO_get_ssl(bio, &ssl) ||
		    (mb_account->host &&
		     1 != SSL_set1_host(ssl, mb_account->host)) ||
		    (mb_account->ciphers &&
		     1 != SSL_set_cipher_list(ssl, mb_account->ciphers)) ||
		    (mb_account->host &&
		     1 != SSL_set_tlsext_host_name(ssl, mb_account->host)))
			goto fail;

		SSL_set_mode(ssl,
				SSL_MODE_AUTO_RETRY |
				SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
				SSL_MODE_ENABLE_PARTIAL_WRITE);

		chain = BIO_push(chain, bio), bio = NULL;
	}

	if (mb_account->tunnel_cmd) {
		int pair[2];
		int type = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
		if (socketpair(PF_UNIX, type, 0, pair) < 0)
			goto fail;

		if (!fork()) {
			if (dup2(pair[0], STDIN_FILENO) < 0 ||
			    dup2(pair[0], STDOUT_FILENO) < 0 ||
			    execl("/bin/sh", "sh", "-c", mb_account->tunnel_cmd, NULL) < 0)
				store_log(store, LOG_ERR, "exec() failed: %s", strerror(errno));
			_exit(EXIT_FAILURE);
		}

		close(pair[0]);

		if (!(bio = BIO_new_fd(pair[1], 1 /* Close. */)) ||
		    1 != BIO_set_nbio(bio, 1))
			goto fail;
	} else {
		char const *port = mb_account->port;
		if (!port) {
			static char const DEFAULT_PORTS[][4] = {
				[MBCONFIG_SSL_NONE] = "143",
				[MBCONFIG_SSL_IMAPS] = "993",
			};

			port = DEFAULT_PORTS[mb_account->ssl];
		}

		if (!(bio = BIO_new(BIO_s_connect())) ||
		    1 != BIO_set_nbio(bio, 1) ||
		    1 != BIO_set_conn_hostname(bio, mb_account->host) ||
		    1 != BIO_set_conn_port(bio, port))
			goto fail;
	}
	chain = BIO_push(chain, bio), bio = NULL;

	SSL_CTX_free(ctx);

	return chain;

fail:
	SSL_CTX_free(ctx);
	BIO_free_all(chain);
	BIO_free(bio);
	return NULL;
}

static void
do_poll(struct imap_store *store)
{
	struct channel *chan = store->chan;
#ifdef EV_MULTIPLICITY
	struct ev_loop *loop = chan->loop;
#endif

	for (int rc;;) switch (store->state) {
	case STATE_GROUND:
		store->cmd = CMD_NONE;
		store->cmd_tag = 0;
		store->seq_num = 0;

		store->bio = create_transport(store);
		if (!store->bio) {
			store->state = STATE_ERROR;
			break;
		}

		store_log(store, LOG_DEBUG, "Connecting...");
		store->state = STATE_CONNECTING;
		break;

	case STATE_CONNECTING:
		if (1 != (rc = BIO_do_connect(store->bio)))
			if (!BIO_should_retry(store->bio)) {
				store->state = STATE_ERROR;
				break;
			}

		if (!ev_is_active(&store->io_watcher)) {
			ev_io_set(&store->io_watcher,
					BIO_get_fd(store->bio, NULL),
					EV_READ | EV_WRITE);
			ev_io_start(EV_A_ &store->io_watcher);
		}

		if (1 != rc)
			return;

		store->state = STATE_CONNECTED;
		break;

	case STATE_CONNECTED:
		store_log(store, LOG_DEBUG, "Connected.");

		if (MBCONFIG_SSL_IMAPS == store->mb_store->imap_store->account->ssl) {
			store_log(store, LOG_DEBUG, "Performing SSL handshake...");
			store->state = STATE_CONNECTING_SSL;
		} else {
			store->state = STATE_ESTABLISHED;
		}
		break;

	case STATE_CONNECTING_SSL:
		/* Use first bio in the chain to let OpenSSL find SSL BIO. */
		if (1 != BIO_do_handshake(store->bio)) {
			if (BIO_should_retry(store->bio))
				return;

			store->state = STATE_ERROR;
			break;
		}

		store->state = STATE_ESTABLISHED_SSL;
		break;

	case STATE_ESTABLISHED_SSL:
	{
		SSL *ssl;
		X509 *untrusted_cert;
		int err;
		BIO_get_ssl(store->bio, &ssl);
		if (!(untrusted_cert = SSL_get_peer_certificate(ssl))) {
			store_log(store, LOG_ERR, "No certificate.");
			store->state = STATE_ERROR;
			break;
		} else if (X509_V_OK != (err = SSL_get_verify_result(ssl))) {
			SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
			X509_STORE *cert_store = SSL_CTX_get_cert_store(ctx);
			STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(cert_store);
			for (int i = 0; i < sk_X509_OBJECT_num(objs); ++i) {
				X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);
				X509 *trusted_cert = X509_OBJECT_get0_X509(obj);
				if (!X509_cmp(untrusted_cert, trusted_cert))
					goto cert_trusted;
			}

			store_log(store, LOG_ERR, "Certificate verification failed: %s.",
					X509_verify_cert_error_string(err));
			if (opt_verbose)
				X509_print_fp(stdout, untrusted_cert);
			store->state = STATE_ERROR;
			break;

		cert_trusted:;
		}
	}

		store_log(store, LOG_DEBUG, "SSL connection established.");
		store->state = STATE_ESTABLISHED;
		break;

	case STATE_ESTABLISHED:
		store_log(store, LOG_DEBUG, "Connection established.");
		store->state = STATE_IMAP;
		break;

	case STATE_IMAP:
	{
		char line[4096];
		rc = BIO_gets(store->bio, line, sizeof line);
		if (2 <= rc) {
			line[rc - 2] = '\0';
			feed(store, line);
		} else if (BIO_should_retry(store->bio))
			return;
		else
			store->state = STATE_DISCONNECTED;
	}
		break;

	case STATE_DISCONNECTED:
		store_log(store, LOG_ERR, "Disconnected.");
		ev_timer_stop(EV_A_ &store->timeout_watcher);
		ev_timer_set(&store->timeout_watcher, 3, 0);
		ev_timer_start(EV_A_ &store->timeout_watcher);
		store->state = STATE_RESET;
		break;

	case STATE_ERROR:
		store_log(store, LOG_ERR, "Error.");
		ERR_print_errors_fp(stderr);
		ev_timer_stop(EV_A_ &store->timeout_watcher);
		ev_timer_set(&store->timeout_watcher, 5 * 60, 0);
		ev_timer_start(EV_A_ &store->timeout_watcher);
		store->state = STATE_RESET;
		break;

	case STATE_RESET:
		BIO_free_all(store->bio);
		store->bio = NULL;
		ev_io_stop(EV_A_ &store->io_watcher);
		return;
	}
}
