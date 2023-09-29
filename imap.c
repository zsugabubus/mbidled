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

	enum state {
		STATE_GROUND,
		STATE_CONNECTING,
		STATE_CONNECTED,
		STATE_CONNECTING_SSL,
		STATE_ESTABLISHED_SSL,
		STATE_ESTABLISHED,
		STATE_IMAP_GROUND,
		STATE_IMAP_CAPABILITY,
		STATE_IMAP_LOGIN,
		STATE_IMAP_LIST,
		STATE_IMAP_EXAMINE,
		STATE_IMAP_IDLE,
		STATE_DISCONNECTED,
		STATE_ERROR,
		STATE_RESET,
	} state;
	enum {
		CAP_IDLE = 1 << 0,
		CAP_LOGINDISABLED = 1 << 1,
	} cap;
	BIO *bio;

	int expected_tag;
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

	if (!store->bio)
		return;

	BIO_flush(store->bio);

	int new_events = EV_READ | (BIO_wpending(store->bio) ? EV_WRITE : 0);
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
	int inbox = !strcmp(mailbox, "INBOX");

	if (!mbconfig_patterns_test(&chan->mb_chan->patterns, mailbox)) {
		channel_log(chan, LOG_DEBUG, "Mailbox [%s] not matched", mailbox);
		/* INBOX must be always watced. */
		if (!inbox)
			return;
	}

	struct imap_store *store;
	ASSERT(store = malloc(sizeof *store));

	store->chan = chan;
	store->mb_store = mb_store;
	ASSERT(store->mailbox = strdup(mailbox));

	store->list_mailboxes = inbox;

	imap_log(store, LOG_INFO, "Watching");

	ev_init(&store->io_watcher, io_cb);
	ev_init(&store->timeout_watcher, timeout_cb);

	store->state = STATE_GROUND;
	do_poll(store);
}

void
imap_open_store(struct channel *chan, struct mbconfig_store *mb_store)
{
	assert(mb_store->type == MBCONFIG_STORE_IMAP);
	imap_open_mailbox(chan, mb_store, "INBOX");
}

static void
write_cmdf(struct imap_store *store, enum state next_state, char const *fmt, ...)
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
				size_t n = strcspn(s, "\"\\");
				BIO_write(store->bio, s, n);
				s += n;
				if (!*s)
					break;
				BIO_write(store->bio, "\\", 1);
				BIO_write(store->bio, s, 1);
				s += 1;
			}
			break;

		default:
			abort();
		}

		from = to + 2;
	}
	va_end(ap);

	BIO_write(store->bio, "\r\n", 2);

	store->state = next_state;
	store->expected_tag = store->seq_num;
}

static void
imap_notify_change(struct imap_store *store)
{
	imap_log(store, LOG_DEBUG, "Changed");
	channel_notify_change(store->chan, store->mb_store, store->mailbox);
}

static void
feed(struct imap_store *store, char *line)
{
	imap_log(store, LOG_DEBUG, "S: %s", line);

	if (*line == '*' || *line == '+') switch (store->state) {
	case STATE_IMAP_GROUND:
		if (strncmp(line, "* OK ", 5)) {
			imap_log(store, LOG_ERR, "OK expected");
			store->state = STATE_ERROR;
			return;
		}

		write_cmdf(store, STATE_IMAP_CAPABILITY,
				"CAPABILITY");
		return;

	case STATE_IMAP_CAPABILITY:
		if (strncmp(line, "* CAPABILITY ", 13))
			return; /* Ignore. */
		line += 12;

		store->cap = 0;
		if (strstr(line, " IDLE"))
			store->cap |= CAP_IDLE;
		if (strstr(line, " LOGINDISABLED"))
			store->cap |= CAP_LOGINDISABLED;
		return;

	case STATE_IMAP_LIST:
		if (strncmp(line, "* LIST ", 7))
			return; /* Ignore. */
		line += 7;

	{
		/* Simple and stupid. */
		char const *mailbox = strstr(line, NAMESPACE);
		if (mailbox) {
			mailbox += sizeof NAMESPACE - 1;
			imap_open_mailbox(store->chan, store->mb_store, mailbox);
		}
	}

		return;

	case STATE_IMAP_IDLE:
		if (!('0' <= line[2] && line[2] <= '9'))
			return; /* Ignore. */

		imap_notify_change(store);
		return;

	default:
		/* Ignore. */
		return;
	}

	int line_tag = strtol(line, &line, 10);
	if (line_tag != store->expected_tag) {
		imap_log(store, LOG_ERR, "Received response with unknown tag %d", line_tag);
		return;
	}

	if (memcmp(line, " OK ", 4)) {
		imap_log(store, LOG_ERR, "OK expected");
		store->state = STATE_ERROR;
		return;
	}

	switch (store->state) {
	case STATE_IMAP_CAPABILITY:
		if (!(store->cap & CAP_IDLE)) {
			imap_log(store, LOG_ERR, "IDLE not supported");
			store->state = STATE_ERROR;
			return;
		}

		if (store->cap & CAP_LOGINDISABLED) {
			imap_log(store, LOG_ERR, "LOGIN disabled by the server");
			store->state = STATE_ERROR;
			return;
		}

		struct mbconfig_imap_account *mb_account =
			store->mb_store->imap_store->account;

		imap_log(store, LOG_DEBUG, "Logging in...");
		if (!mb_account->login_auth) {
			imap_log(store, LOG_ERR, "LOGIN disabled by the user");
			store->state = STATE_ERROR;
			return;
		}

		mbconfig_eval_cmd_option(&mb_account->user, mb_account->user_cmd);
		mbconfig_eval_cmd_option(&mb_account->pass, mb_account->pass_cmd);

		if (!mb_account->user || !mb_account->pass) {
			imap_log(store, LOG_ERR, "Missing User and/or Pass");
			store->state = STATE_ERROR;
			return;
		}

		write_cmdf(store, STATE_IMAP_LOGIN,
				"LOGIN \"%q\" \"%q\"",
				mb_account->user,
				mb_account->pass);
		break;

	case STATE_IMAP_LOGIN:
		imap_log(store, LOG_NOTICE, "Logged in");

		if (store->list_mailboxes) {
			write_cmdf(store, STATE_IMAP_LIST,
					"LIST \"%q\" \"%q\"",
					NAMESPACE,
					"*");
			break;
		case STATE_IMAP_LIST:
			store->list_mailboxes = 0;
		}

		write_cmdf(store, STATE_IMAP_EXAMINE,
				"EXAMINE \"%q%q\"",
				!strcmp(store->mailbox, "INBOX")
					? ""
					: NAMESPACE,
				store->mailbox);
		break;

	case STATE_IMAP_EXAMINE:
		write_cmdf(store, STATE_IMAP_IDLE,
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

	if ((bio = BIO_new(BIO_f_buffer())) == NULL)
		goto fail;
	chain = BIO_push(chain, bio), bio = NULL;

	if (mb_account->ssl == MBCONFIG_SSL_IMAPS) {
		if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL ||
		    (mb_account->system_certs &&
		     SSL_CTX_set_default_verify_paths(ctx) != 1) ||
		    (mb_account->cert_file != NULL &&
		     X509_STORE_load_locations(
				SSL_CTX_get_cert_store(ctx),
				mb_account->cert_file, NULL) != 1))
			goto fail;

		/* Continue handshake even if certificate seems invalid.
		 * Errored certificate will be checked against certificates
		 * explicitly trusted by the user. */
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		SSL_CTX_set_options(ctx, mb_account->ssl_versions);

		SSL *ssl = NULL;
		if ((bio = BIO_new_ssl(ctx, 1 /* Client. */)) == NULL ||
		    BIO_get_ssl(bio, &ssl) != 1 ||
		    (mb_account->host != NULL &&
		     SSL_set1_host(ssl, mb_account->host) != 1) ||
		    (mb_account->ciphers != NULL &&
		     SSL_set_cipher_list(ssl, mb_account->ciphers) != 1) ||
		    (mb_account->host != NULL &&
		     SSL_set_tlsext_host_name(ssl, mb_account->host) != 1))
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
				imap_log(store, LOG_ERR, "exec() failed: %s", strerror(errno));
			_exit(EXIT_FAILURE);
		}

		close(pair[0]);

		if ((bio = BIO_new_fd(pair[1], 1 /* Close. */)) == NULL ||
		    BIO_set_nbio(bio, 1) != 1)
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

		if ((bio = BIO_new(BIO_s_connect())) == NULL ||
		    BIO_set_nbio(bio, 1) != 1 ||
		    BIO_set_conn_hostname(bio, mb_account->host) != 1 ||
		    BIO_set_conn_port(bio, port) != 1)
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
		store->expected_tag = 0;
		store->seq_num = 0;

		store->bio = create_transport(store);
		if (!store->bio) {
			store->state = STATE_ERROR;
			break;
		}

		imap_log(store, LOG_DEBUG, "Connecting...");
		store->state = STATE_CONNECTING;
		break;

	case STATE_CONNECTING:
		if ((rc = BIO_do_connect(store->bio)) != 1)
			if (!BIO_should_retry(store->bio)) {
				store->state = STATE_ERROR;
				break;
			}

		if (!ev_is_active(&store->io_watcher)) {
			int fd = BIO_get_fd(store->bio, NULL);
			ev_io_set(&store->io_watcher, fd, EV_READ | EV_WRITE);
			ev_io_start(EV_A_ &store->io_watcher);
		}

		if (rc != 1)
			return;

		store->state = STATE_CONNECTED;
		break;

	case STATE_CONNECTED:
		imap_log(store, LOG_DEBUG, "Connected");

		if (store->mb_store->imap_store->account->ssl == MBCONFIG_SSL_IMAPS) {
			imap_log(store, LOG_DEBUG, "Performing SSL handshake...");
			store->state = STATE_CONNECTING_SSL;
		} else {
			store->state = STATE_ESTABLISHED;
		}
		break;

	case STATE_CONNECTING_SSL:
		/* Use first bio in the chain to let OpenSSL find SSL BIO. */
		if (BIO_do_handshake(store->bio) != 1) {
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
		if ((untrusted_cert = SSL_get_peer_certificate(ssl)) == NULL) {
			imap_log(store, LOG_ERR, "No certificate");
			store->state = STATE_ERROR;
			break;
		} else if ((err = SSL_get_verify_result(ssl)) != X509_V_OK) {
			SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
			X509_STORE *cert_store = SSL_CTX_get_cert_store(ctx);
			STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(cert_store);
			for (int i = 0; i < sk_X509_OBJECT_num(objs); ++i) {
				X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);
				X509 *trusted_cert = X509_OBJECT_get0_X509(obj);
				if (!X509_cmp(untrusted_cert, trusted_cert))
					goto cert_trusted;
			}

			imap_log(store, LOG_ERR, "Certificate verification failed: %s",
					X509_verify_cert_error_string(err));
			if (opt_verbose)
				X509_print_fp(stdout, untrusted_cert);
			store->state = STATE_ERROR;
			break;

		cert_trusted:;
		}
	}

		imap_log(store, LOG_DEBUG, "SSL connection established");
		store->state = STATE_ESTABLISHED;
		break;

	case STATE_ESTABLISHED:
		imap_log(store, LOG_DEBUG, "Connection established");
		store->state = STATE_IMAP_GROUND;
		break;

	case STATE_DISCONNECTED:
		imap_log(store, LOG_ERR, "Disconnected");
		ev_timer_stop(EV_A_ &store->timeout_watcher);
		ev_timer_set(&store->timeout_watcher, 3, 0);
		ev_timer_start(EV_A_ &store->timeout_watcher);
		store->state = STATE_RESET;
		break;

	case STATE_ERROR:
		imap_log(store, LOG_ERR, "Error");
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

	default:
	{
		char line[4096];
		rc = BIO_gets(store->bio, line, sizeof line);
		if (2 <= rc) {
			line[rc - 2] = '\0';
			feed(store, line);
		} else if (BIO_should_retry(store->bio)) {
			return;
		} else {
			store->state = STATE_DISCONNECTED;
		}
	}
		break;
	}
}
