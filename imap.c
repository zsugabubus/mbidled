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
static int IDLE_TIMEOUT = 2 * 60;

struct imap_store {
	struct channel *chan;
	struct mbconfig_store const *mb_store;
	char *mailbox;
	int list_mailboxes;

	ev_timer timeout_watcher;
	ev_io io_watcher;

	enum state {
		STATE_GROUND,
		STATE_CONNECTING,
		STATE_CONNECTED,
		STATE_SSL_GROUND,
		STATE_SSL_HANDSHAKING,
		STATE_SSL_ESTABLISHED,
		STATE_ESTABLISHED,
		STATE_IMAP_GROUND,
		STATE_IMAP_CAPABILITY,
		STATE_IMAP_STARTTLS,
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
		CAP_STARTTLS = 1 << 2,
		CAP_AUTH = 1 << 3,
	} cap;
	BIO *bio;
	BIO *ssl_bio;
	BIO *sink_bio;

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

	do_poll(store);
}

static void
update_io_interest(EV_P_ struct imap_store *store)
{
	int events = EV_READ;

	if (BIO_wpending(store->bio))
		events |= EV_WRITE;

	if (BIO_should_retry(store->bio) && BIO_should_io_special(store->bio))
		events |= EV_WRITE;

	if (events != (store->io_watcher.events & (EV_READ | EV_WRITE))) {
		ev_io_stop(EV_A_ & store->io_watcher);
		ev_io_modify(&store->io_watcher, events);
		ev_io_start(EV_A_ & store->io_watcher);
	}
}

static void
timeout_cb(EV_P_ ev_timer *w, int revents)
{
	(void)revents;
	struct imap_store *store = container_of(w, struct imap_store, timeout_watcher);

	if (store->state == STATE_IMAP_IDLE) {
		imap_log(store, LOG_DEBUG, "Refresh IDLE");
		BIO_puts(store->bio, "DONE\r\n");
		BIO_flush(store->bio);
		return;
	}

	store->state = STATE_GROUND;
	do_poll(store);
}

static void
imap_open_mailbox(struct channel *chan, struct mbconfig_store const *mb_store, char const *mailbox)
{
	int inbox = !strcmp(mailbox, "INBOX");

	if (!mbconfig_patterns_test(&chan->mb_chan->patterns, mailbox)) {
		channel_log(chan, LOG_DEBUG, "Mailbox [%s] not matched", mailbox);
		/* INBOX must be always watched. */
		if (!inbox)
			return;
	}

	struct imap_store *store = oom(malloc(sizeof *store));

	store->chan = chan;
	store->mb_store = mb_store;
	store->mailbox = oom(strdup(mailbox));

	store->list_mailboxes = inbox;

	ev_init(&store->io_watcher, io_cb);
	ev_init(&store->timeout_watcher, timeout_cb);

	store->state = STATE_GROUND;
	do_poll(store);
}

void
imap_open_store(struct channel *chan, struct mbconfig_store const *mb_store)
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
		size_t n = strcspn(from, "%");
		BIO_write(store->bio, from, n);
		from += n;

		if (!*from)
			break;
		from++;

		switch (*from++) {
		case 's':
			BIO_puts(store->bio, va_arg(ap, char *));
			break;

		case 'q':
			for (char const *s = va_arg(ap, char *);;) {
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

static char const *
eval_cmd_option(
	struct channel const *chan, char *buf, size_t buf_size, char const *cmd_option,
	char const *value, char const *cmd
)
{
	if (cmd == NULL)
		return value;

	if (cmd[0] == '+')
		cmd++;

	FILE *fp = popen(cmd, "r");
	if (fp == NULL) {
		channel_log(chan, LOG_ERR, "%s failed to spawn: %s", cmd_option, strerror(errno));
		return NULL;
	}

	char *line = fgets(buf, buf_size, fp);

	int status = pclose(fp);

	int success = WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS;
	if (!success) {
		channel_log(chan, LOG_ERR, "%s failed", cmd_option);
		return NULL;
	}

	if (line == NULL) {
		channel_log(chan, LOG_ERR, "%s produced no output", cmd_option);
		return NULL;
	}

	char *s = strchr(line, '\n');
	if (s != NULL)
		*s = '\0';

	return buf;
}

static int
parse_cap(char const *s, char const *auth_mech)
{
	if (strcmp(s, "IDLE") == 0)
		return CAP_IDLE;

	if (strcmp(s, "LOGINDISABLED") == 0)
		return CAP_LOGINDISABLED;

	if (strcmp(s, "STARTTLS") == 0)
		return CAP_STARTTLS;

	if (auth_mech != NULL && strncmp(s, "AUTH=", 5) == 0 && strcmp(s + 5, auth_mech) == 0)
		return CAP_AUTH;

	return 0;
}

static int
parse_caps(char *s, char const *auth_mech)
{
	int caps = 0;
	for (;;) {
		char *space = strchr(s, ' ');
		if (space)
			*space = '\0';
		caps |= parse_cap(s, auth_mech);
		if (space == NULL)
			return caps;
		s = space + 1;
	}
}

static void
process_untagged(struct imap_store *store, char *s)
{
	struct mbconfig_imap_account const *mb_account = store->mb_store->imap_store->account;

	switch (store->state) {
	case STATE_IMAP_GROUND:
		if (strncmp(s, "OK ", 3)) {
			imap_log(store, LOG_WARNING, "OK expected");
			store->state = STATE_ERROR;
			return;
		}

		write_cmdf(store, STATE_IMAP_CAPABILITY, "CAPABILITY");
		return;

	case STATE_IMAP_CAPABILITY:
		if (strncmp(s, "CAPABILITY ", 11) == 0)
			store->cap = parse_caps(s + 11, mb_account->auth_mech);
		return;

	case STATE_IMAP_LIST:
		if (strncmp(s, "LIST ", 5) == 0) {
			char const *mailbox = strstr(s + 5, NAMESPACE);
			if (mailbox != NULL) {
				mailbox += strlen(NAMESPACE);
				imap_open_mailbox(store->chan, store->mb_store, mailbox);
			}
		}
		return;

	case STATE_IMAP_IDLE:
		if ('0' <= *s && *s <= '9')
			imap_notify_change(store);
		return;

	default:
		/* Ignore. */
		return;
	}
}

static void
process_ok(struct imap_store *store)
{
	struct mbconfig_imap_account const *mb_account = store->mb_store->imap_store->account;
#ifdef EV_MULTIPLICITY
	struct ev_loop *loop = store->chan->loop;
#endif

	switch (store->state) {
	case STATE_IMAP_CAPABILITY:
	{
		if (!(store->cap & CAP_IDLE)) {
			imap_log(store, LOG_ERR, "IDLE not supported");
			store->state = STATE_ERROR;
			return;
		}

		if (store->ssl_bio == NULL && mb_account->ssl == MBCONFIG_SSL_STARTTLS) {
			if (!(store->cap & CAP_STARTTLS)) {
				imap_log(store, LOG_ERR, "STARTTLS not supported");
				store->state = STATE_ERROR;
				return;
			}

			write_cmdf(store, STATE_IMAP_STARTTLS, "STARTTLS");
			return;
		}

		imap_log(store, LOG_DEBUG, "Logging in...");

		if (store->cap & CAP_AUTH) {
			char buf[8192];
			char const *authdata = eval_cmd_option(
				store->chan,
				buf,
				sizeof buf,
				"PassCmd",
				mb_account->pass,
				mb_account->pass_cmd
			);
			if (authdata == NULL) {
				imap_log(store, LOG_ERR, "No authdata");
				store->state = STATE_ERROR;
				return;
			}

			write_cmdf(
				store,
				STATE_IMAP_LOGIN,
				"AUTHENTICATE %s %s",
				mb_account->auth_mech,
				authdata
			);
			return;
		}

		if (store->cap & CAP_LOGINDISABLED) {
			imap_log(store, LOG_ERR, "LOGIN disabled by the server");
			store->state = STATE_ERROR;
			return;
		}

		if (!mb_account->login_auth) {
			imap_log(store, LOG_ERR, "LOGIN disabled by the user");
			store->state = STATE_ERROR;
			return;
		}

		char user_buf[1024];
		char const *user = eval_cmd_option(
			store->chan,
			user_buf,
			sizeof user_buf,
			"UserCmd",
			mb_account->user,
			mb_account->user_cmd
		);
		if (user == NULL) {
			imap_log(store, LOG_ERR, "No username");
			store->state = STATE_ERROR;
			return;
		}

		char pass_buf[1024];
		char const *pass = eval_cmd_option(
			store->chan,
			pass_buf,
			sizeof pass_buf,
			"PassCmd",
			mb_account->pass,
			mb_account->pass_cmd
		);
		if (pass == NULL) {
			imap_log(store, LOG_ERR, "No password");
			store->state = STATE_ERROR;
			return;
		}

		write_cmdf(store, STATE_IMAP_LOGIN, "LOGIN \"%q\" \"%q\"", user, pass);
		return;
	}

	case STATE_IMAP_STARTTLS:
		store->state = STATE_SSL_GROUND;
		return;

	case STATE_IMAP_LOGIN:
		imap_log(store, LOG_DEBUG, "Logged in");

		if (store->list_mailboxes) {
			write_cmdf(store, STATE_IMAP_LIST, "LIST \"%q\" \"%q\"", NAMESPACE, "*");
			return;
		}
		/* FALLTHROUGH */
	case STATE_IMAP_LIST:
		store->list_mailboxes = 0;
		write_cmdf(
			store,
			STATE_IMAP_EXAMINE,
			"EXAMINE \"%q%q\"",
			!strcmp(store->mailbox, "INBOX") ? "" : NAMESPACE,
			store->mailbox
		);
		return;

	case STATE_IMAP_EXAMINE:
		imap_log(store, LOG_DEBUG, "Watching");

		write_cmdf(store, STATE_IMAP_IDLE, "IDLE");

		ev_timer_stop(EV_A_ & store->timeout_watcher);
		ev_timer_set(&store->timeout_watcher, IDLE_TIMEOUT, IDLE_TIMEOUT);
		ev_timer_start(EV_A_ & store->timeout_watcher);

		/* Bring other side up-to-date. */
		imap_notify_change(store);
		return;

	case STATE_IMAP_IDLE:
		write_cmdf(store, STATE_IMAP_IDLE, "IDLE");
		return;

	default:
		/* Ignore unneeded completion responses. */
		return;
	}
}

static void
process_line(struct imap_store *store, char *line)
{
	imap_log(store, LOG_DEBUG, "S: %s", line);

	if ((line[0] == '*' || line[0] == '+') && line[1] == ' ') {
		process_untagged(store, line + 2);
		return;
	}

	int tag = strtol(line, &line, 10);
	if (tag != store->expected_tag) {
		imap_log(store, LOG_DEBUG, "Received response with unknown tag %d", tag);
		return;
	}

	if (memcmp(line, " OK ", 4) != 0) {
		imap_log(store, LOG_WARNING, "OK expected");
		store->state = STATE_ERROR;
		return;
	}

	process_ok(store);
}

static BIO *
create_source_bio(struct imap_store const *store)
{
	(void)store;

	return BIO_new(BIO_f_buffer());
}

static BIO *
create_ssl_bio(struct imap_store const *store)
{
	struct mbconfig_imap_account const *mb_account = store->mb_store->imap_store->account;

	SSL_CTX *ctx = NULL;
	BIO *bio = NULL;

	if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL ||
	    (mb_account->system_certs && SSL_CTX_set_default_verify_paths(ctx) != 1) ||
	    (mb_account->cert_file != NULL &&
	     X509_STORE_load_locations(SSL_CTX_get_cert_store(ctx), mb_account->cert_file, NULL) !=
		     1))
		goto fail;

	/* Continue handshake even if certificate seems invalid.
	 * Errored certificate will be checked against certificates
	 * explicitly trusted by the user. */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_options(ctx, mb_account->ssl_versions);

	SSL *ssl = NULL;
	if ((bio = BIO_new_ssl(ctx, 1 /* Client. */)) == NULL || BIO_get_ssl(bio, &ssl) != 1 ||
	    (mb_account->host != NULL && SSL_set1_host(ssl, mb_account->host) != 1) ||
	    (mb_account->ciphers != NULL && SSL_set_cipher_list(ssl, mb_account->ciphers) != 1) ||
	    (mb_account->host != NULL && SSL_set_tlsext_host_name(ssl, mb_account->host) != 1))
		goto fail;

	SSL_set_mode(
		ssl,
		SSL_MODE_AUTO_RETRY | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
			SSL_MODE_ENABLE_PARTIAL_WRITE
	);

	SSL_CTX_free(ctx);
	return bio;

fail:
	SSL_CTX_free(ctx);
	BIO_free(bio);
	return NULL;
}

static BIO *
create_tunnel_bio(struct imap_store const *store, char const *cmd)
{
	BIO *bio = NULL;

	int pair[2];
	int type = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
	if (socketpair(PF_UNIX, type, 0, pair) < 0)
		goto fail;

	if (!fork()) {
		if (dup2(pair[0], STDIN_FILENO) < 0 || dup2(pair[0], STDOUT_FILENO) < 0 ||
		    execl("/bin/sh", "sh", "-c", cmd, NULL) < 0)
			imap_log(store, LOG_ERR, "exec() failed: %s", strerror(errno));
		_exit(EXIT_FAILURE);
	}

	close(pair[0]);

	if ((bio = BIO_new_fd(pair[1], 1 /* Close. */)) == NULL || BIO_set_nbio(bio, 1) != 1)
		goto fail;

	return bio;

fail:
	BIO_free(bio);
	return NULL;
}

static BIO *
create_connect_bio(char const *host, char const *port)
{
	BIO *bio = NULL;

	if ((bio = BIO_new(BIO_s_connect())) == NULL || BIO_set_nbio(bio, 1) != 1 ||
	    BIO_set_conn_hostname(bio, host) != 1 || BIO_set_conn_port(bio, port) != 1)
		goto fail;

	return bio;

fail:
	BIO_free(bio);
	return NULL;
}

static BIO *
create_sink_bio(struct imap_store *store)
{
	struct mbconfig_imap_account const *mb_account = store->mb_store->imap_store->account;

	if (mb_account->tunnel_cmd != NULL) {
		return create_tunnel_bio(store, mb_account->tunnel_cmd);
	} else {
		char const *port = mb_account->port;
		if (port == NULL)
			port = mb_account->ssl == MBCONFIG_SSL_IMAPS ? "993" : "143";

		return create_connect_bio(mb_account->host, port);
	}
}

static int
verify_cert(struct imap_store const *store)
{
	SSL *ssl;
	BIO_get_ssl(store->bio, &ssl);

	X509 *untrusted_cert = SSL_get_peer_certificate(ssl);
	if (untrusted_cert == NULL) {
		imap_log(store, LOG_ERR, "No certificate");
		return 0;
	}

	int result = SSL_get_verify_result(ssl);
	if (result == X509_V_OK)
		return 1;

	SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
	X509_STORE *cert_store = SSL_CTX_get_cert_store(ctx);
	STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(cert_store);

	for (int i = 0; i < sk_X509_OBJECT_num(objs); ++i) {
		X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);
		X509 *trusted_cert = X509_OBJECT_get0_X509(obj);
		if (X509_cmp(untrusted_cert, trusted_cert) == 0)
			return 1;
	}

	imap_log(
		store,
		LOG_ERR,
		"Certificate verification failed: %s",
		X509_verify_cert_error_string(result)
	);

	if (opt_verbose)
		X509_print_fp(stderr, untrusted_cert);

	return 0;
}

static void
do_poll(struct imap_store *store)
{
	struct channel *chan = store->chan;
#ifdef EV_MULTIPLICITY
	struct ev_loop *loop = chan->loop;
#endif

	for (;;) {
		switch (store->state) {
		case STATE_GROUND:
			imap_log(store, LOG_DEBUG, "Connecting...");

			store->bio = create_source_bio(store);
			if (store->bio == NULL) {
				store->state = STATE_ERROR;
				break;
			}

			store->sink_bio = create_sink_bio(store);
			if (store->sink_bio == NULL) {
				store->state = STATE_ERROR;
				break;
			}

			BIO_push(store->bio, store->sink_bio);

			store->ssl_bio = NULL;
			store->expected_tag = 0;
			store->seq_num = 0;
			store->state = STATE_CONNECTING;
			break;

		case STATE_CONNECTING:
		{
			int connected = BIO_do_connect(store->bio) == 1;

			if (!connected && !BIO_should_retry(store->bio)) {
				store->state = STATE_ERROR;
				break;
			}

			if (!ev_is_active(&store->io_watcher)) {
				int fd = BIO_get_fd(store->bio, NULL);
				ev_io_set(&store->io_watcher, fd, EV_READ | EV_WRITE);
				ev_io_start(EV_A_ & store->io_watcher);
			}

			if (!connected) {
				update_io_interest(EV_A_ store);
				return;
			}

			store->state = STATE_CONNECTED;
			break;
		}

		case STATE_CONNECTED:
			imap_log(store, LOG_DEBUG, "Connected");

			if (store->mb_store->imap_store->account->ssl == MBCONFIG_SSL_IMAPS)
				store->state = STATE_SSL_GROUND;
			else
				store->state = STATE_ESTABLISHED;
			break;

		case STATE_SSL_GROUND:
			imap_log(store, LOG_DEBUG, "Performing SSL handshake...");

			store->ssl_bio = create_ssl_bio(store);
			if (store->ssl_bio == NULL) {
				store->state = STATE_ERROR;
				break;
			}

			BIO_pop(store->sink_bio);
			BIO_push(store->bio, store->ssl_bio);
			BIO_push(store->bio, store->sink_bio);

			store->state = STATE_SSL_HANDSHAKING;
			break;

		case STATE_SSL_HANDSHAKING:
			if (BIO_do_handshake(store->bio) != 1) {
				if (BIO_should_retry(store->bio)) {
					update_io_interest(EV_A_ store);
					return;
				}

				store->state = STATE_ERROR;
				break;
			}

			store->state = STATE_SSL_ESTABLISHED;
			break;

		case STATE_SSL_ESTABLISHED:
			if (!verify_cert(store)) {
				store->state = STATE_ERROR;
				break;
			}

			imap_log(store, LOG_DEBUG, "SSL connection established");

			if (store->mb_store->imap_store->account->ssl == MBCONFIG_SSL_STARTTLS)
				write_cmdf(store, STATE_IMAP_CAPABILITY, "CAPABILITY");
			else
				store->state = STATE_ESTABLISHED;
			break;

		case STATE_ESTABLISHED:
			imap_log(store, LOG_DEBUG, "Connection established");
			store->state = STATE_IMAP_GROUND;
			break;

		case STATE_DISCONNECTED:
			imap_log(store, LOG_DEBUG, "Disconnected");
			ev_timer_stop(EV_A_ & store->timeout_watcher);
			ev_timer_set(&store->timeout_watcher, 3, 0);
			ev_timer_start(EV_A_ & store->timeout_watcher);
			store->state = STATE_RESET;
			break;

		case STATE_ERROR:
			imap_log(store, LOG_ERR, "Error");
			ERR_print_errors_fp(stderr);
			ev_timer_stop(EV_A_ & store->timeout_watcher);
			ev_timer_set(&store->timeout_watcher, 5 * 60, 0);
			ev_timer_start(EV_A_ & store->timeout_watcher);
			store->state = STATE_RESET;
			break;

		case STATE_RESET:
			BIO_free_all(store->bio);
			store->bio = NULL;
			ev_io_stop(EV_A_ & store->io_watcher);
			return;

		default:
		{
			char line[4096];
			int n = BIO_gets(store->bio, line, sizeof line);
			if (n >= 2) {
				line[n - 2] = '\0';
				process_line(store, line);
			} else if (BIO_should_retry(store->bio)) {
				BIO_flush(store->bio);
				update_io_interest(EV_A_ store);
				return;
			} else {
				store->state = STATE_DISCONNECTED;
			}
			break;
		}
		}
	}
}
