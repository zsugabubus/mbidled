#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include "imap.h"
#include "mbconfig.h"
#include "ts.h"

static char const USAGE[] =
	"Usage: %s -c MBSYNC_CONFIG [-e COMMAND] [-v]\n"
	"Run command on mailbox change.\n"
	"\n"
	"Try man mbidled(1) for more information.\n";

static char const *opt_config = NULL;
static char const *opt_cmd =
	"mbsync -c \"$MBIDLED_CONFIG\" \"$MBIDLED_CHANNEL:$MBIDLED_MAILBOX\"";
static int opt_reaction_time = 150;
static int opt_rerun_delay = 30 * 1000;
static int opt_verbose = 0;

enum channel_state {
	CHANNEL_STATE_GROUND,
	CHANNEL_STATE_ERROR,
	CHANNEL_STATE_CONNECTING,
	CHANNEL_STATE_CONNECTED,
	CHANNEL_STATE_CONNECTING_SSL,
	CHANNEL_STATE_ESTABLISHED_SSL,
	CHANNEL_STATE_ESTABLISHED,
	CHANNEL_STATE_IMAP,
	CHANNEL_STATE_DISCONNECTED,
};

enum channel_cmd {
	CHANNEL_CMD_NONE,
	CHANNEL_CMD_CAPABILITY,
	CHANNEL_CMD_LOGIN,
	CHANNEL_CMD_LIST,
	CHANNEL_CMD_EXAMINE,
	CHANNEL_CMD_IDLE,
	CHANNEL_CMD_LOGOUT,
};

enum channel_cap {
	CHANNEL_CAP_IDLE = 1 << 0,
	CHANNEL_CAP_LOGINDISABLED = 1 << 1,
};

struct channel {
	struct imap imap;
	enum channel_state state;
	char *mailbox;
	struct pollfd *pollfd;
	int timeout; /**< in ms. */

	int want_sync;
	pid_t pid;

	struct mbconfig *mb_config;
	struct mbconfig_channel *mb_chan;
	struct mbconfig_imap_account *mb_account;

	enum channel_cmd cmd;
	int cmd_tag;
	enum channel_cap cap;
};

static size_t nchannels;
static struct channel *channels;
static struct pollfd *pollfds;

static void
channel_init(struct channel *chan, struct pollfd *pollfd,
		struct mbconfig *mb_config,
		struct mbconfig_channel *mb_chan)
{
	chan->mb_config = mb_config,
	chan->mb_chan = mb_chan;
	chan->mb_account = mb_chan->far.store->account;

	imap_init(&chan->imap);
	chan->state = CHANNEL_STATE_GROUND;
	/* TODO Support multiple mailboxes pre channel. */
	chan->mailbox = "INBOX";
	chan->pollfd = pollfd;
	chan->pollfd->fd = -1;
	chan->timeout = 0;

	chan->want_sync = 0;
	chan->pid = 0;
}

static void
channel_log(struct channel const *chan, int priority, char const *fmt, ...)
{
	switch (priority) {
	case LOG_INFO:
	case LOG_DEBUG:
		if (!opt_verbose)
			return;
	}

	fprintf(stderr, "%s: ", chan->mb_account->name);

	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fputc('\n', stderr);
}

static void
channel_write_cmdf(struct channel *chan, enum channel_cmd cmd, char const *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int rc = imap_write_vcmdf(&chan->imap, fmt, ap);
	va_end(ap);
	if (rc < 0) {
		channel_log(chan, LOG_ERR, "Cannot compose command: %s", strerror(rc));
		chan->state = CHANNEL_STATE_ERROR;
	} else {
		chan->cmd = cmd;
		chan->cmd_tag = chan->imap.seq_num;

		char const *buf = chan->imap.wrbuf + chan->imap.wrhead;
		size_t len = chan->imap.wrtail - chan->imap.wrhead;
		channel_log(chan, LOG_DEBUG, "C: %.*s", (int)len - 2, buf);
	}
}

static void
channel_do_sync(struct channel *chan)
{
	channel_log(chan, LOG_DEBUG, "Running command...");

	chan->want_sync = 0;
	chan->pid = fork();
	if (!chan->pid) {
		if (!opt_verbose)
			dup2(open("/dev/null", O_WRONLY | O_CLOEXEC), STDOUT_FILENO);
		if (setenv("MBIDLED_CONFIG", chan->mb_config->filename, 1) ||
		    setenv("MBIDLED_CHANNEL", chan->mb_chan->name, 1) ||
		    setenv("MBIDLED_MAILBOX", chan->mailbox, 1) ||
		    execl("/bin/sh", "sh", opt_verbose ? "-xc" : "-c", opt_cmd, NULL))
			channel_log(chan, LOG_ERR, "exec() failed: %s", strerror(errno));
		_exit(EXIT_FAILURE);
	} else if (chan->pid < 0) {
		channel_log(chan, LOG_ERR, "fork() failed: %s", strerror(errno));
	}
}

static void
eval_cmd_option(char **option, char const *option_cmd)
{
	if (*option)
		return;

	char buf[8192];

	option_cmd += '+' == *option_cmd;
	FILE *stream = popen(option_cmd, "r");
	if (!stream)
		return;
	char *ok = fgets(buf, sizeof buf, stream);
	pclose(stream);
	if (!ok)
		return;
	char *s = strchr(buf, '\n');
	if (s)
		*s = '\0';
	*option = strdup(buf);
}

static void
channel_feed(struct channel *chan, char *line)
{
	channel_log(chan, LOG_DEBUG, "S: %s", line);

	if ('*' == *line || '+' == *line) switch (chan->cmd) {
	case CHANNEL_CMD_NONE:
		if (strncmp(line, "* OK ", 5)) {
			channel_log(chan, LOG_ERR, "OK expected.");
			chan->state = CHANNEL_STATE_ERROR;
			return;
		}

		channel_write_cmdf(chan, CHANNEL_CMD_CAPABILITY,
				"CAPABILITY");
		return;

	case CHANNEL_CMD_CAPABILITY:
		if (strncmp(line, "* CAPABILITY ", 13))
			/* Ignore. */
			return;
		line += 13;

		if (strstr(line, " IDLE"))
			chan->cap |= CHANNEL_CAP_IDLE;
		if (strstr(line, " LOGINDISABLED"))
			chan->cap |= CHANNEL_CAP_LOGINDISABLED;
		return;

	case CHANNEL_CMD_IDLE:
		if (!('0' <= line[2] && line[2] <= '9'))
			/* Ignore. */
			return;

		chan->want_sync = 1;
		if (/* Just to avoid a wakeup, otherwise omittable. */
		    chan->pid <= 0 &&
		    chan->timeout < 0)
			chan->timeout = opt_reaction_time;

		return;

	default:
		/* Ignore. */
		return;
	}

	assert(*line == 'A');
	int line_tag = strtol(line + 1, &line, 10);
	if (line_tag != chan->cmd_tag) {
		channel_log(chan, LOG_ERR, "Received response with unknown tag %d", line_tag);
		return;
	}

	if (strncmp(line, " OK ", 4)) {
		channel_log(chan, LOG_ERR, "OK expected.");
		chan->state = CHANNEL_STATE_ERROR;
		return;
	}

	switch (chan->cmd) {
	case CHANNEL_CMD_CAPABILITY:
		if (!(CHANNEL_CAP_IDLE & chan->cap)) {
			channel_log(chan, LOG_ERR, "IDLE not supported.");
			chan->state = CHANNEL_STATE_ERROR;
			return;
		}

		if (CHANNEL_CAP_LOGINDISABLED & chan->cap) {
			channel_log(chan, LOG_ERR, "LOGIN disabled by the server.");
			chan->state = CHANNEL_STATE_ERROR;
			return;
		}

		struct mbconfig_imap_account *mb_account = chan->mb_account;

		channel_log(chan, LOG_DEBUG, "Logging in...");
		if (!mb_account->login_auth) {
			channel_log(chan, LOG_ERR, "LOGIN disabled by the user.");
			chan->state = CHANNEL_STATE_ERROR;
			return;
		}

		eval_cmd_option(&mb_account->user, mb_account->user_cmd);
		eval_cmd_option(&mb_account->pass, mb_account->pass_cmd);

		if (!mb_account->user || !mb_account->pass) {
			channel_log(chan, LOG_ERR, "Missing User and/or Pass.");
			chan->state = CHANNEL_STATE_ERROR;
			return;
		}

		channel_write_cmdf(chan, CHANNEL_CMD_LOGIN,
				"LOGIN \"%q\" \"%q\"",
				mb_account->user,
				mb_account->pass);
		break;

	case CHANNEL_CMD_LOGIN:
		channel_log(chan, LOG_NOTICE, "Logged in.");
#if 0
		channel_write_cmdf(chan, CHANNEL_CMD_LIST,
				"LIST \"%q\" \"%q\"", "", "*");
		break;

	case CHANNEL_CMD_LIST:
#endif
		channel_write_cmdf(chan, CHANNEL_CMD_EXAMINE,
				"EXAMINE \"%q\"",
				chan->mailbox);
		break;

	case CHANNEL_CMD_EXAMINE:
		channel_write_cmdf(chan, CHANNEL_CMD_IDLE,
				"IDLE");
		break;

	default:
		/* Ignore unneeded completion responses. */
		break;
	}
}

static BIO *
channel_create_transport(struct channel *chan)
{
	struct mbconfig_imap_account *mb_account = chan->mb_account;

	SSL_CTX *ctx = NULL;
	BIO *chain = NULL, *bio = NULL;

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
				channel_log(chan, LOG_ERR, "exec() failed: %s", strerror(errno));
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
channel_poll(struct channel *chan)
{
	for (int rc;;) switch (chan->state) {
	case CHANNEL_STATE_GROUND:
	{
		imap_close(&chan->imap);
		chan->want_sync = 1;
		chan->timeout = -1;
		chan->pollfd->fd = -1;
		chan->cap = 0;

		BIO *bio = channel_create_transport(chan);
		if (!bio) {
			chan->state = CHANNEL_STATE_ERROR;
			break;
		}

		imap_open(&chan->imap, bio);
	}

		channel_log(chan, LOG_DEBUG, "Connecting...");
		chan->state = CHANNEL_STATE_CONNECTING;
		break;

	case CHANNEL_STATE_CONNECTING:
		if (1 != BIO_do_connect(chan->imap.bio)) {
			rc = BIO_should_retry(chan->imap.bio) ? -EAGAIN : -EIO;
		} else {
			rc = 0;
		}

		if (chan->pollfd->fd < 0) {
			chan->pollfd->fd = BIO_get_fd(chan->imap.bio, NULL);
			chan->pollfd->events = POLLIN | POLLOUT;
		}

		if (-EAGAIN == rc) {
			return;
		} else if (rc < 0) {
			chan->state = CHANNEL_STATE_ERROR;
			break;
		}

		chan->state = CHANNEL_STATE_CONNECTED;
		break;

	case CHANNEL_STATE_CONNECTED:
		channel_log(chan, LOG_INFO, "Connected.");

		if (MBCONFIG_SSL_IMAPS == chan->mb_account->ssl) {
			channel_log(chan, LOG_DEBUG, "Performing SSL handshake...");
			chan->state = CHANNEL_STATE_CONNECTING_SSL;
		} else {
			chan->state = CHANNEL_STATE_ESTABLISHED;
		}
		break;

	case CHANNEL_STATE_CONNECTING_SSL:
		if (1 != BIO_do_handshake(chan->imap.bio)) {
			if (BIO_should_retry(chan->imap.bio))
				return;

			chan->state = CHANNEL_STATE_ERROR;
			break;
		}

		chan->state = CHANNEL_STATE_ESTABLISHED_SSL;
		break;

	case CHANNEL_STATE_ESTABLISHED_SSL:
	{
		SSL *ssl;
		X509 *untrusted_cert;
		int err;
		BIO_get_ssl(chan->imap.bio, &ssl);
		if (!(untrusted_cert = SSL_get_peer_certificate(ssl))) {
			channel_log(chan, LOG_ERR, "No certificate.");
			chan->state = CHANNEL_STATE_ERROR;
			break;
		} else if (X509_V_OK != (err = SSL_get_verify_result(ssl))) {
			SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
			X509_STORE *store = SSL_CTX_get_cert_store(ctx);
			STACK_OF(X509_OBJECT) *objs = X509_STORE_get0_objects(store);
			for (int i = 0; i < sk_X509_OBJECT_num(objs); ++i) {
				X509_OBJECT *obj = sk_X509_OBJECT_value(objs, i);
				X509 *trusted_cert = X509_OBJECT_get0_X509(obj);
				if (!X509_cmp(untrusted_cert, trusted_cert))
					goto cert_trusted;
			}

			channel_log(chan, LOG_ERR, "Certificate verification failed: %s.",
					X509_verify_cert_error_string(err));
			if (opt_verbose)
				X509_print_fp(stdout, untrusted_cert);
			chan->state = CHANNEL_STATE_ERROR;
			break;

		cert_trusted:;
		}
	}

		channel_log(chan, LOG_INFO, "SSL connection established.");
		chan->state = CHANNEL_STATE_ESTABLISHED;
		break;

	case CHANNEL_STATE_ESTABLISHED:
		channel_log(chan, LOG_INFO, "Connection established.");
		chan->state = CHANNEL_STATE_IMAP;
		break;

	case CHANNEL_STATE_IMAP:
		if (chan->want_sync &&
		    chan->timeout < 0 &&
		    chan->pid <= 0)
			channel_do_sync(chan);

		rc = imap_write_flush(&chan->imap);
		if (0 <= rc || -EAGAIN == rc) {
			/* OK. */
		} else if (-EIO == rc) {
			chan->state = CHANNEL_STATE_DISCONNECTED;
			break;
		} else {
			chan->state = CHANNEL_STATE_ERROR;
			break;
		}

		for (char *line;;) {
			rc = imap_readline(&chan->imap, &line);
			if (!rc) {
				channel_feed(chan, line);
			} else if (-EAGAIN == rc) {
				chan->pollfd->events = imap_get_events(&chan->imap);
				return;
			} else if (-EIO == rc) {
				chan->state = CHANNEL_STATE_DISCONNECTED;
				break;
			} else if (rc < 0) {
				chan->state = CHANNEL_STATE_ERROR;
				break;
			}
		}
		break;

	case CHANNEL_STATE_DISCONNECTED:
		channel_log(chan, LOG_ERR, "Disconnected.");
		chan->pid = 0;
		chan->pollfd->fd = -1;
		chan->timeout = 3 * 1000;
		chan->state = CHANNEL_STATE_GROUND;
		return;

	case CHANNEL_STATE_ERROR:
		ERR_print_errors_fp(stderr);
		channel_log(chan, LOG_ERR, "Error.");
		chan->pid = 0;
		chan->pollfd->fd = -1;
		chan->timeout = 5 * 60 * 1000;
		chan->state = CHANNEL_STATE_GROUND;
		return;
	}
}

static struct channel *
find_channel_by_pid(pid_t pid)
{
	for (size_t i = 0; i < nchannels; ++i) {
		struct channel *chan = &channels[i];
		if (pid == chan->pid)
			return chan;
	}
	return NULL;
}

static void
handle_sigchld(int sig)
{
	(void)sig;
	int status;
	for (pid_t pid; 0 < (pid = waitpid(-1, &status, 0));) {
		struct channel *chan = find_channel_by_pid(pid);
		if (!chan)
			continue;

		int ok = WIFEXITED(status) && EXIT_SUCCESS == WEXITSTATUS(status);
		int level = ok ? LOG_INFO : LOG_ERR;
		channel_log(chan, level, "Command terminated with %s.",
				ok ? "success" : "failure");

		chan->pid = 0;
		if (chan->want_sync)
			chan->timeout = opt_rerun_delay;
	}
}

int
main(int argc, char *argv[])
{
	struct sigaction sa;
	sigfillset(&sa.sa_mask);

	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	sa.sa_flags = SA_RESTART;
	sa.sa_handler = handle_sigchld;
	sigaction(SIGCHLD, &sa, NULL);

	sigset_t ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGCHLD);
	sigprocmask(SIG_BLOCK, &ss, NULL);

	if (SSL_library_init() < 0)
		return EXIT_FAILURE;
	SSL_load_error_strings();

	for (int opt; 0 <= (opt = getopt(argc, argv, "c:e:d:D:vh"));) {
		switch (opt) {
		case 'c':
			opt_config = optarg;
			break;

		case 'e':
			opt_cmd = optarg;
			break;

		case 'd':
			opt_reaction_time = atoi(optarg);
			break;

		case 'D':
			opt_rerun_delay = atoi(optarg);
			break;

		case 'v':
			opt_verbose = 1;
			fprintf(stderr, MBIDLED_VERSION "\n");
			break;

		case 'h':
			printf(USAGE, argv[0]);
			return EXIT_SUCCESS;

		default:
			return EXIT_FAILURE;
		}
	}

	if (!opt_config) {
		fprintf(stderr, "missing required option -- 'c'\n");
		return EXIT_FAILURE;
	}

	struct mbconfig mb_config;
	struct mbconfig_parser mb_config_parser;
	mb_config_parser.config = &mb_config;
	if (mbconfig_parse(&mb_config_parser, opt_config) < 0) {
		fprintf(stderr, "%s:%d:%d: %s\n",
				opt_config,
				mb_config_parser.lnum,
				mb_config_parser.col,
				mb_config_parser.error_msg);
		fprintf(stderr, "Could not parse configuration file. Halting.\n");
		return EXIT_FAILURE;
	}

	for (struct mbconfig_channel *mb_chan = mb_config.channels;
	     mb_chan;
	     mb_chan = mb_chan->next)
		if (mb_chan->sync_pull)
			++nchannels;

	pollfds = malloc(nchannels * sizeof *pollfds);
	channels = malloc(nchannels * sizeof *channels);
	if (!pollfds || !channels)
		return EXIT_FAILURE;

	size_t i = 0;
	for (struct mbconfig_channel *mb_chan = mb_config.channels;
	     mb_chan;
	     mb_chan = mb_chan->next)
	{
		if (!mb_chan->sync_pull)
			continue;

		struct channel *chan = &channels[i];
		channel_init(chan, &pollfds[i], &mb_config, mb_chan);
		++i;
	}

	struct timespec start, now;
	clock_gettime(CLOCK_MONOTONIC, &start);

	sigemptyset(&ss);

	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		int elapsed = ts_sub_ms(&now, &start);
		memcpy(&start, &now, sizeof start);

		int next_timeout = -1;
		for (size_t i = 0; i < nchannels; ++i) {
			struct pollfd *pollfd = &pollfds[i];
			struct channel *chan = &channels[i];

			if ((0 <= chan->timeout &&
			     (chan->timeout -= elapsed) < 0) ||
			     pollfd->revents)
				channel_poll(chan);

			if (0 <= chan->timeout &&
			    (next_timeout < 0 || chan->timeout < next_timeout))
				next_timeout = chan->timeout;
		}

		if (0 < next_timeout) {
			clock_gettime(CLOCK_MONOTONIC, &now);
			elapsed = ts_sub_ms(&now, &start);
			next_timeout -= elapsed;
			if (next_timeout < 0)
				next_timeout = 0;
		}

		struct timespec timeout, *ptimeout;
		if (next_timeout < 0) {
			ptimeout = NULL;
		} else {
			ptimeout = &timeout;
			ts_set_ms(&timeout, next_timeout);
		}

		int rc = ppoll(pollfds, nchannels, ptimeout, &ss);
		if (rc < 0) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
				/* Ignore. */
				break;

			default:
				return EXIT_FAILURE;
			}
		}
	}
}
