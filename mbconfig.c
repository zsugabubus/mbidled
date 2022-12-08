/* mbsync(1) configuration parser. */
#include <ctype.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "mbconfig.h"

#define MBIDLED_CMD_PREFIX "#MBIDLED:"

#define ISARG(kw) ( \
	ctx->argsz == sizeof kw - 1 && \
	!memcmp(ctx->buf, kw, sizeof kw - 1) \
)

#define ISPREFIXARG(kw) ( \
	sizeof kw - 1 <= ctx->argsz && \
	!memcmp(ctx->buf, kw, sizeof kw - 1) \
)

#define ALLOC_DATA(slist_head, type) \
	struct type *data = calloc(1, sizeof *data); \
	if (data == NULL) \
		abort(); \
	SLIST_INSERT_HEAD(&ctx->config->slist_head, data, link);

#define SECTION_FOREACH \
	int rc = parse_str(ctx, &data->name); \
	while (0 < rc && \
	       0 < (rc = get_cmd(ctx)) && \
	       0 < (rc = preprocess_cmd(ctx, 0)))

static int
get_arg(struct mbconfig_parser *ctx, char delim, int caseless)
{
	for (;; ++ctx->col) {
		char const *s = ctx->buf + ctx->col;
		if (!*s || (*s == '#' && strncmp(MBIDLED_CMD_PREFIX, s, sizeof MBIDLED_CMD_PREFIX - 1)))
			return 0;
		if (isspace(*s))
			continue;
		break;
	}

	int quoted = 0;
	int escaped = 0;

	char *arg = ctx->buf;

	for (char c; (c = ctx->buf[ctx->col]);) {
		++ctx->col;
		if (!escaped && c == '\\') {
			escaped = 1;
		} else if (!escaped && c == '"') {
			quoted ^= 1;
		} else if (!escaped && !quoted && (isspace(c) || (delim == c))) {
			break;
		} else {
			/* Make c faster. */
			if (caseless && islower(c))
				c = toupper(c);

			*arg++ = c;
			escaped = 0;
		}
	}

	if (quoted) {
		ctx->error_msg = "Unterminated quoted string";
		return -1;
	}

	if (escaped) {
		ctx->error_msg = "Unterminated escape sequence";
		return -1;
	}

	*arg = '\0';

	ctx->argsz = (unsigned short)(arg - ctx->buf);
	return 1;
}

static int
get_kw(struct mbconfig_parser *ctx)
{
	return get_arg(ctx, '\0', 1);
}

static int
get_str(struct mbconfig_parser *ctx)
{
	return get_arg(ctx, '\0', 0);
}

static int
want_str(struct mbconfig_parser *ctx)
{
	int rc = get_str(ctx);
	if (!rc) {
		ctx->error_msg = "Argument expected";
		rc = -1;
	}
	return rc;
}

static int
get_line(struct mbconfig_parser *ctx)
{
	int rc = get_str(ctx);
	if (rc) {
		ctx->error_msg = "Extra arguments";
		return -1;
	}

	++ctx->lnum;
	ctx->col = 0;

	/* BANANA: fgets() == fucking gets(). Actually you do not need to
	 * terminate lines with \n, it is also good if you pad it with spaces
	 * to 1023 characters. */
	if (!fgets(ctx->buf, sizeof ctx->buf, ctx->stream)) {
		*ctx->buf = '\0';
		if (ferror(ctx->stream)) {
			ctx->error_msg = strerror(EIO);
			return -1;
		}
		return 0;
	}

	return 1;
}

static int
get_cmd(struct mbconfig_parser *ctx)
{
	int rc = get_line(ctx);
	if (rc <= 0)
		return rc;
	return get_kw(ctx);
}

static void
dup_arg(struct mbconfig_parser *ctx, char **data)
{
	free(*data);
	if ((*data = malloc(ctx->argsz + 1 /* NUL */)) == NULL)
		abort();

	memcpy(*data, ctx->buf, ctx->argsz);
	(*data)[ctx->argsz] = '\0';
}

static int
parse_str(struct mbconfig_parser *ctx, char **data)
{
	int rc = want_str(ctx);
	if (rc <= 0)
		return rc;
	dup_arg(ctx, data);
	return 1;
}

static int
parse_int(struct mbconfig_parser *ctx, int *data)
{
	int rc = want_str(ctx);
	if (rc < 0)
		return rc;
	else if (!rc)
		goto invalid;

	char *end;
	errno = 0;
	*data = strtol(ctx->buf, &end, 10);
	if (errno) {
	invalid:;
		ctx->error_msg = "Invalid number";
		return -1;
	} else if (*end) {
		ctx->error_msg = "Junk after number";
		return -1;
	}
	return 1;
}

static int
parse_path(struct mbconfig_parser *ctx, char **data)
{
	int rc = want_str(ctx);
	if (rc <= 0)
		return rc;

	char *s = ctx->buf;
	if (*s == '~') {
		++s;

		char *slash = strchr(s, '/');
		if (!slash)
			slash = s + strlen(s);

		struct passwd *pw;
		if (s == slash) {
			pw = getpwuid(geteuid());
		} else {
			char old = *slash;
			*slash = '\0';
			pw = getpwnam(s);
			*slash = old;
		}

		int n = snprintf(NULL, 0, "%s%s", pw->pw_dir, slash);
		free(*data);
		if ((*data = malloc(n + 1 /* NUL */)) == NULL)
			abort();
		sprintf(*data, "%s%s", pw->pw_dir, slash);
		return 1;
	} else {
		dup_arg(ctx, data);
		return 1;
	}
}

static int
parse_bool(struct mbconfig_parser *ctx, int *data)
{
	int rc = get_kw(ctx);
	if (rc <= 0)
		return rc;

	if (ISARG("YES") || ISARG("TRUE") || ISARG("ON") || ISARG("1")) {
		*data = 1;
	} else if (ISARG("NO") || ISARG("FALSE") || ISARG("OFF") || ISARG("0")) {
		*data = 0;
	} else {
		ctx->error_msg = "Invalid boolean value";
		return -1;
	}

	return 1;
}

static int
parse_store(struct mbconfig_parser *ctx, struct mbconfig_store *data)
{
	int rc = get_arg(ctx, ':', 0);
	if (rc <= 0)
		return rc;
	if (ctx->argsz)
		goto bad_format;

	rc = get_arg(ctx, ':', 0);
	if (rc <= 0)
		goto bad_format;

	char const *store = ctx->buf;

	do {
		struct mbconfig_imap_store *imap_store;
		SLIST_FOREACH(imap_store, &ctx->config->imap_stores, link)
			if (!strcmp(store, imap_store->name))
				break;
		if (imap_store) {
			data->type = MBCONFIG_STORE_IMAP;
			data->imap_store = imap_store;
			break;
		}

		struct mbconfig_maildir_store *maildir_store;
		SLIST_FOREACH(maildir_store, &ctx->config->maildir_stores, link)
			if (!strcmp(store, maildir_store->name))
				break;
		if (maildir_store) {
			data->type = MBCONFIG_STORE_MAILDIR;
			data->maildir_store = maildir_store;
			break;
		}

		ctx->error_msg = "No such IMAPStore or MaildirStore";
		return -1;
	} while (0);

	rc = get_str(ctx);
	if (rc < 0) {
		return rc;
	} else if (!rc) {
		data->mailbox = NULL;
		return 1;
	} else {
		dup_arg(ctx, &data->mailbox);
		return 1;
	}

bad_format:
	ctx->error_msg = "Bad format";
	return -1;
}

static int
parse_str_list(struct mbconfig_parser *ctx, struct mbconfig_str_list *data)
{
	/* We barely care about memory leaks. */
	SLIST_INIT(data);

	int rc;
	while (0 < (rc = get_str(ctx))) {
		struct mbconfig_str *pattern = calloc(1, sizeof *pattern);
		if (pattern == NULL)
			abort();

		dup_arg(ctx, &pattern->str);
		/* Note that patterns are in reverse order. */
		SLIST_INSERT_HEAD(data, pattern, link);
	}
	if (0 <= rc)
		rc = 1;
	return rc;
}

static int
preprocess_cmd(struct mbconfig_parser *ctx, int global)
{
	int rc = 1;
	struct mbconfig_mbidled_channel *c = &ctx->channel_config[global];

	if (ISARG(MBIDLED_CMD_PREFIX "STRICTPROPAGATE")) {
		if ((rc = get_kw(ctx)) != 1)
			return rc;
		if (ISARG("NONE")) {
			c->strict_propagate = 0;
		} else if (ISARG("FAR")) {
			c->strict_propagate = MBCONFIG_PROPAGATE_FAR;
		} else if (ISARG("NEAR")) {
			c->strict_propagate = MBCONFIG_PROPAGATE_NEAR;
		} else if (ISARG("BOTH")) {
			c->strict_propagate =
				MBCONFIG_PROPAGATE_NEAR |
				MBCONFIG_PROPAGATE_FAR;
		} else {
			ctx->error_msg = "Unknown argument";
			return -1;
		}
	} else if (ISARG(MBIDLED_CMD_PREFIX "STARTTIMEOUT")) {
		rc = parse_int(ctx, &c->start_timeout);
	} else if (ISARG(MBIDLED_CMD_PREFIX "STARTINTERVAL")) {
		rc = parse_int(ctx, &c->start_interval);
	} else if (ISPREFIXARG(MBIDLED_CMD_PREFIX)) {
		/* Drop command prefix. */
		int const l = sizeof MBIDLED_CMD_PREFIX - 1;
		ctx->argsz -= l;
		memmove(ctx->buf, ctx->buf + l, ctx->argsz + 1 /* NUL */);
	}

	if (global)
		/* Reset local config to global. */
		memcpy(&ctx->channel_config[0], &ctx->channel_config[1],
				sizeof ctx->channel_config[0]);

	return rc;
}

static void
skip_unknown_cmd(struct mbconfig_parser *ctx)
{
	ctx->buf[ctx->col] = '\0';
}

static int
parse_imap_account_section(struct mbconfig_parser *ctx)
{
	ALLOC_DATA(imap_accounts, mbconfig_imap_account);

	data->system_certs = 1;
	data->login_auth = 1;
	data->ssl_versions = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;

	SECTION_FOREACH {
		if (ISARG("HOST")) {
			rc = parse_str(ctx, &data->host);
		} else if (ISARG("PORT")) {
			rc = parse_str(ctx, &data->port);
		} else if (ISARG("USER")) {
			rc = parse_str(ctx, &data->user);
		} else if (ISARG("USERCMD")) {
			rc = parse_str(ctx, &data->user_cmd);
		} else if (ISARG("PASS")) {
			rc = parse_str(ctx, &data->pass);
		} else if (ISARG("PASSCMD")) {
			rc = parse_str(ctx, &data->pass_cmd);
		} else if (ISARG("TUNNEL")) {
			rc = parse_str(ctx, &data->tunnel_cmd);
		} else if (ISARG("AUTHMECHS")) {
			data->login_auth = 0;
			while (0 < (rc = get_kw(ctx)))
				data->login_auth |= ISARG("*") || ISARG("LOGIN");
			if (0 <= rc)
				rc = 1;
		} else if (ISARG("TLSTYPE") || ISARG("SSLTYPE")) {
			if (!(rc = get_kw(ctx))) {
				continue;
			} else if (rc < 0) {
				break;
			}
			if (ISARG("NONE")) {
				data->ssl = MBCONFIG_SSL_NONE;
			} else if (ISARG("IMAPS")) {
				data->ssl = MBCONFIG_SSL_IMAPS;
			} else {
				ctx->error_msg = "Unknown argument";
				return -1;
			}
		} else if (ISARG("TLSVERSIONS")) {
			while (0 < (rc = get_kw(ctx))) {
				int op = *ctx->buf;
				memmove(ctx->buf, ctx->buf + 1, ctx->argsz-- + 1 /* NUL */);

				int version;
				if (ISARG("1.0")) {
					version = SSL_OP_NO_TLSv1;
				} else if (ISARG("1.1")) {
					version = SSL_OP_NO_TLSv1_1;
				} else if (ISARG("1.2")) {
					version = SSL_OP_NO_TLSv1_2;
				} else if (ISARG("1.3")) {
					version = SSL_OP_NO_TLSv1_3;
				} else {
					ctx->error_msg = "Unrecognized TLS version";
					return -1;
				}

				if (op == '-') {
					data->ssl_versions |= version;
				} else if (op == '+') {
					data->ssl_versions &= ~version;
				} else {
					ctx->error_msg = "+ OR - expected";
					return -1;
				}
			}
			if (0 <= rc)
				rc = 1;
		} else if (ISARG("SSLVERSIONS")) {
#define ARGS \
	/* xmacro(name, op) */ \
	xmacro("SSLV3", SSL_OP_NO_SSLv3) \
	xmacro("TLSV1", SSL_OP_NO_TLSv1) \
	xmacro("TLSV1.1", SSL_OP_NO_TLSv1_1) \
	xmacro("TLSV1.2", SSL_OP_NO_TLSv1_2) \
	xmacro("TLSV1.3", SSL_OP_NO_TLSv1_3) \

#define xmacro(name, op) | op
			data->ssl_versions = 0 ARGS;
#undef xmacro
			while (0 < (rc = get_kw(ctx))) {
				if (0) (void)0;
#define xmacro(name, op) else if (ISARG(name)) data->ssl_versions &= ~(op);
				ARGS
#undef xmacro
			}
#undef ARGS
			if (0 <= rc)
				rc = 1;
		} else if (ISARG("SYSTEMCERTIFICATES")) {
			rc = parse_bool(ctx, &data->system_certs);
		} else if (ISARG("CERTIFICATEFILE")) {
			rc = parse_path(ctx, &data->cert_file);
		} else if (ISARG("CIPHERSTRING")) {
			rc = parse_str(ctx, &data->ciphers);
		} else {
			skip_unknown_cmd(ctx);
		}
	}

	if (rc < 0)
		return rc;

	if (!data->user && !data->user_cmd) {
		ctx->error_msg = "Neither User nor UserCmd present";
		return -1;
	}

	if (!data->pass && !data->pass_cmd) {
		ctx->error_msg = "Neither Pass nor PassCmd present";
		return -1;
	}

	if (!data->host && !data->tunnel_cmd) {
		ctx->error_msg = "Neither Host nor Tunnel present";
		return -1;
	}

	return rc;
}

static int
parse_imap_store_section(struct mbconfig_parser *ctx)
{
	ALLOC_DATA(imap_stores, mbconfig_imap_store);

	SECTION_FOREACH {
		if (ISARG("ACCOUNT")) {
			if ((rc = want_str(ctx)) <= 0)
				break;
			struct mbconfig_imap_account *account;
			SLIST_FOREACH(account, &ctx->config->imap_accounts, link)
				if (!strcmp(ctx->buf, account->name))
					break;
			if (!account) {
				ctx->error_msg = "No such IMAPAccount";
				return -1;
			}
			data->account = account;
		} else {
			skip_unknown_cmd(ctx);
		}
	}

	if (0 <= rc && !data->account) {
		ctx->error_msg = "Missing required Account";
		return -1;
	}

	return rc;
}

static int
parse_maildir_store_section(struct mbconfig_parser *ctx)
{
	ALLOC_DATA(maildir_stores, mbconfig_maildir_store);

	SECTION_FOREACH {
		if (ISARG("PATH"))
			rc = parse_path(ctx, &data->path);
		else if (ISARG("INBOX"))
			rc = parse_path(ctx, &data->inbox);
		else
			skip_unknown_cmd(ctx);
	}

	if (0 <= rc && !data->path) {
		ctx->error_msg = "Missing required Path";
		return -1;
	}

	return rc;
}

static int
parse_channel_section(struct mbconfig_parser *ctx)
{
	ALLOC_DATA(channels, mbconfig_channel);

	data->sync = MBCONFIG_SYNC_PUSH | MBCONFIG_SYNC_PULL;

	SECTION_FOREACH {
		if (ISARG("FAR")) {
			rc = parse_store(ctx, &data->far);
		} else if (ISARG("NEAR")) {
			rc = parse_store(ctx, &data->near);
		} else if (ISARG("PATTERN") || ISARG("PATTERNS")) {
			rc = parse_str_list(ctx, &data->patterns);
		} else if (ISARG("SYNC")) {
			data->sync = 0;
			while (0 < (rc = get_kw(ctx))) {
				if (ISARG("NONE"))
					/* Nop. */;
				else if (ISPREFIXARG("PULL"))
					data->sync |= MBCONFIG_SYNC_PULL;
				else if (ISPREFIXARG("PUSH"))
					data->sync |= MBCONFIG_SYNC_PUSH;
				else
					/* Specifying flag both pulls and pushes. */
					data->sync |=
						MBCONFIG_SYNC_PULL |
						MBCONFIG_SYNC_PUSH;
			}
			if (0 <= rc)
				rc = 1;
		} else {
			skip_unknown_cmd(ctx);
		}
	}

	if (rc < 0)
		return rc;

	if (!data->near.store) {
		ctx->error_msg = "Missing required Near";
		return -1;
	}

	if (!data->far.store) {
		ctx->error_msg = "Missing required Far";
		return -1;
	}

	memcpy(&data->mbidled, &ctx->channel_config[0], sizeof data->mbidled);

	return rc;
}

int
mbconfig_parse(struct mbconfig_parser *ctx, char const *filename)
{
	struct mbconfig *config = ctx->config;

	ctx->channel_config[1] = (struct mbconfig_mbidled_channel){
		.start_timeout = 1,
		.start_interval = 30,
		.strict_propagate =
			MBCONFIG_PROPAGATE_NEAR |
			MBCONFIG_PROPAGATE_FAR,
	};

	SLIST_INIT(&config->imap_accounts);
	SLIST_INIT(&config->imap_stores);
	SLIST_INIT(&config->maildir_stores);
	SLIST_INIT(&config->channels);

	ctx->lnum = 0;

	config->filename = strdup(filename);
	if (config->filename == NULL)
		abort();

	ctx->stream = fopen(filename, "r");
	if (!ctx->stream) {
		free(config->filename);
		ctx->error_msg = strerror(errno);
		return -1;
	}

	*ctx->buf = 0;
	ctx->col = 0;

	int rc = 0;
	while (0 <= rc && 0 < (rc = get_line(ctx))) {
		rc = get_kw(ctx);
		if (rc < 0)
			break;
		else if (!rc)
			continue;
		rc = preprocess_cmd(ctx, 1);
		if (rc < 0)
			break;
		if (ISARG("IMAPACCOUNT"))
			rc = parse_imap_account_section(ctx);
		else if (ISARG("IMAPSTORE"))
			rc = parse_imap_store_section(ctx);
		else if (ISARG("MAILDIRSTORE"))
			rc = parse_maildir_store_section(ctx);
		else if (ISARG("CHANNEL"))
			rc = parse_channel_section(ctx);
		else
			skip_unknown_cmd(ctx);
	}

	fclose(ctx->stream);
	return rc;
}

void
mbconfig_eval_cmd_option(char **option, char const *option_cmd)
{
	if (*option)
		return;

	char buf[8192];

	option_cmd += *option_cmd == '+';
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

int
match_pattern(char const *pat, char const *s)
{
	if (*pat == '*') {
		return
			/* Continue * match. */
			(*s && match_pattern(pat, s + 1)) ||
			/* End of * match. */
			match_pattern(pat + 1, s);
	} else if (*pat == '%') {
		/* '/' seems to be the hardcoded hierarchy delimiter. */
		return
			/* Continue % match. */
			(*s && *s != '/' && match_pattern(pat, s + 1)) ||
			/* End of % match. */
			match_pattern(pat + 1, s);
	} else if (*pat == *s) {
		/* Accept. */
		if (!*s)
			return 1;

		/* Next. */
		return match_pattern(pat + 1, s + 1);
	} else {
		/* Reject. */
		return 0;
	}
}

int
mbconfig_patterns_test(struct mbconfig_str_list const *patterns, char const *s)
{
	if (SLIST_EMPTY(patterns))
		return 1;

	struct mbconfig_str *pattern;
	SLIST_FOREACH(pattern, patterns, link) {
		int not;
		char const *pat = pattern->str;
		pat += (not = (*pat == '!'));
		if (match_pattern(pat, s))
			return !not;
	}

	return 0;
}
