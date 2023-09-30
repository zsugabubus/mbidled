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

enum {
	ERR = -1,
	NONE = 0,
	OK = 1,
};

#define MBIDLED_CMD_PREFIX "#MBIDLED:"

#define ISARG(kw) (strcmp(ctx->arg, kw) == 0)
#define ISPREFIXARG(kw) (strncmp(ctx->arg, kw, strlen(kw)) == 0)

#define ALLOC_DATA(slist_head, type) \
	struct type *data = calloc(1, sizeof *data); \
	if (data == NULL) \
		abort(); \
	SLIST_INSERT_HEAD(&ctx->config->slist_head, data, link);

#define SECTION_FOREACH \
	int rc = parse_str(ctx, &data->name); \
	while (rc != ERR && (rc = read_line(ctx)) == OK && (rc = read_kw(ctx)) == OK && \
	       (rc = preprocess_cmd(ctx, 0)) == OK)

static int
read_arg(struct mbconfig_parser *ctx, int caseless)
{
	for (;; ctx->col += 1) {
		char const *s = ctx->buf + ctx->col;
		if (*s == '\0')
			return NONE;
		if (isspace(*s))
			continue;
		break;
	}

	int quoted = 0;
	int escaped = 0;

	ctx->arg = ctx->buf + ctx->col;
	char *p = ctx->arg;

	for (;;) {
		char c = ctx->buf[ctx->col];
		if (c == '\0')
			break;

		ctx->col += 1;

		if (!escaped && c == '\\') {
			escaped = 1;
		} else if (!escaped && c == '"') {
			quoted ^= 1;
		} else if (!escaped && !quoted && isspace(c)) {
			break;
		} else {
			if (caseless && islower(c))
				c = toupper(c);

			*p++ = c;
			escaped = 0;
		}
	}

	if (quoted) {
		ctx->error_msg = "Unterminated quoted string";
		return ERR;
	}

	if (escaped) {
		ctx->error_msg = "Unterminated escape sequence";
		return ERR;
	}

	*p = '\0';

	return OK;
}

static int
read_kw(struct mbconfig_parser *ctx)
{
	return read_arg(ctx, 1);
}

static int
read_str(struct mbconfig_parser *ctx)
{
	return read_arg(ctx, 0);
}

static int
expect_kw(struct mbconfig_parser *ctx)
{
	int rc = read_kw(ctx);
	if (rc == NONE) {
		ctx->error_msg = "Argument expected";
		rc = ERR;
	}
	return rc;
}

static int
expect_str(struct mbconfig_parser *ctx)
{
	int rc = read_str(ctx);
	if (rc == NONE) {
		ctx->error_msg = "Argument expected";
		rc = ERR;
	}
	return rc;
}

static int
read_line(struct mbconfig_parser *ctx)
{
	int rc = read_str(ctx);
	if (rc) {
		ctx->error_msg = "Extra arguments";
		return ERR;
	}

	do {
		ctx->lnum += 1;
		ctx->col = 0;
		*ctx->buf = '\0';
		ctx->arg = ctx->buf;

		if (fgets(ctx->buf, sizeof ctx->buf, ctx->stream) == NULL) {
			if (ferror(ctx->stream)) {
				ctx->error_msg = "I/O error";
				return ERR;
			}
			return NONE;
		}
		ctx->buf[strcspn(ctx->buf, "\r\n")] = '\0';

		if (strncmp(MBIDLED_CMD_PREFIX, ctx->buf, strlen(MBIDLED_CMD_PREFIX)) == 0)
			break;
	} while (*ctx->buf == '#');

	return OK;
}

static int
parse_str(struct mbconfig_parser *ctx, char **data)
{
	int rc = expect_str(ctx);
	if (rc == OK) {
		free(*data);
		*data = strdup(ctx->arg);
		if (*data == NULL)
			abort();
	}
	return rc;
}

static int
parse_int(struct mbconfig_parser *ctx, int *data)
{
	int rc = expect_str(ctx);
	if (rc != OK)
		return rc;

	char *end;
	errno = 0;
	*data = strtol(ctx->arg, &end, 10);
	if (ctx->arg == end || errno) {
		ctx->error_msg = "Invalid number";
		return ERR;
	} else if (*end != '\0') {
		ctx->error_msg = "Junk after number";
		return ERR;
	}

	return OK;
}

static int
parse_path(struct mbconfig_parser *ctx, char **data)
{
	int rc = expect_str(ctx);
	if (rc != OK)
		return rc;

	free(*data);

	char *s = ctx->arg;
	if (*s == '~') {
		s += 1;

		char *slash = s + strcspn(s, "/");

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
		*data = malloc(n + 1 /* NUL */);
		if (*data == NULL)
			abort();
		sprintf(*data, "%s%s", pw->pw_dir, slash);
	} else {
		*data = strdup(s);
		if (*data == NULL)
			abort();
	}

	return OK;
}

static int
parse_bool(struct mbconfig_parser *ctx, int *data)
{
	int rc = expect_kw(ctx);
	if (rc == ERR)
		return ERR;

	if (ISARG("YES") || ISARG("TRUE") || ISARG("ON") || ISARG("1")) {
		*data = 1;
	} else if (ISARG("NO") || ISARG("FALSE") || ISARG("OFF") || ISARG("0")) {
		*data = 0;
	} else {
		ctx->error_msg = "Invalid boolean value";
		return ERR;
	}

	return OK;
}

static int
parse_store(struct mbconfig_parser *ctx, struct mbconfig_store *data)
{
	if (expect_str(ctx) == ERR)
		return ERR;

	if (*ctx->arg != ':') {
		ctx->error_msg = "Expected ':' before store name";
		return ERR;
	}
	ctx->arg += 1;

	char const *store = ctx->arg;

	char *sep = strchr(ctx->arg, ':');
	if (sep == NULL) {
		ctx->error_msg = "Expected ':' after store name";
		return ERR;
	}
	*sep = '\0';

	do {
		struct mbconfig_imap_store *imap_store;
		SLIST_FOREACH (imap_store, &ctx->config->imap_stores, link)
			if (strcmp(store, imap_store->name) == 0)
				break;
		if (imap_store) {
			data->type = MBCONFIG_STORE_IMAP;
			data->imap_store = imap_store;
			break;
		}

		struct mbconfig_maildir_store *maildir_store;
		SLIST_FOREACH (maildir_store, &ctx->config->maildir_stores, link)
			if (strcmp(store, maildir_store->name) == 0)
				break;
		if (maildir_store) {
			data->type = MBCONFIG_STORE_MAILDIR;
			data->maildir_store = maildir_store;
			break;
		}

		ctx->error_msg = "No such IMAPStore or MaildirStore";
		return ERR;
	} while (0);

	free(data->mailbox);
	data->mailbox = strdup(sep + 1);
	if (data->mailbox == NULL)
		abort();

	return OK;
}

static int
parse_patterns(struct mbconfig_parser *ctx, struct mbconfig_str_list *data)
{
	/* We barely care about memory leaks. */
	SLIST_INIT(data);

	int rc;
	while (0 < (rc = read_str(ctx))) {
		struct mbconfig_str *pattern = calloc(1, sizeof *pattern);
		if (pattern == NULL)
			abort();

		pattern->str = strdup(ctx->arg);
		if (pattern->str == NULL)
			abort();

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
		if ((rc = expect_kw(ctx)) != OK)
			return rc;
		if (ISARG("NONE")) {
			c->strict_propagate = 0;
		} else if (ISARG("FAR")) {
			c->strict_propagate = MBCONFIG_PROPAGATE_FAR;
		} else if (ISARG("NEAR")) {
			c->strict_propagate = MBCONFIG_PROPAGATE_NEAR;
		} else if (ISARG("BOTH")) {
			c->strict_propagate = MBCONFIG_PROPAGATE_NEAR | MBCONFIG_PROPAGATE_FAR;
		} else {
			ctx->error_msg = "Unknown argument";
			return ERR;
		}
	} else if (ISARG(MBIDLED_CMD_PREFIX "STARTTIMEOUT")) {
		rc = parse_int(ctx, &c->start_timeout);
	} else if (ISARG(MBIDLED_CMD_PREFIX "STARTINTERVAL")) {
		rc = parse_int(ctx, &c->start_interval);
	} else if (ISPREFIXARG(MBIDLED_CMD_PREFIX)) {
		ctx->arg += strlen(MBIDLED_CMD_PREFIX);
	}

	if (global)
		/* Reset local config to global. */
		memcpy(&ctx->channel_config[0],
		       &ctx->channel_config[1],
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
	data->ssl = MBCONFIG_SSL_STARTTLS;
	data->ssl_versions = SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;

	SECTION_FOREACH
	{
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
			while ((rc = read_kw(ctx)) == OK)
				data->login_auth |= ISARG("*") || ISARG("LOGIN");
		} else if (ISARG("TLSTYPE") || ISARG("SSLTYPE")) {
			if ((rc = expect_kw(ctx)) != OK)
				continue;
			if (ISARG("NONE")) {
				data->ssl = MBCONFIG_SSL_NONE;
			} else if (ISARG("STARTTLS")) {
				data->ssl = MBCONFIG_SSL_STARTTLS;
			} else if (ISARG("IMAPS")) {
				data->ssl = MBCONFIG_SSL_IMAPS;
			} else {
				ctx->error_msg = "Unknown argument";
				return ERR;
			}
		} else if (ISARG("TLSVERSIONS")) {
			while ((rc = read_kw(ctx)) == OK) {
				int op = *ctx->arg;
				ctx->arg += 1;

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
					return ERR;
				}

				if (op == '-') {
					data->ssl_versions |= version;
				} else if (op == '+') {
					data->ssl_versions &= ~version;
				} else {
					ctx->error_msg = "+ OR - expected";
					return ERR;
				}
			}
		} else if (ISARG("SSLVERSIONS")) {
#define ARGS \
	/* xmacro(name, op) */ \
	xmacro("SSLV3", SSL_OP_NO_SSLv3) xmacro("TLSV1", SSL_OP_NO_TLSv1) \
		xmacro("TLSV1.1", SSL_OP_NO_TLSv1_1) xmacro("TLSV1.2", SSL_OP_NO_TLSv1_2) \
			xmacro("TLSV1.3", SSL_OP_NO_TLSv1_3)

#define xmacro(name, op) | op
			data->ssl_versions = 0 ARGS;
#undef xmacro
			while ((rc = read_kw(ctx)) == OK) {
				if (0)
					(void)0;
#define xmacro(name, op) else if (ISARG(name)) data->ssl_versions &= ~(op);
				ARGS
#undef xmacro
			}
#undef ARGS
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

	if (rc == ERR)
		return ERR;

	if (data->user == NULL && data->user_cmd == NULL) {
		ctx->error_msg = "Neither User nor UserCmd present";
		return ERR;
	}

	if (data->pass == NULL && data->pass_cmd == NULL) {
		ctx->error_msg = "Neither Pass nor PassCmd present";
		return ERR;
	}

	if (data->host == NULL && data->tunnel_cmd == NULL) {
		ctx->error_msg = "Neither Host nor Tunnel present";
		return ERR;
	}

	return OK;
}

static int
parse_imap_store_section(struct mbconfig_parser *ctx)
{
	ALLOC_DATA(imap_stores, mbconfig_imap_store);

	SECTION_FOREACH
	{
		if (ISARG("ACCOUNT")) {
			if ((rc = expect_str(ctx)) <= 0)
				break;
			struct mbconfig_imap_account *account;
			SLIST_FOREACH (account, &ctx->config->imap_accounts, link)
				if (strcmp(ctx->arg, account->name) == 0)
					break;
			if (account == NULL) {
				ctx->error_msg = "No such IMAPAccount";
				return ERR;
			}
			data->account = account;
		} else {
			skip_unknown_cmd(ctx);
		}
	}

	if (0 <= rc && data->account == NULL) {
		ctx->error_msg = "Missing required Account";
		return ERR;
	}

	return rc;
}

static int
parse_maildir_store_section(struct mbconfig_parser *ctx)
{
	ALLOC_DATA(maildir_stores, mbconfig_maildir_store);

	SECTION_FOREACH
	{
		if (ISARG("PATH"))
			rc = parse_path(ctx, &data->path);
		else if (ISARG("INBOX"))
			rc = parse_path(ctx, &data->inbox);
		else
			skip_unknown_cmd(ctx);
	}

	if (0 <= rc && data->path == NULL) {
		ctx->error_msg = "Missing required Path";
		return ERR;
	}

	return rc;
}

static int
parse_channel_section(struct mbconfig_parser *ctx)
{
	ALLOC_DATA(channels, mbconfig_channel);

	data->sync = MBCONFIG_SYNC_PUSH | MBCONFIG_SYNC_PULL;

	SECTION_FOREACH
	{
		if (ISARG("FAR")) {
			rc = parse_store(ctx, &data->far);
		} else if (ISARG("NEAR")) {
			rc = parse_store(ctx, &data->near);
		} else if (ISARG("PATTERN") || ISARG("PATTERNS")) {
			rc = parse_patterns(ctx, &data->patterns);
		} else if (ISARG("SYNC")) {
			data->sync = 0;
			while ((rc = read_kw(ctx)) == OK) {
				if (ISARG("NONE"))
					/* Nop. */;
				else if (ISPREFIXARG("PULL"))
					data->sync |= MBCONFIG_SYNC_PULL;
				else if (ISPREFIXARG("PUSH"))
					data->sync |= MBCONFIG_SYNC_PUSH;
				else
					/* Specifying flag both pulls and pushes. */
					data->sync |= MBCONFIG_SYNC_PULL | MBCONFIG_SYNC_PUSH;
			}
		} else {
			skip_unknown_cmd(ctx);
		}
	}

	if (rc == ERR)
		return rc;

	if (data->near.store == NULL) {
		ctx->error_msg = "Missing required Near";
		return ERR;
	}

	if (data->far.store == NULL) {
		ctx->error_msg = "Missing required Far";
		return ERR;
	}

	memcpy(&data->mbidled, &ctx->channel_config[0], sizeof data->mbidled);

	return OK;
}

int
mbconfig_parse(struct mbconfig_parser *ctx, char const *filename)
{
	struct mbconfig *config = ctx->config;

	ctx->channel_config[1] = (struct mbconfig_mbidled_channel){
		.start_timeout = 1,
		.start_interval = 30,
		.strict_propagate = MBCONFIG_PROPAGATE_NEAR | MBCONFIG_PROPAGATE_FAR,
	};

	SLIST_INIT(&config->imap_accounts);
	SLIST_INIT(&config->imap_stores);
	SLIST_INIT(&config->maildir_stores);
	SLIST_INIT(&config->channels);

	ctx->lnum = 0;
	ctx->col = 0;
	*ctx->buf = '\0';
	ctx->arg = ctx->buf;

	config->filename = strdup(filename);
	if (config->filename == NULL)
		abort();

	ctx->stream = fopen(filename, "r");
	if (ctx->stream == NULL) {
		free(config->filename);
		ctx->error_msg = strerror(errno);
		return ERR;
	}

	int rc = NONE;
	while (rc != ERR && (rc = read_line(ctx)) == OK && (rc = read_kw(ctx)) != ERR &&
	       (rc = preprocess_cmd(ctx, 1)) == OK) {
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
	return rc == ERR ? -1 : 0;
}

void
mbconfig_eval_cmd_option(char **option, char const *option_cmd)
{
	if (*option != NULL)
		return;

	char buf[8192];

	option_cmd += *option_cmd == '+';
	FILE *stream = popen(option_cmd, "r");
	if (stream == NULL)
		return;
	char *ok = fgets(buf, sizeof buf, stream);
	pclose(stream);
	if (ok == NULL)
		return;
	char *s = strchr(buf, '\n');
	if (s != NULL)
		*s = '\0';
	*option = strdup(buf);
}

static int
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
		if (*s == '\0')
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
	SLIST_FOREACH (pattern, patterns, link) {
		int bang;
		char const *pat = pattern->str;
		pat += (bang = (*pat == '!'));
		if (match_pattern(pat, s))
			return !bang;
	}

	return 0;
}
