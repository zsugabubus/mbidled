/* mbsync(1) configuration parser. */
#include <ctype.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "mbconfig.h"

#define ISARG(kw) ( \
	ctx->argsz == sizeof kw - 1 && \
	!memcmp(ctx->buf, kw, sizeof kw - 1) \
)

static int
get_arg(struct mbconfig_parser *ctx, char delim, int caseless)
{
	for (;; ++ctx->col) {
		char c = ctx->buf[ctx->col];
		if (!c || '#' == c)
			return 0;
		if (isspace(c))
			continue;
		break;
	}

	int quoted = 0;
	int escaped = 0;

	char *arg = ctx->buf;

	for (char c; (c = ctx->buf[ctx->col]);) {
		++ctx->col;
		if (!escaped && '\\' == c) {
			escaped = 1;
		} else if (!escaped && '"' == c) {
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

static int
dup_arg(struct mbconfig_parser *ctx, char **data)
{
	free(*data);
	*data = malloc(ctx->argsz + 1 /* NUL */);
	if (!*data) {
		ctx->error_msg = strerror(ENOMEM);
		return -1;
	}

	memcpy(*data, ctx->buf, ctx->argsz);
	(*data)[ctx->argsz] = '\0';
	return 1;
}

static int
parse_str(struct mbconfig_parser *ctx, char **data)
{
	int rc = want_str(ctx);
	if (rc <= 0)
		return rc;
	return dup_arg(ctx, data);
}

static int
parse_path(struct mbconfig_parser *ctx, char **data)
{
	int rc = want_str(ctx);
	if (rc <= 0)
		return rc;

	char *s = ctx->buf;
	if ('~' == *s) {
		struct passwd *pw;
		char *slash = strchr(s, '/');
		char const *skip_slash;
		if (!slash)
			skip_slash = slash = s + strlen(s);
		else
			skip_slash = slash + 1;
		if (s + 1 == slash)
			pw = getpwuid(geteuid());
		else {
			*slash = '\0';
			pw = getpwnam(s + 1);
		}

		int n = snprintf(NULL, 0, "%s/%s", pw->pw_dir, skip_slash);
		free(*data);
		if (!(*data = malloc(n + 1 /* NUL */))) {
			ctx->error_msg = strerror(ENOMEM);
			return -1;
		}
		sprintf(*data, "%s/%s", pw->pw_dir, skip_slash);
		return 1;
	} else {
		return dup_arg(ctx, data);
	}
}

static int
parse_bool(struct mbconfig_parser *ctx, int *data)
{
	int rc = get_kw(ctx);
	if (rc <= 0)
		return rc;

	if (ISARG("YES") ||
	    ISARG("TRUE") ||
	    ISARG("ON") ||
	    ISARG("1"))
		*data = 1;
	else if (
	    ISARG("NO") ||
	    ISARG("FALSE") ||
	    ISARG("OFF") ||
	    ISARG("0"))
		*data = 0;
	else {
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

	struct mbconfig_imap_store *store = ctx->config->imap_stores;
	for (; store; store = store->next)
		if (!strcmp(ctx->buf, store->name))
			break;
	if (!store) {
		ctx->error_msg = "No such IMAPStore";
		return -1;
	}
	data->store = store;

	rc = get_str(ctx);
	if (rc < 0) {
		return rc;
	} else if (!rc) {
		data->mailbox = NULL;
		return 1;
	} else {
		return dup_arg(ctx, &data->mailbox);
	}

bad_format:
	ctx->error_msg = "Bad format";
	return -1;
}

static void
skip_unknown_cmd(struct mbconfig_parser *ctx)
{
	ctx->buf[ctx->col] = '\0';
}

static int
skip_unknown_section(struct mbconfig_parser *ctx)
{
	int rc;
	do
		skip_unknown_cmd(ctx);
	while (0 < (rc = get_cmd(ctx)));
	return rc;
}

static int
parse_imap_account_section(struct mbconfig_parser *ctx)
{
	struct mbconfig_imap_account *data = calloc(1, sizeof *data);
	if (!data) {
		ctx->error_msg = strerror(ENOMEM);
		return -1;
	}
	struct mbconfig_imap_account **head = &ctx->config->imap_accounts;
	data->next = *head;
	*head = data;

	data->system_certs = 1;
	data->login_auth = 1;
	data->ssl_versions = SSL_OP_NO_SSLv3;

	int rc = parse_str(ctx, &data->name);
	while (0 < rc && 0 < (rc = get_cmd(ctx)))
		if (ISARG("HOST"))
			rc = parse_str(ctx, &data->host);
		else if (ISARG("PORT"))
			rc = parse_str(ctx, &data->port);
		else if (ISARG("USER"))
			rc = parse_str(ctx, &data->user);
		else if (ISARG("USERCMD"))
			rc = parse_str(ctx, &data->user_cmd);
		else if (ISARG("PASS"))
			rc = parse_str(ctx, &data->pass);
		else if (ISARG("PASSCMD"))
			rc = parse_str(ctx, &data->pass_cmd);
		else if (ISARG("TUNNEL"))
			rc = parse_str(ctx, &data->tunnel_cmd);
		else if (ISARG("AUTHMECHS")) {
			data->login_auth = 0;
			while (0 < (rc = get_kw(ctx)))
				data->login_auth |= ISARG("*") || ISARG("LOGIN");
			if (0 <= rc)
				rc = 1;
		} else if (ISARG("SSLTYPE")) {
			if (!(rc = get_kw(ctx))) {
				continue;
			} else if (rc < 0)
				break;
			if (ISARG("NONE"))
				data->ssl = MBCONFIG_SSL_NONE;
			else if (ISARG("IMAPS"))
				data->ssl = MBCONFIG_SSL_IMAPS;
			else {
				ctx->error_msg = "Unknown argument";
				return -1;
			}
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

#define xmacro(name, op) \
	else if (ISARG(name)) \
		data->ssl_versions &= ~(op);
			while (0 < (rc = get_kw(ctx)))
				if (0) (void)0;
				ARGS
#undef xmacro
#undef ARGS
		} else if (ISARG("SYSTEMCERTIFICATES"))
			rc = parse_bool(ctx, &data->system_certs);
		else if (ISARG("CERTIFICATEFILE"))
			rc = parse_path(ctx, &data->cert_file);
		else if (ISARG("CIPHERSTRING"))
			rc = parse_str(ctx, &data->ciphers);
		else
			skip_unknown_cmd(ctx);

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
	struct mbconfig_imap_store *data = calloc(1, sizeof *data);
	if (!data) {
		ctx->error_msg = strerror(ENOMEM);
		return -1;
	}
	struct mbconfig_imap_store **head = &ctx->config->imap_stores;
	data->next = *head;
	*head = data;

	int rc = parse_str(ctx, &data->name);
	while (0 < rc && 0 < (rc = get_cmd(ctx)))
		if (ISARG("ACCOUNT")) {
			if ((rc = want_str(ctx)) <= 0)
				break;
			struct mbconfig_imap_account *account =
				ctx->config->imap_accounts;
			for (; account; account = account->next)
				if (!strcmp(ctx->buf, account->name))
					break;
			if (!account) {
				ctx->error_msg = "No such IMAPAccount";
				return -1;
			}
			data->account = account;
		} else
			skip_unknown_cmd(ctx);

	if (0 <= rc && !data->account) {
		ctx->error_msg = "Missing required Account";
		return -1;
	}

	return rc;
}

static int
parse_channel_section(struct mbconfig_parser *ctx)
{
	struct mbconfig_channel *data = calloc(1, sizeof *data);
	if (!data) {
		ctx->error_msg = strerror(ENOMEM);
		return -1;
	}
	struct mbconfig_channel **head = &ctx->config->channels;
	data->next = *head;
	*head = data;

	data->sync_pull = 1;

	int rc = parse_str(ctx, &data->name);
	while (0 < rc && 0 < (rc = get_cmd(ctx)))
		if (ISARG("FAR"))
			rc = parse_store(ctx, &data->far);
		else if (ISARG("SYNC")) {
			data->sync_pull = 0;
			while (0 < (rc = get_kw(ctx)))
				data->sync_pull |= ISARG("PULL");
		} else
			skip_unknown_cmd(ctx);

	if (0 <= rc && !data->far.store) {
		ctx->error_msg = "Missing required Far";
		return -1;
	}

	return rc;
}

int
mbconfig_parse(struct mbconfig_parser *ctx, char const *filename)
{
	struct mbconfig *config = ctx->config;
	memset(config, 0, sizeof *config);

	ctx->lnum = 0;

	config->filename = strdup(filename);
	if (!config->filename) {
		ctx->error_msg = strerror(ENOMEM);
		return -1;
	}

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
		if (ISARG("IMAPACCOUNT"))
			rc = parse_imap_account_section(ctx);
		else if (ISARG("IMAPSTORE"))
			rc = parse_imap_store_section(ctx);
		else if (ISARG("CHANNEL"))
			rc = parse_channel_section(ctx);
		else
			rc = skip_unknown_section(ctx);
	}

	fclose(ctx->stream);
	return rc;
}
