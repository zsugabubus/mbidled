#ifndef MBIDLED_MBCONFIG_H
#define MBIDLED_MBCONFIG_H

#include <stdio.h>

struct mbconfig_imap_account {
	struct mbconfig_imap_account *next;
	char *name;
	char *host;
	char *port;
	char *user;
	char *user_cmd;
	char *pass;
	char *pass_cmd;
	char *tunnel_cmd;
	int login_auth;
	enum mbconfig_ssl_type {
		MBCONFIG_SSL_NONE,
		MBCONFIG_SSL_IMAPS,
	} ssl;
	int ssl_versions;
	int system_certs;
	char *cert_file;
	char *ciphers;
};

struct mbconfig_imap_store {
	struct mbconfig_imap_store *next;
	char *name;
	struct mbconfig_imap_account *account;
};

struct mbconfig_store {
	struct mbconfig_imap_store *store;
	char *mailbox;
};

struct mbconfig_channel {
	struct mbconfig_channel *next;
	char *name;
	struct mbconfig_store far;
	int sync_pull;
};

struct mbconfig {
	char *filename;
	struct mbconfig_imap_account *imap_accounts;
	struct mbconfig_imap_store *imap_stores;
	struct mbconfig_channel *channels;
};

struct mbconfig_parser {
	FILE *stream;
	int lnum;
	char buf[1024];
	unsigned short argsz, col;
	char const *error_msg;
	struct mbconfig *config;
};

int mbconfig_parse(struct mbconfig_parser *ctx, char const *filename);

#endif
