#ifndef MBIDLED_MBCONFIG_H
#define MBIDLED_MBCONFIG_H

#include <stdio.h>
#include <sys/queue.h>

struct mbconfig_imap_account {
	SLIST_ENTRY(mbconfig_imap_account) link;
	char *name;
	char *host;
	char *port;
	char *user;
	char *user_cmd;
	char *pass;
	char *pass_cmd;
	char *tunnel_cmd;
	int login_auth;
	char *auth_mech;
	enum {
		MBCONFIG_SSL_NONE,
		MBCONFIG_SSL_STARTTLS,
		MBCONFIG_SSL_IMAPS,
	} ssl;
	int ssl_versions;
	int system_certs;
	char *cert_file;
	char *ciphers;
};

struct mbconfig_imap_store {
	SLIST_ENTRY(mbconfig_imap_store) link;
	char *name;
	struct mbconfig_imap_account *account;
};

struct mbconfig_maildir_store {
	SLIST_ENTRY(mbconfig_maildir_store) link;
	char *name;
	char *path;
	char *inbox;
};

struct mbconfig_store {
	enum mbconfig_store_type {
		MBCONFIG_STORE_IMAP,
		MBCONFIG_STORE_MAILDIR,
	} type;
	union {
		void *store;
		struct mbconfig_imap_store *imap_store;
		struct mbconfig_maildir_store *maildir_store;
	};
	char *mailbox;
};

struct mbconfig_str {
	SLIST_ENTRY(mbconfig_str) link;
	char *str;
};

SLIST_HEAD(mbconfig_str_list, mbconfig_str);

struct mbconfig_mbidled_channel {
	int start_timeout;
	int start_interval;
	enum {
		MBCONFIG_PROPAGATE_FAR = 1 << 0,
		MBCONFIG_PROPAGATE_NEAR = 1 << 1,
	} strict_propagate;
};

struct mbconfig_channel {
	SLIST_ENTRY(mbconfig_channel) link;
	char *name;
	struct mbconfig_store far;
	struct mbconfig_store near;
	enum {
		MBCONFIG_SYNC_PULL = 1 << 0,
		MBCONFIG_SYNC_PUSH = 1 << 1,
	} sync;
	struct mbconfig_str_list patterns;
	struct mbconfig_mbidled_channel mbidled;
};

struct mbconfig {
	char *filename;
	SLIST_HEAD(, mbconfig_imap_account) imap_accounts;
	SLIST_HEAD(, mbconfig_imap_store) imap_stores;
	SLIST_HEAD(, mbconfig_maildir_store) maildir_stores;
	SLIST_HEAD(, mbconfig_channel) channels;
};

struct mbconfig_parser {
	FILE *stream;
	int lnum;
	char buf[1024];
	int col;
	char *arg;
	char const *error_msg;
	struct mbconfig *config;
	struct mbconfig_mbidled_channel channel_config[2];
};

int mbconfig_parse(struct mbconfig_parser *ctx, char const *filename);
int mbconfig_patterns_test(struct mbconfig_str_list const *patterns, char const *s);

#endif
