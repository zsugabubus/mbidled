#ifndef MBIDLED_IMAP_H
#define MBIDLED_IMAP_H

#include <openssl/bio.h>

struct mbconfig_imap_account;

struct imap {
	BIO *bio;
	uint32_t seq_num;

	/* wr */
	unsigned short wrhead;
	unsigned short wrtail;
	unsigned short wrptr;
	int wrrc;

	/* rd */
	unsigned short head;
	unsigned short tail;

	char wrbuf[1000];
	char rdbuf[1000];
};

void imap_init(struct imap *imap);
void imap_open(struct imap *imap, BIO *bio);
void imap_close(struct imap *imap);
int imap_get_events(struct imap const *imap);
int imap_readline(struct imap *imap, char **line);
void imap_write_cancel(struct imap *imap);
int imap_write_commit(struct imap *imap);
int imap_write_flush(struct imap *imap);
void imap_write_tag(struct imap *imap);
void imap_write_rawnstr(struct imap *imap, char const *s, size_t n);
void imap_write_rawstr(struct imap *imap, char const *s);
void imap_write_str(struct imap *imap, char const *s);
void imap_write_cmd_begin(struct imap *imap);
int imap_write_cmd_end(struct imap *imap);
int imap_logout(struct imap *imap);
int imap_write_vcmdf(struct imap *imap, char const *fmt, va_list ap);
int imap_write_cmdf(struct imap *imap, char const *fmt, ...);

#endif
