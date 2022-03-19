/* IMAP4 toy implementation. */
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <string.h>

#include "imap.h"

void
imap_init(struct imap *imap)
{
	imap->bio = NULL;
}

void
imap_open(struct imap *imap, BIO *bio)
{
	imap->bio = bio;

	imap->seq_num = 0;
	imap->wrhead = 0;
	imap->wrtail = 0;
	imap_write_cancel(imap);

	imap->head = 0;
	imap->tail = 0;
}

void
imap_close(struct imap *imap)
{
	if (imap->bio) {
		BIO_free_all(imap->bio);
		imap->bio = NULL;
	}
}

int
imap_get_events(struct imap const *imap)
{
	return (imap->wrhead != imap->wrtail ? POLLOUT : 0) | POLLIN;
}

int
imap_readline(struct imap *imap, char **line)
{
	struct imap *i = imap;

	char *line_end = memchr(i->rdbuf + i->head, '\n', i->tail - i->head);
	if (!line_end) do {
		size_t size = sizeof i->rdbuf;
		if (size == i->tail && i->head) {
			memmove(i->rdbuf, i->rdbuf + i->head, i->tail - i->head);
			i->tail -= i->head;
			i->head = 0;
		} else if (size == i->tail) {
			return -ENOSPC;
		}

		char *buf = i->rdbuf + i->tail;
		size_t len = size - i->tail;
		size_t got;
		if (1 != BIO_read_ex(i->bio, buf, len, &got))
			return BIO_should_retry(i->bio) ? -EAGAIN : -EIO;
		line_end = memchr(i->rdbuf + i->tail, '\n', got);
		i->tail += got;
	} while (!line_end);

	unsigned short len = line_end + 1 - (i->rdbuf + i->head);
	if (len < 2)
		return -EINVAL;

	*line = i->rdbuf + i->head;
	i->head += len;
	len -= 2;
	/* *linesz = len; */

	line_end[-1] = '\0';

	return 0;
}

void
imap_write_cancel(struct imap *imap)
{
	imap->wrptr = imap->wrtail;
	imap->wrrc = 0;
}

int
imap_write_commit(struct imap *imap)
{
	int rc = imap->wrrc;
	if (0 <= rc)
		imap->wrtail = imap->wrptr;
	else
		imap_write_cancel(imap);
	return rc;
}

int
imap_write_flush(struct imap *imap)
{
	char const *buf = imap->wrbuf + imap->wrhead;
	size_t len = imap->wrtail - imap->wrhead;
	if (!len)
		return 0;

	size_t written;
	if (1 != BIO_write_ex(imap->bio, buf, len, &written))
		return BIO_should_retry(imap->bio) ? -EAGAIN : -EIO;

	imap->wrhead += written;

	memmove(imap->wrbuf, imap->wrbuf + imap->wrhead, imap->wrptr - imap->wrhead);
	imap->wrtail -= imap->wrhead;
	imap->wrptr -= imap->wrhead;
	imap->wrhead = 0;

	return 0;
}

void
imap_write_tag(struct imap *imap)
{
	size_t rem = sizeof imap->wrbuf - imap->wrptr;
	size_t len = snprintf(imap->wrbuf + imap->wrptr, rem,
			"A%03" PRIu32, imap->seq_num);
	if (len < rem)
		imap->wrptr += len;
	else
		imap->wrrc = -ENOSPC;
}

void
imap_write_rawnstr(struct imap *imap, char const *s, size_t n)
{
	size_t rem = sizeof imap->wrbuf - imap->wrptr;
	if (n <= rem) {
		memcpy(imap->wrbuf + imap->wrptr, s, n);
		imap->wrptr += n;
	} else {
		imap->wrrc = -ENOSPC;
	}
}

void
imap_write_rawstr(struct imap *imap, char const *s)
{
	imap_write_rawnstr(imap, s, strlen(s));
}

void
imap_write_str(struct imap *imap, char const *s)
{
	char *wrbuf = imap->wrbuf;
	size_t size = sizeof imap->wrbuf;
	size_t ptr = imap->wrptr;

	for (; *s; ++s) {
		if (size - 2 /* \ X OR X CR */ <= ptr) {
			imap->wrrc = -ENOSPC;
			return;
		}

		if ('"' == *s || '\\' == *s)
			wrbuf[ptr++] = '\\';
		wrbuf[ptr++] = *s;
	}

	imap->wrptr = ptr;
}

void
imap_write_cmd_begin(struct imap *imap)
{
	++imap->seq_num;
	imap_write_tag(imap);
	imap_write_rawnstr(imap, " ", 1);
}

int
imap_write_cmd_end(struct imap *imap)
{
	imap_write_rawnstr(imap, "\r\n", 2);
	return imap_write_commit(imap);
}

int
imap_logout(struct imap *imap)
{
	imap_write_cmd_begin(imap);
	imap_write_rawstr(imap, "LOGOUT");
	return imap_write_cmd_end(imap);

	/* BIO_shutdown_wr(imap->bio); */
}

int
imap_write_vcmdf(struct imap *imap, char const *fmt, va_list ap)
{
	imap_write_cmd_begin(imap);

	for (char const *from = fmt;;) {
		char const *to = strchr(from, '%');
		if (!to)
			to = from + strlen(from);
		int n = (int)(to - from);

		imap_write_rawnstr(imap, from, n);

		if (!*to)
			break;

		char const *arg = va_arg(ap, char *);

		switch (to[1]) {
		case 's':
			imap_write_rawstr(imap, arg);
			break;

		case 'q':
			imap_write_str(imap, arg);
			break;

		default:
			abort();
		}

		from = to + 2;
	}

	return imap_write_cmd_end(imap);
}

int
imap_write_cmdf(struct imap *imap, char const *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int rc = imap_write_vcmdf(imap, fmt, ap);
	va_end(ap);
	return rc;
}
