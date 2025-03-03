#include <ev.h>
#include <openssl/ssl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>

#include "channel.h"
#include "mbconfig.h"
#include "mbidled.h"
#include "version.h"

static char const USAGE[] = "Usage: %s -c MBSYNC_CONFIG [-e COMMAND] [-v]\n"
			    "Run command on mailbox change.\n"
			    "\n"
			    "Try man mbidled(1) for more information.\n";

char const *opt_cmd = "mbsync -c \"$MBIDLED_CONFIG\" \"$MBIDLED_CHANNEL:$MBIDLED_MAILBOX\"";
int opt_verbose = 0;

void
mb_log(int level, char const *format, ...)
{
	if (!opt_verbose && level > LOG_INFO)
		return;

	(void)fprintf(stderr, "<%d>", level);

	va_list ap;
	va_start(ap, format);
	(void)vfprintf(stderr, format, ap);
	va_end(ap);

	(void)fputc('\n', stderr);
}

int
main(int argc, char *argv[])
{
	(void)SSL_library_init();
	SSL_load_error_strings();

	sigaction(
		SIGPIPE,
		&(struct sigaction const){
			.sa_flags = SA_RESTART,
			.sa_handler = SIG_IGN,
		},
		NULL
	);

	char const *config_path = NULL;

	for (int opt; 0 <= (opt = getopt(argc, argv, "c:e:d:D:vh"));) {
		switch (opt) {
		case 'c':
			config_path = optarg;
			break;

		case 'e':
			opt_cmd = optarg;
			break;

		case 'v':
			opt_verbose = 1;
			fprintf(stderr, VERSION "\n");
			break;

		case 'h':
			printf(USAGE, argv[0]);
			return EXIT_SUCCESS;

		default:
			return EXIT_FAILURE;
		}
	}

	if (config_path == NULL) {
		fprintf(stderr, "Missing -c\n");
		return EXIT_FAILURE;
	}

	struct mbconfig mb_config;
	struct mbconfig_parser mb_config_parser;
	mb_config_parser.config = &mb_config;
	if (mbconfig_parse(&mb_config_parser, config_path)) {
		mb_log(LOG_ALERT,
		       "%s:%d:%d: %s",
		       config_path,
		       mb_config_parser.lnum,
		       mb_config_parser.col,
		       mb_config_parser.error_msg);
		return EXIT_FAILURE;
	}

	struct ev_loop *loop = EV_DEFAULT;

	struct mbconfig_channel const *mb_chan;
	SLIST_FOREACH (mb_chan, &mb_config.channels, link)
		channel_open(EV_A_ & mb_config, mb_chan);

	ev_run(EV_A_ 0);
}
