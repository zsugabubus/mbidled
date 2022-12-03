#include <assert.h>
#include <ev.h>
#include <openssl/ssl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "channel.h"
#include "mbidled.h"
#include "mbconfig.h"
#include "version.h"

static char const USAGE[] =
	"Usage: %s -c MBSYNC_CONFIG [-e COMMAND] [-v]\n"
	"Run command on mailbox change.\n"
	"\n"
	"Try man mbidled(1) for more information.\n";

char const *opt_cmd =
	"mbsync -c \"$MBIDLED_CONFIG\" \"$MBIDLED_CHANNEL:$MBIDLED_MAILBOX\"";
int opt_verbose = 0;

void
print_log(int priority, char const *message)
{
	if (!opt_verbose && priority > LOG_NOTICE)
		return;
	(void)fprintf(stderr, "<%d>%s\n", priority, message);
}

int
main(int argc, char *argv[])
{
	(void)SSL_library_init();
	SSL_load_error_strings();

	sigaction(SIGPIPE, &(struct sigaction const){
		.sa_flags = SA_RESTART,
		.sa_handler = SIG_IGN,
	}, NULL);

	char const *opt_config = NULL;

	for (int opt; 0 <= (opt = getopt(argc, argv, "c:e:d:D:vh"));) {
		switch (opt) {
		case 'c':
			opt_config = optarg;
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

	char path_xdg[PATH_MAX], path_legacy[PATH_MAX];
	if (!opt_config) {
		char const *config_home = getenv("XDG_CONFIG_HOME");
		char const *home = getenv("HOME");
		ASSERT(home);

		if (config_home)
			ASSERT_SNPRINTF(path_xdg, "%s/isyncrc", config_home);
		else
			ASSERT_SNPRINTF(path_xdg, "%s/.config/isyncrc", home);

		ASSERT_SNPRINTF(path_legacy, "%s/.mbsyncrc", home);

		struct stat st;
		int xdg = !lstat(path_xdg, &st);
		int legacy = !lstat(path_legacy, &st);
		if (!xdg && legacy) {
			opt_config = path_legacy;
		} else if (xdg && legacy) {
			fprintf(stderr, "Using configuration file %s instead of legacy %s.\n",
					path_xdg, path_legacy);
			opt_config = path_xdg;
		} else {
			opt_config = path_xdg;
		}
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
		fprintf(stderr, "Could not parse configuration file.\n");
		return EXIT_FAILURE;
	}

	struct ev_loop *loop = EV_DEFAULT;

	struct mbconfig_channel *mb_chan;
	SLIST_FOREACH(mb_chan, &mb_config.channels, link)
		channel_open(EV_A_ &mb_config, mb_chan);

	ev_run(EV_A_ 0);
}
