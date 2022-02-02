project('mbidled', 'c',
	version: '0.0a',
	license: 'UNLICENSE',
	default_options: [
		'c_std=c99',
		'warning_level=2',
	],
)

add_project_arguments([
	'-D_GNU_SOURCE',
	'-DMBIDLED_VERSION="@0@ @1@"'.format(
		meson.project_name(),
		meson.project_version(),
	),
], language: 'c')

executable('mbidled',
	'mbidled.c',
	'imap.c',
	'mbconfig.c',
	dependencies: [
		dependency('openssl')
	],
	install: true,
)
install_man('mbidled.1')
