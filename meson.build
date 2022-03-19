project('mbidled', 'c',
	license: 'UNLICENSE',
	default_options: [
		'c_std=c99',
		'warning_level=2',
	],
)

add_project_arguments([
	'-D_GNU_SOURCE',
], language: 'c')

executable('mbidled',
	'mbidled.c',
	'imap.c',
	'mbconfig.c',
	vcs_tag(
		command: [
			'git',
			'log',
			'-1',
			'--date=short',
			'--format=%t %cd',
		],
		input: 'version.h.in',
		output: 'version.h',
	),
	dependencies: [
		dependency('openssl')
	],
	install: true,
)
install_man('mbidled.1')
