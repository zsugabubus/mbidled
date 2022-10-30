project('mbidled', 'c',
	license: 'UNLICENSE',
	default_options: [
		'c_std=c11',
		'warning_level=3',
	],
)

add_project_arguments([
	'-D_GNU_SOURCE',
], language: 'c')

cc = meson.get_compiler('c')

libev_dep = dependency('libev', required: false)
if not libev_dep.found()
	libev_dep = cc.find_library('libev')
endif

executable('mbidled',
	'mbidled.c',
	'channel.c',
	'imap.c',
	'maildir.c',
	'mbconfig.c',
	vcs_tag(
		command: [
			'git',
			'log',
			'-1',
			'--date=short',
			'--format=%h %cd',
		],
		input: 'version.h.in',
		output: 'version.h',
	),
	dependencies: [
		dependency('openssl'),
		libev_dep,
	],
	install: true,
)
install_man('mbidled.1')
