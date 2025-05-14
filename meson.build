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

mbidled_exe = executable('mbidled',
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

test(
	'e2e',
	find_program('make'),
	workdir: meson.project_source_root(),
	env: [
		'MBIDLED_PATH=' + meson.project_build_root()
	],
	depends: mbidled_exe,
	args: ['check'],
	timeout: 60,
)

test(
	'lint',
	find_program('make'),
	workdir: meson.project_source_root(),
	args: ['lint'],
)
