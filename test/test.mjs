import fs from 'node:fs/promises';
import os from 'node:os';
import { sep } from 'node:path';
import tls from 'node:tls';
import net from 'node:net';
import child_process from 'node:child_process';

const raw = String.raw;

const createIMAPServer = async ({
	isSecure = true,
	isStartTLSSupported = true,
	isLoginAllowed = true,
	isClearTextLoginAllowed = false,
	isIDLEAllowed = true,
	allowedAuths = [],
	onIdle,
} = {}) => {
	const secureContext = tls.createSecureContext({
		key: await fs.readFile('key.pem'),
		cert: await fs.readFile('cert.pem'),
	});

	const clients = [];

	const server = net.createServer(async (socket) => {
		const upgradeSocket = async () => {
			console.log('Upgrade client');

			const wrappedSocket = socket;

			socket = new tls.TLSSocket(wrappedSocket, {
				secureContext,
				isServer: true,
			});

			const securePromise = new Promise((resolve) => {
				socket.on('secure', () => {
					console.log('Client secured');
					resolve();
				});
			});
			await securePromise;

			socket.on('data', async (data) => {
				wrappedSocket.emit('data', data);
			});
		};

		if (isSecure) await upgradeSocket();

		const writeRawLine = async (S) => {
			console.log(`S: ${S}`);
			await socket.write(`${S}\r\n`);
		};
		const writeOK = (tag, msg = 'Completed.') =>
			writeRawLine(`${tag} OK ${msg}`);
		const writeERR = (tag, msg) => writeRawLine(`${tag} ERR ${msg}`);

		const session = {
			isLoggedIn: false,
			isIdle: false,
		};
		clients.push(session);

		const hasStartTLS = () =>
			!session.isLoggedIn && isStartTLSSupported && !socket.encrypted;
		const hasLogin = () =>
			!session.isLoggedIn &&
			isLoginAllowed &&
			(isClearTextLoginAllowed || socket.encrypted);
		const hasIdle = () => isIDLEAllowed;

		socket.on('data', async (data) => {
			const C = data.toString().trim();
			console.log(`C: ${C}`);

			const [_, tag, cmd, cmdArgs] = C.match(/^(\d+) ([A-Z]+) ?(.*)$/);
			if (cmd === 'CAPABILITY') {
				await writeRawLine(
					`* CAPABILITY ${[
						...(hasStartTLS() ? ['STARTTLS'] : []),
						...(hasLogin() ? [] : ['LOGINDISABLED']),
						...(hasIdle() ? ['IDLE'] : []),
						...allowedAuths.map((x) => `AUTH=${x}`),
					].join(' ')}`,
				);
				await writeOK(tag);
			} else if (cmd === 'STARTTLS') {
				if (hasStartTLS()) {
					await writeOK(tag, 'Begin TLS negotiation now.');
					await upgradeSocket();
				} else {
					await writeERR(tag, 'Unsupported');
				}
			} else if (cmd === 'LOGIN') {
				if (hasLogin()) {
					session.isLoggedIn = true;
					session.loginArgs = cmdArgs;
					await writeOK(tag, 'Welcome.');
				} else {
					await writeERR(tag, 'Unsupported');
				}
			} else if (cmd === 'AUTHENTICATE') {
				if (allowedAuths.length > 0) {
					session.isLoggedIn = true;
					session.authenticateArgs = cmdArgs;
					await writeOK(tag, 'Welcome.');
				} else {
					await writeERR(tag, 'Unsupported');
				}
			} else if (cmd === 'LIST') {
				await writeRawLine(
					raw`* LIST (\HasNoChildren \Marked \Trash) "." INBOX.Trash`,
				);
				await writeRawLine(raw`* LIST (\HasNoChildren) "." INBOX.Drafts`);
				await writeRawLine(raw`* LIST (\HasNoChildren) "." INBOX.Folder`);
				await writeOK(tag);
			} else if (cmd === 'EXAMINE') {
				session.examineArgs = cmdArgs;
				await writeOK(tag);
			} else if (cmd === 'IDLE') {
				session.isIdle = true;
				if (onIdle) {
					let i = 0;
					onIdle({
						notify: () => {
							console.log(
								'Send IDLE notification in folder: %o',
								session.examineArgs,
							);
							writeRawLine(`* ${++i} Unread`);
						},
					});
				}
			} else {
				await writeERR(tag, `Unknown command ${cmd}`);
			}
		});

		socket.on('close', function () {
			console.log('Connection closed');
		});

		socket.on('error', function (error) {
			console.error(error);
			socket.destroy();
		});

		await writeRawLine('* OK Ready.');
	});

	server.listen();

	const listeningPromise = new Promise((resolve) => {
		server.on('listening', () => resolve());
	});
	await listeningPromise;

	console.log('IMAP server listening on', server.address());

	return {
		port: server.address().port,
		host: '127.0.0.1',
		clients,
		close: () => {
			const closePromise = new Promise((resolve) => {
				server.on('close', () => resolve());
			});

			server.close();

			return closePromise;
		},
	};
};

const createMaildir = async ({
	maildirPath,
	folders = ['Folder'],
	onSetup,
}) => {
	await Promise.all(
		folders.flatMap((name) => [
			fs.mkdir(`${maildirPath}${name}${sep}new`, { recursive: true }),
			fs.mkdir(`${maildirPath}${name}${sep}cur`, { recursive: true }),
		]),
	);

	if (onSetup) {
		let i = 0;
		onSetup({
			notify: (folder) => {
				console.log('Deliver new message to folder: %o', folder);
				fs.writeFile(
					`${maildirPath}${folder}${sep}new${sep}message.${++i}`,
					'',
				);
			},
		});
	}
};

const createConfig = async ({
	imap,
	configOverride,
	maildirPath,
	configPath,
	tlsType = 'IMAPS',
	withCertificateFile = true,
	authMech = 'LOGIN',
	userCmd,
	passCmd,
	patterns = '% !Trash !Drafts',
}) => {
	const sections = configOverride ?? [
		['#MBIDLED:StartTimeout 1', '#MBIDLED:StartInterval 2'],
		[
			'IMAPAccount test',
			`Host ${imap.host}`,
			`Port ${imap.port}`,
			`AuthMechs ${authMech}`,
			`TLSType ${tlsType}`,
			userCmd ? `UserCmd ${userCmd}` : 'User username',
			passCmd ? `PassCmd ${passCmd}` : 'Pass password',
			...(withCertificateFile
				? ['SystemCertificates No', 'CertificateFile ./cert.pem']
				: []),
		],
		['IMAPStore test-remote', 'Account test'],
		[
			'MaildirStore test-local',
			`Path ${maildirPath}`,
			`Inbox ${maildirPath}/inbox`,
		],
		[
			'Channel test',
			'Far :test-remote:',
			'Near :test-local:',
			`Patterns ${patterns}`,
		],
	];
	const config = sections.map((x) => x.join('\n')).join('\n\n');
	await fs.writeFile(configPath, config);
};

const createMBIDLEDProcess = async ({ configPath, timeout = 500 } = {}) => {
	let output = '';

	const handleOutput = (data) => {
		const chunk = data.toString();
		output += chunk;
		chunk
			.trim()
			.split('\n')
			.forEach((line) => {
				console.log(`[MBIDLED] ${line}`);
			});
	};

	const subprocess = child_process.spawn(
		'mbidled',
		[
			'-v',
			'-e',
			'echo "$MBIDLED_CONFIG:$MBIDLED_CHANNEL:$MBIDLED_MAILBOX"',
			'-c',
			configPath,
		],
		{
			stdio: ['ignore', 'pipe', 'pipe'],
		},
	);
	subprocess.stderr.on('data', handleOutput);
	subprocess.stdout.on('data', handleOutput);

	setTimeout(() => {
		subprocess.kill('SIGKILL');
	}, timeout);

	const exitPromise = new Promise((resolve) => {
		subprocess.on('exit', () => resolve());
	});

	const getExecutedCommands = () => {
		const result = [];
		output.replace(/\+ echo (.*)/g, (_, calledWith) => result.push(calledWith));
		return result;
	};

	const getOutput = () => output;

	return {
		exitPromise,
		getExecutedCommands,
		getOutput,
	};
};

export const runScenario = async ({
	imap: imapOptions,
	mbidled: mbidledOptions,
	config: configOptions,
	maildir: maildirOptions,
}) => {
	const tmpPrefix = `${os.tmpdir()}${sep}mbidled-`;
	const tmpdir = await fs.mkdtemp(tmpPrefix);

	const configPath = `${tmpdir}${sep}config`;
	const maildirPath = `${tmpdir}${sep}`;
	console.log({ configPath, maildirPath });

	try {
		const imap = await createIMAPServer(imapOptions);

		await createMaildir({
			...maildirOptions,
			maildirPath,
		});

		await createConfig({
			...configOptions,
			configPath,
			maildirPath,
			imap,
		});

		const mbidled = await createMBIDLEDProcess({
			...mbidledOptions,
			configPath,
		});

		await mbidled.exitPromise;

		await imap.close();

		return {
			configPath,
			expect: {
				outputToContain: (searchString) => {
					assert(mbidled.getOutput().includes(searchString));
				},
				outputToMatch: (regExp) => {
					assert(mbidled.getOutput().match(regExp));
				},
				executedCommandsToBe: (listOfCommands) => {
					const actual = mbidled.getExecutedCommands();
					actual.sort();
					const expected = listOfCommands;
					console.log('Expected', expected);
					console.log('Actual', actual);
					assert(JSON.stringify(actual) == JSON.stringify(expected));
				},
				noClients: () => {
					console.log(imap.clients);
					assert(imap.clients.length === 0);
				},
				clientsToFailToLogin: () => {
					console.log(imap.clients);
					assert(imap.clients.length > 0);
					for (const client of imap.clients) {
						assert(!client.isLoggedIn);
					}
				},
				clientsToBeIdle: () => {
					console.log(imap.clients);
					assert(imap.clients.length > 0);
					for (const client of imap.clients) {
						assert(client.isIdle);
					}
				},
				clientsToBeLoggedInWith: (loginArgs) => {
					console.log(imap.clients);
					assert(imap.clients.length > 0);
					for (const client of imap.clients) {
						assert(client.isLoggedIn);
						assert(client.loginArgs === loginArgs);
					}
				},
				clientsToBeAuthenticatedWith: (authenticateArgs) => {
					console.log(imap.clients);
					assert(imap.clients.length > 0);
					for (const client of imap.clients) {
						assert(client.isLoggedIn);
						assert(client.authenticateArgs === authenticateArgs);
					}
				},
				examinedIMAPFoldersToBe: (listOfExamineArgs) => {
					console.log(imap.clients);
					assert(imap.clients.length > 0);
					const actual = imap.clients.map((client) => client.examineArgs);
					actual.sort();
					const expected = listOfExamineArgs;
					console.log('Expected', expected);
					console.log('Actual', actual);
					assert(JSON.stringify(actual) == JSON.stringify(expected));
				},
			},
		};
	} finally {
		fs.rm(tmpdir, {
			recursive: true,
		});
	}
};

const assert = (condition) => {
	if (!condition) {
		throw new Error('Assertion failed');
	}
	console.log('Assertion OK');
};

const tests = [];

export const test = (name, fn) => {
	fn.testName = name;
	tests.push(fn);
};

export const runTests = async () => {
	const filterRegExp = new RegExp(process.argv[2] ?? '', 'i');
	const filteredTests = tests.filter((fn) => fn.testName.match(filterRegExp));

	console.log(
		'Pattern %o matches %o tests',
		filterRegExp.toString(),
		filteredTests.length,
	);

	for (const fn of filteredTests) {
		console.log();
		console.log('='.repeat(50));
		console.log('Test %o...', fn.testName);
		console.log('='.repeat(50));
		console.log();
		await fn();
	}
};
