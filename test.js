import fs from "node:fs/promises";
import os from "node:os";
import tls from "node:tls";
import net from "node:net";
import assert from "node:assert/strict";
import child_process from "node:child_process";
import { test } from "node:test";

const getOptions = (options, defaults) =>
	Object.assign(Object.seal(defaults), options);

const createIMAPServer = async (options) => {
	options = getOptions(options, {
		isSecure: true,
		isStartTLSSupported: true,
		isLoginAllowed: true,
		isClearTextLoginAllowed: false,
		isIDLEAllowed: true,
		allowedAuths: [],
		onIdle: undefined,
	});

	const secureContext = tls.createSecureContext({
		key: await fs.readFile("key.pem"),
		cert: await fs.readFile("cert.pem"),
	});

	const clients = [];

	const server = net.createServer(async (socket) => {
		const upgradeSocket = async () => {
			console.log("Upgrade client");

			const wrappedSocket = socket;

			socket = new tls.TLSSocket(wrappedSocket, {
				secureContext,
				isServer: true,
			});

			const securePromise = new Promise((resolve) => {
				socket.on("secure", () => {
					console.log("Client secured");
					resolve();
				});
			});
			await securePromise;

			socket.on("data", async (data) => {
				wrappedSocket.emit("data", data);
			});
		};

		if (options.isSecure) await upgradeSocket();

		const writeRawLine = async (S) => {
			console.log(`S: ${S}`);
			await socket.write(`${S}\r\n`);
		};
		const writeOK = (tag, msg = "Completed.") =>
			writeRawLine(`${tag} OK ${msg}`);
		const writeERR = (tag, msg) => writeRawLine(`${tag} ERR ${msg}`);

		const session = {
			isLoggedIn: false,
			isIdle: false,
		};
		clients.push(session);

		const hasStartTLS = () =>
			!session.isLoggedIn && options.isStartTLSSupported && !socket.encrypted;
		const hasLogin = () =>
			!session.isLoggedIn &&
			options.isLoginAllowed &&
			(options.isClearTextLoginAllowed || socket.encrypted);
		const hasIdle = () => options.isIDLEAllowed;

		socket.on("data", async (data) => {
			const C = data.toString().trim();
			console.log(`C: ${C}`);

			const [_, tag, cmd, cmdArgs] = C.match(/^(\d+) ([A-Z]+) ?(.*)$/);
			if (cmd === "CAPABILITY") {
				await writeRawLine(
					`* CAPABILITY ${[
						...(hasStartTLS() ? ["STARTTLS"] : []),
						...(hasLogin() ? [] : ["LOGINDISABLED"]),
						...(hasIdle() ? ["IDLE"] : []),
						...options.allowedAuths.map((x) => `AUTH=${x}`),
					].join(" ")}`,
				);
				await writeOK(tag);
			} else if (cmd === "STARTTLS") {
				if (hasStartTLS()) {
					await writeOK(tag, "Begin TLS negotiation now.");
					await upgradeSocket();
				} else {
					await writeERR(tag, "Unsupported");
				}
			} else if (cmd === "LOGIN") {
				if (hasLogin()) {
					session.isLoggedIn = true;
					session.loginArgs = cmdArgs;
					await writeOK(tag, "Welcome.");
				} else {
					await writeERR(tag, "Unsupported");
				}
			} else if (cmd === "AUTHENTICATE") {
				if (options.allowedAuths.length > 0) {
					session.isLoggedIn = true;
					session.authenticateArgs = cmdArgs;
					await writeOK(tag, "Welcome.");
				} else {
					await writeERR(tag, "Unsupported");
				}
			} else if (cmd === "LIST") {
				await writeRawLine(
					`* LIST (\\HasNoChildren \\Marked \\Trash) "." INBOX.Trash`,
				);
				await writeRawLine(`* LIST (\\HasNoChildren) "." INBOX.Drafts`);
				await writeRawLine(`* LIST (\\HasNoChildren) "." INBOX.Folder`);
				await writeOK(tag);
			} else if (cmd === "EXAMINE") {
				session.examineArgs = cmdArgs;
				await writeOK(tag);
			} else if (cmd === "IDLE") {
				session.isIdle = true;
				if (options.onIdle) {
					let i = 0;
					options.onIdle({
						notify: () => {
							console.log(
								"Send IDLE notification in folder: %o",
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

		socket.on("close", function () {
			console.log("Connection closed");
		});

		socket.on("error", function (error) {
			console.error(error);
			socket.destroy();
		});

		await writeRawLine("* OK Ready.");
	});

	const close = () =>
		new Promise((resolve) => {
			server.close(resolve);
		});

	await new Promise((resolve) => {
		server.listen({ port: 0 }, resolve);
	});

	console.log("IMAP server listening on", server.address());

	return {
		port: server.address().port,
		host: "127.0.0.1",
		clients,
		close,
	};
};

const createMaildir = async (options) => {
	options = getOptions(options, {
		maildirPath: undefined,
		folders: ["Folder"],
		onSetup: undefined,
	});

	await Promise.all(
		options.folders.flatMap((name) => [
			fs.mkdir(`${options.maildirPath}${name}/new`, { recursive: true }),
			fs.mkdir(`${options.maildirPath}${name}/cur`, { recursive: true }),
		]),
	);

	if (options.onSetup) {
		let i = 0;
		options.onSetup({
			notify: (folder) => {
				console.log("Deliver new message to folder: %o", folder);
				fs.writeFile(`${options.maildirPath}${folder}/new/message.${++i}`, "");
			},
		});
	}
};

const createConfig = async (options) => {
	options = getOptions(options, {
		imap: undefined,
		configOverride: undefined,
		maildirPath: undefined,
		configPath: undefined,
		tlsType: "IMAPS",
		withCertificateFile: true,
		authMech: "LOGIN",
		userCmd: undefined,
		passCmd: undefined,
		patterns: "% !Trash !Drafts",
	});

	const sections = options.configOverride ?? [
		["#MBIDLED:StartTimeout 1", "#MBIDLED:StartInterval 2"],
		[
			"IMAPAccount test",
			`Host ${options.imap.host}`,
			`Port ${options.imap.port}`,
			`AuthMechs ${options.authMech}`,
			`TLSType ${options.tlsType}`,
			options.userCmd ? `UserCmd ${options.userCmd}` : "User username",
			options.passCmd ? `PassCmd ${options.passCmd}` : "Pass password",
			...(options.withCertificateFile
				? ["SystemCertificates No", "CertificateFile ./cert.pem"]
				: []),
		],
		["IMAPStore test-remote", "Account test"],
		[
			"MaildirStore test-local",
			`Path ${options.maildirPath}`,
			`Inbox ${options.maildirPath}/inbox`,
		],
		[
			"Channel test",
			"Far :test-remote:",
			"Near :test-local:",
			`Patterns ${options.patterns}`,
		],
	];
	const config = sections.map((x) => x.join("\n")).join("\n\n");
	await fs.writeFile(options.configPath, config);
};

const createMBIDLEDProcess = async (options) => {
	options = getOptions(options, {
		configPath: undefined,
		timeout: 500,
	});

	let output = "";

	const handleOutput = (data) => {
		const chunk = data.toString();
		output += chunk;
		chunk
			.trim()
			.split("\n")
			.forEach((line) => {
				console.log(`[MBIDLED] ${line}`);
			});
	};

	const subprocess = child_process.spawn(
		"mbidled",
		[
			"-v",
			"-e",
			'echo "$MBIDLED_CONFIG:$MBIDLED_CHANNEL:$MBIDLED_MAILBOX"',
			"-c",
			options.configPath,
		],
		{
			stdio: ["ignore", "pipe", "pipe"],
			killSignal: "SIGKILL",
			timeout: options.timeout,
		},
	);
	subprocess.stderr.on("data", handleOutput);
	subprocess.stdout.on("data", handleOutput);

	const exitPromise = new Promise((resolve) => {
		subprocess.on("exit", resolve);
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

export const setupWorld = async (options) => {
	options = getOptions(options, {
		imap: {},
		mbidled: {},
		config: {},
		maildir: {},
	});

	const tmpPrefix = `${os.tmpdir()}/mbidled-`;
	const tmpdir = await fs.mkdtemp(tmpPrefix);

	const configPath = `${tmpdir}/config`;
	const maildirPath = `${tmpdir}/`;
	console.log({ configPath, maildirPath });

	try {
		const imap = await createIMAPServer(options.imap);

		await createMaildir({
			...options.maildir,
			maildirPath,
		});

		await createConfig({
			...options.config,
			configPath,
			maildirPath,
			imap,
		});

		const mbidled = await createMBIDLEDProcess({
			...options.mbidled,
			configPath,
		});

		await mbidled.exitPromise;

		await imap.close();

		// Workaround for a Node bug?
		const assertArrayPartialDeepStrictEqual = (actual, expected) => {
			const toObject = (x) => Object.fromEntries(Object.entries(x));
			assert.partialDeepStrictEqual(toObject(actual), toObject(expected));
		};

		return {
			configPath,
			expect: {
				outputToMatch: (regexp) => {
					assert.match(mbidled.getOutput(), regexp);
				},
				executedCommandsToBe: (listOfCommands) => {
					assert.deepStrictEqual(
						mbidled.getExecutedCommands().sort(),
						listOfCommands,
					);
				},
				noClients: () => {
					assert.deepStrictEqual(imap.clients, []);
				},
				clientsToFailToLogin: () => {
					assert.notDeepStrictEqual(imap.clients, []);
					assertArrayPartialDeepStrictEqual(
						imap.clients,
						imap.clients.map(() => ({ isLoggedIn: false })),
					);
				},
				clientsToBeIdle: () => {
					assert.notDeepStrictEqual(imap.clients, []);
					assertArrayPartialDeepStrictEqual(
						imap.clients,
						imap.clients.map(() => ({ isIdle: true })),
					);
				},
				clientsToBeLoggedInWith: (loginArgs) => {
					assert.notDeepStrictEqual(imap.clients, []);
					assertArrayPartialDeepStrictEqual(
						imap.clients,
						imap.clients.map(() => ({ isLoggedIn: true })),
					);
					for (const client of imap.clients) {
						assert.deepStrictEqual(client.loginArgs, loginArgs);
					}
				},
				clientsToBeAuthenticatedWith: (authenticateArgs) => {
					assert.notDeepStrictEqual(imap.clients, []);
					assertArrayPartialDeepStrictEqual(
						imap.clients,
						imap.clients.map(() => ({ isLoggedIn: true })),
					);
					for (const client of imap.clients) {
						assert.deepStrictEqual(client.authenticateArgs, authenticateArgs);
					}
				},
				examinedIMAPFoldersToBe: (listOfExamineArgs) => {
					assert.notDeepStrictEqual(imap.clients, []);
					assert.deepStrictEqual(
						imap.clients.map((client) => client.examineArgs).sort(),
						listOfExamineArgs,
					);
				},
			},
		};
	} finally {
		await fs.rm(tmpdir, { recursive: true });
	}
};

const selfTestThrows = (fn) => {
	assert.throws(fn, assert.AssertionError);
};

const OAUTHBEARER = "OAUTHBEARER";
const cmdFailsWithOutput = '"echo stdout; echo stderr >&2; false"';
const cmdSucceedsWithoutOutput = '"echo stderr >&2"';

test("self-test", async () => {
	try {
		selfTestThrows(() => {});
		assert.fail();
	} catch {}
});

test("tilde expansion with non-existent user", async () => {
	const { expect } = await setupWorld({
		config: {
			configOverride: [
				[
					"MaildirStore test",
					"Path ~",
					"Path ~/path",
					"Path ~nonexistentuser/path",
				],
			],
		},
	});
	expect.outputToMatch(/\/config:4:26: Unknown user/);
	expect.noClients();
	selfTestThrows(() => expect.outputToMatch(/FOO/));
	selfTestThrows(() => expect.clientsToFailToLogin());
	selfTestThrows(() => expect.clientsToBeLoggedInWith("FOO"));
});

test.only("invalid certificate", async () => {
	const { expect } = await setupWorld({
		config: {
			withCertificateFile: false,
		},
	});
	expect.outputToMatch(
		/Certificate verification failed: self-signed certificate/,
	);
	expect.clientsToFailToLogin();
	selfTestThrows(() => expect.noClients());
});

test("LOGINDISABLED capability", async () => {
	const { expect } = await setupWorld({
		imap: {
			isLoginAllowed: false,
		},
	});
	expect.outputToMatch(/LOGIN disabled by the server/);
	expect.clientsToFailToLogin();
});

test("no matching AUTH= capability but LOGIN allowed by the user", async () => {
	const { expect } = await setupWorld({
		imap: {
			allowedAuths: ["A", "ABC"],
		},
		config: {
			authMech: "LOGIN AB",
		},
	});
	expect.clientsToBeLoggedInWith('"username" "password"');
	expect.clientsToBeIdle();
	selfTestThrows(() => expect.noClients());
	selfTestThrows(() => expect.clientsToFailToLogin());
	selfTestThrows(() => expect.clientsToBeLoggedInWith("FOO"));
});

test("has matching AUTH= capability while LOGIN also allowed by the user", async () => {
	const { expect } = await setupWorld({
		imap: {
			allowedAuths: ["AB"],
		},
		config: {
			authMech: "LOGIN AB",
		},
	});
	expect.clientsToBeAuthenticatedWith("AB password");
	expect.clientsToBeIdle();
	selfTestThrows(() => expect.clientsToBeAuthenticatedWith("FOO"));
});

test("AUTH=LOGIN capability", async () => {
	const { expect } = await setupWorld({
		imap: {
			allowedAuths: ["LOGIN"],
		},
		config: {
			authMech: "LOGIN",
		},
	});
	expect.clientsToBeLoggedInWith('"username" "password"');
	expect.clientsToBeIdle();
});

test("no IDLE capability", async () => {
	const { expect } = await setupWorld({
		imap: {
			isIDLEAllowed: false,
		},
	});
	expect.outputToMatch(/IDLE not supported/);
	expect.clientsToFailToLogin();
});

test("LOGIN with User and Pass", async () => {
	const { expect } = await setupWorld({});
	expect.clientsToBeLoggedInWith('"username" "password"');
	expect.clientsToBeIdle();
});

test("LOGIN with UserCmd and PassCmd", async () => {
	const { expect } = await setupWorld({
		config: {
			userCmd: '"echo secretusername"',
			passCmd: '"echo secretpassword"',
		},
	});
	expect.clientsToBeLoggedInWith('"secretusername" "secretpassword"');
	expect.clientsToBeIdle();
});

for (const [configKey, optionName, errorMessage] of [
	["passCmd", "PassCmd", /No password/],
	["userCmd", "UserCmd", /No username/],
]) {
	test(`${optionName} produces output but fails`, async () => {
		const { expect } = await setupWorld({
			config: {
				[configKey]: cmdFailsWithOutput,
			},
		});
		expect.outputToMatch(new RegExp(`${optionName} failed`));
		expect.outputToMatch(errorMessage);
		expect.clientsToFailToLogin();
	});

	test(`${optionName} succeeds without producing any data on stdout`, async () => {
		const { expect } = await setupWorld({
			config: {
				[configKey]: cmdSucceedsWithoutOutput,
			},
		});
		expect.outputToMatch(new RegExp(`${optionName} produced no output`));
		expect.outputToMatch(errorMessage);
		expect.clientsToFailToLogin();
	});
}

test("PassCmd and UserCmd are always re-evaluated", async () => {
	const { expect } = await setupWorld({
		config: {
			userCmd: '"echo stderr of userCmd >&2; echo secretusername"',
			passCmd: '"echo stderr of passCmd >&2; echo secretpassword"',
			patterns: "%",
		},
	});
	expect.outputToMatch(/(.*^stderr of userCmd$){4}/ms);
	expect.outputToMatch(/(.*^stderr of passCmd$){4}/ms);
	expect.clientsToBeLoggedInWith('"secretusername" "secretpassword"');
	expect.clientsToBeIdle();
});

test("PassCmd fails to generate AUTHENTICATE data", async () => {
	const { expect } = await setupWorld({
		imap: {
			allowedAuths: [OAUTHBEARER],
		},
		config: {
			authMech: OAUTHBEARER,
			passCmd: cmdFailsWithOutput,
		},
	});
	expect.outputToMatch(/PassCmd failed/);
	expect.outputToMatch(/No authdata/);
	expect.clientsToFailToLogin();
});

test("PassCmd generates empty AUTHENTICATE data", async () => {
	const { expect } = await setupWorld({
		imap: {
			allowedAuths: [OAUTHBEARER],
		},
		config: {
			authMech: OAUTHBEARER,
			passCmd: cmdSucceedsWithoutOutput,
		},
	});
	expect.outputToMatch(/PassCmd produced no output/);
	expect.outputToMatch(/No authdata/);
	expect.clientsToFailToLogin();
});

test("PassCmd generates AUTHENTICATE data without new lines", async () => {
	const { expect } = await setupWorld({
		imap: {
			allowedAuths: [OAUTHBEARER],
		},
		config: {
			authMech: OAUTHBEARER,
			passCmd: '"echo -n no new line"',
		},
	});
	expect.clientsToBeAuthenticatedWith(`${OAUTHBEARER} no new line`);
});

test("PassCmd generates multiple lines for AUTHENTICATE data", async () => {
	const { expect } = await setupWorld({
		imap: {
			allowedAuths: [OAUTHBEARER],
		},
		config: {
			authMech: OAUTHBEARER,
			// Use a single write to avoid failure due to broken pipe.
			passCmd: '"printf %s\\\\\\\\n 1st\\\\ line 2nd\\\\ line 3rd\\\\ line"',
		},
	});
	expect.clientsToBeAuthenticatedWith(`${OAUTHBEARER} 1st line`);
});

test("no TLS", async () => {
	const { expect } = await setupWorld({
		imap: {
			isSecure: false,
			isStartTLSSupported: false,
			isClearTextLoginAllowed: true,
		},
		config: {
			tlsType: "NONE",
		},
	});
	expect.clientsToBeIdle();
});

test("STARTTLS", async () => {
	const { expect } = await setupWorld({
		imap: {
			isSecure: false,
		},
		config: {
			tlsType: "STARTTLS",
		},
	});
	expect.clientsToBeIdle();
});

test("no STARTTLS capability", async () => {
	const { expect } = await setupWorld({
		imap: {
			isSecure: false,
			isStartTLSSupported: false,
		},
		config: {
			tlsType: "STARTTLS",
			// To be 100% sure password is not sent.
			passCmd: '"sleep infinite"',
		},
	});
	expect.outputToMatch(/STARTTLS not supported/);
	expect.clientsToFailToLogin();
});

test("initial command", async () => {
	const { expect, configPath } = await setupWorld({
		mbidled: {
			timeout: 1500,
		},
	});
	expect.executedCommandsToBe([
		`${configPath}:test:Folder`,
		`${configPath}:test:INBOX`,
	]);
	expect.examinedIMAPFoldersToBe(['"INBOX"', '"INBOX.Folder"']);
	selfTestThrows(() => expect.executedCommandsToBe(["FOO"]));
	selfTestThrows(() => expect.examinedIMAPFoldersToBe(["FOO"]));
});

test("several AuthMechs given by the user", async () => {
	const { expect } = await setupWorld({
		imap: {
			allowedAuths: ["FIRST"],
		},
		config: {
			authMech: "* LOGIN FIRST SECOND THIRD",
		},
	});
	expect.clientsToBeAuthenticatedWith("FIRST password");
});

test("IMAP changes", async () => {
	const { expect, configPath } = await setupWorld({
		imap: {
			onIdle({ notify }) {
				setTimeout(notify, 0);
				setTimeout(notify, 100);
				setTimeout(notify, 500);
				// Initial command at 1s.
				setTimeout(notify, 1500);
				setTimeout(notify, 2500);
				// One more at 1s+2s.
			},
		},
		config: {
			patterns: "!Folder",
		},
		mbidled: {
			timeout: (1 + 2 + 3) * 1000,
		},
	});
	expect.executedCommandsToBe([
		`${configPath}:test:INBOX`,
		`${configPath}:test:INBOX`,
	]);
});

test("IMAP changes slow", async () => {
	const { expect, configPath } = await setupWorld({
		imap: {
			onIdle({ notify }) {
				// Initial command at 1s.
				setTimeout(notify, 4000);
				// One more at 4s+1s.
			},
		},
		config: {
			patterns: "INBOX",
		},
		mbidled: {
			timeout: 5500,
		},
	});
	expect.executedCommandsToBe([
		`${configPath}:test:INBOX`,
		`${configPath}:test:INBOX`,
	]);
});

test("Maildir changes", async () => {
	const { expect, configPath } = await setupWorld({
		maildir: {
			onSetup({ notify }) {
				// Initial commands at 1s.
				setTimeout(notify, 1500, "Folder");
				setTimeout(notify, 2500, "Folder");
				// One more at 1s+2s.
			},
		},
		config: {
			patterns: "Folder",
		},
		mbidled: {
			timeout: (1 + 2 + 3) * 1000,
		},
	});
	expect.executedCommandsToBe([
		`${configPath}:test:Folder`,
		`${configPath}:test:Folder`,
		`${configPath}:test:INBOX`,
	]);
});
