import { runScenario, test, runTests } from './test.mjs';

const OAUTHBEARER = 'OAUTHBEARER';
const cmdFailsWithOutput = '"echo stdout; echo stderr >&2; false"';
const cmdSucceedsWithoutOutput = '"echo stderr >&2"';

test('tilde expansion with non-existent user', async () => {
	const { expect } = await runScenario({
		config: {
			configOverride: [
				[
					'MaildirStore test',
					'Path ~',
					'Path ~/path',
					'Path ~nonexistentuser/path',
				],
			],
		},
	});
	expect.outputToContain('/config:4:26: Unknown user');
	expect.noClients();
});

test('invalid certificate', async () => {
	const { expect } = await runScenario({
		config: {
			withCertificateFile: false,
		},
	});
	expect.outputToContain(
		'Certificate verification failed: self-signed certificate',
	);
	expect.clientsToFailToLogin();
});

test('LOGINDISABLED capability', async () => {
	const { expect } = await runScenario({
		imap: {
			isLoginAllowed: false,
		},
	});
	expect.outputToContain('LOGIN disabled by the server');
	expect.clientsToFailToLogin();
});

test('no matching AUTH= capability but LOGIN allowed by the user', async () => {
	const { expect } = await runScenario({
		imap: {
			allowedAuths: ['A', 'ABC'],
		},
		config: {
			authMech: 'LOGIN AB',
		},
	});
	expect.clientsToBeLoggedInWith('"username" "password"');
	expect.clientsToBeIdle();
});

test('has matching AUTH= capability while LOGIN also allowed by the user', async () => {
	const { expect } = await runScenario({
		imap: {
			allowedAuths: ['AB'],
		},
		config: {
			authMech: 'LOGIN AB',
		},
	});
	expect.clientsToBeAuthenticatedWith('AB password');
	expect.clientsToBeIdle();
});

test('AUTH=LOGIN capability', async () => {
	const { expect } = await runScenario({
		imap: {
			allowedAuths: ['LOGIN'],
		},
		config: {
			authMech: 'LOGIN',
		},
	});
	expect.clientsToBeLoggedInWith('"username" "password"');
	expect.clientsToBeIdle();
});

test('no IDLE capability', async () => {
	const { expect } = await runScenario({
		imap: {
			isIDLEAllowed: false,
		},
	});
	expect.outputToContain('IDLE not supported');
	expect.clientsToFailToLogin();
});

test('LOGIN with User and Pass', async () => {
	const { expect } = await runScenario({});
	expect.clientsToBeLoggedInWith('"username" "password"');
	expect.clientsToBeIdle();
});

test('LOGIN with UserCmd and PassCmd', async () => {
	const { expect } = await runScenario({
		config: {
			userCmd: '"echo secretusername"',
			passCmd: '"echo secretpassword"',
		},
	});
	expect.clientsToBeLoggedInWith('"secretusername" "secretpassword"');
	expect.clientsToBeIdle();
});

for (const [configKey, optionName, errorMessage] of [
	['passCmd', 'PassCmd', 'No password'],
	['userCmd', 'UserCmd', 'No username'],
]) {
	test(`${optionName} produces output but fails`, async () => {
		const { expect } = await runScenario({
			config: {
				[configKey]: cmdFailsWithOutput,
			},
		});
		expect.outputToContain(`${optionName} failed`);
		expect.outputToContain(errorMessage);
		expect.clientsToFailToLogin();
	});

	test(`${optionName} succeeds without producing any data on stdout`, async () => {
		const { expect } = await runScenario({
			config: {
				[configKey]: cmdSucceedsWithoutOutput,
			},
		});
		expect.outputToContain(`${optionName} produced no output`);
		expect.outputToContain(errorMessage);
		expect.clientsToFailToLogin();
	});
}

test('PassCmd and UserCmd are always re-evaluated', async () => {
	const { expect } = await runScenario({
		config: {
			userCmd: '"echo stderr of userCmd >&2; echo secretusername"',
			passCmd: '"echo stderr of passCmd >&2; echo secretpassword"',
			patterns: '%',
		},
	});
	expect.outputToMatch(/(.*^stderr of userCmd$){4}/ms);
	expect.outputToMatch(/(.*^stderr of passCmd$){4}/ms);
	expect.clientsToBeLoggedInWith('"secretusername" "secretpassword"');
	expect.clientsToBeIdle();
});

test('PassCmd fails to generate AUTHENTICATE data', async () => {
	const { expect } = await runScenario({
		imap: {
			allowedAuths: [OAUTHBEARER],
		},
		config: {
			authMech: OAUTHBEARER,
			passCmd: cmdFailsWithOutput,
		},
	});
	expect.outputToContain('PassCmd failed');
	expect.outputToContain('No authdata');
	expect.clientsToFailToLogin();
});

test('PassCmd generates empty AUTHENTICATE data', async () => {
	const { expect } = await runScenario({
		imap: {
			allowedAuths: [OAUTHBEARER],
		},
		config: {
			authMech: OAUTHBEARER,
			passCmd: cmdSucceedsWithoutOutput,
		},
	});
	expect.outputToContain('PassCmd produced no output');
	expect.outputToContain('No authdata');
	expect.clientsToFailToLogin();
});

test('PassCmd generates AUTHENTICATE data without new lines', async () => {
	const { expect } = await runScenario({
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

test('PassCmd generates multiple lines for AUTHENTICATE data', async () => {
	const { expect } = await runScenario({
		imap: {
			allowedAuths: [OAUTHBEARER],
		},
		config: {
			authMech: OAUTHBEARER,
			passCmd: '"echo 1st line; echo 2nd line; echo 3rd line"',
		},
	});
	expect.clientsToBeAuthenticatedWith(`${OAUTHBEARER} 1st line`);
});

test('no TLS', async () => {
	const { expect } = await runScenario({
		imap: {
			isSecure: false,
			isStartTLSSupported: false,
			isClearTextLoginAllowed: true,
		},
		config: {
			tlsType: 'NONE',
		},
	});
	expect.clientsToBeIdle();
});

test('STARTTLS', async () => {
	const { expect } = await runScenario({
		imap: {
			isSecure: false,
		},
		config: {
			tlsType: 'STARTTLS',
		},
	});
	expect.clientsToBeIdle();
});

test('no STARTTLS capability', async () => {
	const { expect } = await runScenario({
		imap: {
			isSecure: false,
			isStartTLSSupported: false,
		},
		config: {
			tlsType: 'STARTTLS',
			// To be 100% sure password is not sent.
			passCmd: '"sleep infinite"',
		},
	});
	expect.outputToContain('STARTTLS not supported');
	expect.clientsToFailToLogin();
});

test('initial command', async () => {
	const { expect, configPath } = await runScenario({
		mbidled: {
			timeout: 1500,
		},
	});
	expect.executedCommandsToBe([
		`${configPath}:test:Folder`,
		`${configPath}:test:INBOX`,
	]);
	expect.examinedIMAPFoldersToBe(['"INBOX"', '"INBOX.Folder"']);
});

test('several AuthMechs given by the user', async () => {
	const { expect } = await runScenario({
		imap: {
			allowedAuths: ['FIRST'],
		},
		config: {
			authMech: '* LOGIN FIRST SECOND THIRD',
		},
	});
	expect.clientsToBeAuthenticatedWith('FIRST password');
});

test('IMAP changes', async () => {
	const { expect, configPath } = await runScenario({
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
			patterns: '!Folder',
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

test('IMAP changes slow', async () => {
	const { expect, configPath } = await runScenario({
		imap: {
			onIdle({ notify }) {
				// Initial command at 1s.
				setTimeout(notify, 4000);
				// One more at 4s+1s.
			},
		},
		config: {
			patterns: 'INBOX',
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

test('Maildir changes', async () => {
	const { expect, configPath } = await runScenario({
		maildir: {
			onSetup({ notify }) {
				// Initial commands at 1s.
				setTimeout(notify, 1500, 'Folder');
				setTimeout(notify, 2500, 'Folder');
				// One more at 1s+2s.
			},
		},
		config: {
			patterns: 'Folder',
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

await runTests();
