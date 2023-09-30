import { assert, createTestSetup } from './helpers.mjs';

const clientLoggedIn = (client) => client.isLoggedIn;
const clientIdling = (client) => client.isIdling;

const tests = {
	async testCertificate() {
		const { imap, mbidled } = await createTestSetup({
			config: {
				withCertificateFile: false,
			},
		});

		assert(
			mbidled
				.getOutput()
				.includes('Certificate verification failed: self-signed certificate'),
		);
		assert(imap.clients.length === 1);
		assert(!imap.clients.some(clientLoggedIn));
	},
	async testLoginDisabled() {
		const { imap, mbidled } = await createTestSetup({
			imap: {
				isLoginAllowed: false,
			},
		});

		assert(mbidled.getOutput().includes('LOGIN disabled by the server'));
		assert(imap.clients.length === 1);
		assert(!imap.clients.some(clientLoggedIn));
	},
	async testIDLEDisabled() {
		const { imap, mbidled } = await createTestSetup({
			imap: {
				isIDLEAllowed: false,
				isLoginAllowed: false,
			},
		});

		assert(mbidled.getOutput().includes('IDLE not supported'));
		assert(imap.clients.length === 1);
		assert(!imap.clients.some(clientLoggedIn));
	},
	async testNoTLS() {
		const { imap, mbidled } = await createTestSetup({
			imap: {
				isSecure: false,
				isStartTLSSupported: false,
				isClearTextLoginAllowed: true,
			},
			config: {
				tlsType: 'NONE',
			},
		});

		assert(imap.clients.length > 0);
		assert(imap.clients.every(clientLoggedIn));
	},
	async testSTARTTLS() {
		const { imap, mbidled } = await createTestSetup({
			imap: {
				isSecure: false,
			},
			config: {
				tlsType: 'STARTTLS',
			},
		});

		assert(imap.clients.length > 0);
		assert(imap.clients.every(clientLoggedIn));
	},
	async testTLS() {
		const { imap, mbidled } = await createTestSetup({});

		assert(imap.clients.length > 0);
		assert(imap.clients.every(clientLoggedIn));
	},
	async testInitialCommand() {
		const { imap, mbidled, configPath } = await createTestSetup({
			mbidled: {
				timeout: 1500,
			},
		});

		assert(
			JSON.stringify(mbidled.getExecutedCommands()) ==
				JSON.stringify([`${configPath}:test:Folder`]),
		);
	},
	async testIMAPChanges() {
		const { imap, mbidled, configPath } = await createTestSetup({
			imap: {
				onIdle({ notify }) {
					setTimeout(notify, 0);
					setTimeout(notify, 100);
					setTimeout(notify, 500);
					/* Initial command at 1s. */
					setTimeout(notify, 1500);
					setTimeout(notify, 2500);
					/* One more at 1s+2s. */
				},
			},
			mbidled: {
				timeout: (1 + 2 + 3) * 1000,
			},
		});

		assert(
			JSON.stringify(mbidled.getExecutedCommands()) ==
				JSON.stringify([
					`${configPath}:test:Folder`,
					`${configPath}:test:Folder`,
				]),
		);
	},
	async testIMAPChangesSlow() {
		const { imap, mbidled, configPath } = await createTestSetup({
			imap: {
				onIdle({ notify }) {
					/* Initial command at 1s. */
					setTimeout(notify, 4000);
					/* One more at 4s+1s. */
				},
			},
			mbidled: {
				timeout: 5500,
			},
		});

		assert(
			JSON.stringify(mbidled.getExecutedCommands()) ==
				JSON.stringify([
					`${configPath}:test:Folder`,
					`${configPath}:test:Folder`,
				]),
		);
	},
	async testMaildirChanges() {
		const { imap, mbidled, configPath } = await createTestSetup({
			maildir: {
				onSetup({ notify }) {
					/* Initial command at 1s. */
					setTimeout(notify, 1500);
					setTimeout(notify, 2500);
					/* One more at 1s+2s. */
				},
			},
			mbidled: {
				timeout: (1 + 2 + 3) * 1000,
			},
		});

		assert(
			JSON.stringify(mbidled.getExecutedCommands()) ==
				JSON.stringify([
					`${configPath}:test:Folder`,
					`${configPath}:test:Folder`,
				]),
		);
	},
};

await Promise.all(Object.values(tests).map((testFn) => testFn()));
