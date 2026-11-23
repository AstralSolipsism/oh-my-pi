import { afterEach, describe, expect, it, setSystemTime, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	type AuthCredential,
	type AuthCredentialStore,
	AuthStorage,
	SqliteAuthCredentialStore,
	type StoredAuthCredential,
} from "@oh-my-pi/pi-ai/auth-storage";
import * as oauthUtils from "@oh-my-pi/pi-ai/registry/oauth";
import type { OAuthCredentials } from "@oh-my-pi/pi-ai/registry/oauth/types";
import type { FetchImpl } from "@oh-my-pi/pi-ai/types";
import type { UsageLimit, UsageProvider, UsageReport } from "@oh-my-pi/pi-ai/usage";
import { kimiUsageProvider } from "@oh-my-pi/pi-ai/usage/kimi";
import { removeWithRetries } from "../../utils/src/temp";

const HOUR_MS = 60 * 60_000;
const DAY_MS = 24 * HOUR_MS;
const storages: AuthStorage[] = [];

/**
 * A weekly-quota 429 persists an unscoped cooldown for the reset it reported,
 * but the provider can restore quota days before that deadline. A fresh live
 * report over the subscription windows must lift the cooldown; exhausted,
 * unknown, partial, or failed reports never may.
 */
function kimiLimit(windowId: string, usedFraction: number, resetsAt?: number): UsageLimit {
	return {
		id: `kimi-code:${windowId}`,
		label: `${windowId} limit`,
		scope: { provider: "kimi-code", shared: true, windowId },
		window: resetsAt === undefined ? { id: windowId, label: windowId } : { id: windowId, label: windowId, resetsAt },
		amount: { usedFraction, remainingFraction: 1 - usedFraction, unit: "percent" },
		status: usedFraction >= 1 ? "exhausted" : usedFraction >= 0.9 ? "warning" : "ok",
	};
}

function kimiReport(limits: UsageLimit[], options?: { fetchedAt?: number; accountId?: string }): UsageReport {
	return {
		provider: "kimi-code",
		fetchedAt: options?.fetchedAt ?? Date.now(),
		limits,
		metadata: { accountId: options?.accountId ?? "account-1" },
	};
}

/** Feed a raw upstream payload through the real provider parser. */
async function parsedReport(payload: unknown): Promise<UsageReport | null> {
	const fetch: FetchImpl = async () => new Response(JSON.stringify(payload), { status: 200 });
	return kimiUsageProvider.fetchUsage(
		{ provider: "kimi-code", credential: { type: "oauth", accessToken: "kimi-test-token" } },
		{ fetch },
	);
}

function oauthRow(id: number): StoredAuthCredential {
	const credential: AuthCredential = {
		type: "oauth",
		access: `access-${id}`,
		refresh: `refresh-${id}`,
		expires: Date.now() + 24 * HOUR_MS,
		accountId: `account-${id}`,
	};
	return { id, provider: "kimi-code", credential, disabledCause: null };
}

/** Two OAuth accounts: 1 carries a days-long block in `blockScope` (default the unscoped key) and answers `report` (or `null`, a failed probe); 2 answers `sibling`. */
function makeStorage(options?: { report?: UsageReport | null; sibling?: UsageReport; blockScope?: string }): {
	storage: AuthStorage;
	blocks: Map<string, number>;
} {
	const rows = [oauthRow(1), oauthRow(2)];
	const blocks = new Map<string, number>([[`1:${options?.blockScope ?? ""}`, Date.now() + 3 * DAY_MS]]);
	const store: AuthCredentialStore = {
		close() {},
		listAuthCredentials: provider => rows.filter(row => provider === undefined || row.provider === provider),
		updateAuthCredential() {},
		async deleteAuthCredential() {
			return false;
		},
		tryDisableAuthCredentialIfMatches: () => false,
		replaceAuthCredentials: async () => rows,
		upsertAuthCredential: async () => rows,
		async deleteAuthCredentials() {},
		getCredentialBlock: (credentialId, _providerKey, scope) => blocks.get(`${credentialId}:${scope}`),
		upsertCredentialBlock: block => {
			blocks.set(`${block.credentialId}:${block.blockScope}`, block.blockedUntilMs);
		},
		deleteCredentialBlock: (credentialId, _providerKey, scope) => {
			blocks.delete(`${credentialId}:${scope}`);
		},
		getCache: () => null,
		setCache() {},
		cleanExpiredCache() {},
	};
	const usageProvider: UsageProvider = {
		id: "kimi-code",
		async fetchUsage(params) {
			const access = params.credential.type === "oauth" ? params.credential.accessToken : undefined;
			if (access === "access-2") {
				return (
					options?.sibling ?? kimiReport([kimiLimit("5h", 0.95), kimiLimit("7d", 0.9)], { accountId: "account-2" })
				);
			}
			return options?.report === undefined ? null : options.report;
		},
	};
	const storage = new AuthStorage(store, {
		usageProviderResolver: provider => (provider === "kimi-code" ? usageProvider : undefined),
		configValueResolver: async value => value,
	});
	return { storage, blocks };
}

/** Open a harness and register it for the afterEach teardown. */
async function openStorage(options?: Parameters<typeof makeStorage>[0]) {
	const harness = makeStorage(options);
	storages.push(harness.storage);
	await harness.storage.credentials.reload();
	return harness;
}

const oauthMock = () =>
	vi.spyOn(oauthUtils, "getOAuthApiKey").mockImplementation(async (_provider, credentials) => {
		const credential = credentials["kimi-code"] as OAuthCredentials | undefined;
		return credential ? { apiKey: credential.access, newCredentials: credential } : null;
	});

const healthy = () => kimiReport([kimiLimit("5h", 0.1), kimiLimit("7d", 0.2)]);

describe("Kimi usage-block healing", () => {
	afterEach(() => {
		for (const storage of storages) storage.close();
		storages.length = 0;
		vi.restoreAllMocks();
	});

	it("recovers a stale account-wide block during credential selection", async () => {
		oauthMock();
		const { storage, blocks } = await openStorage({ report: healthy() });

		expect(await storage.keys.get("kimi-code", "s-heal")).toBe("access-1");
		expect(blocks.has("1:")).toBe(false);
	});

	it("recovers a stale account-wide block through a health check and a usage pass", async () => {
		oauthMock();
		const { storage, blocks } = await openStorage({ report: healthy() });

		expect((await storage.usage.reports())?.length).toBeGreaterThan(0);
		const health = await storage.health.model("kimi-code", { reserveFraction: 0.1 });

		expect(blocks.has("1:")).toBe(false);
		expect(health.accounts.find(account => account.credentialId === 1)?.state).toBe("healthy");
	});

	it("heals from a zero-usage weekly payload that carries no reset time", async () => {
		oauthMock();
		const report = await parsedReport({ usage: { limit: "100", used: "0", remaining: "100" } });
		if (!report) throw new Error("expected a parsed weekly report");
		const { storage, blocks } = await openStorage({ report });

		expect(await storage.keys.get("kimi-code", "s-zero-week")).toBe("access-1");
		expect(blocks.has("1:")).toBe(false);
	});

	it("does not keep a healthy subscription blocked when only the one-shot top-up is spent", async () => {
		oauthMock();
		const report = await parsedReport({
			usage: {
				limit: "100",
				used: "10",
				remaining: "90",
				resetTime: new Date(Date.now() + 5 * DAY_MS).toISOString(),
			},
			limits: [
				{
					window: { duration: 300, timeUnit: "TIME_UNIT_MINUTE" },
					detail: { limit: "100", used: "10", remaining: "90" },
				},
			],
			totalQuota: { limit: "500", used: "500", remaining: "0", window: { duration: 30, timeUnit: "TIME_UNIT_DAY" } },
		});
		if (!report) throw new Error("expected a parsed report");
		const { storage, blocks } = await openStorage({ report });

		expect(await storage.keys.get("kimi-code", "s-top-up")).toBe("access-1");
		expect(blocks.has("1:")).toBe(false);
	});

	it("rotates a usage-limited session onto a recovered sibling within the pool", async () => {
		oauthMock();
		const { storage, blocks } = await openStorage({
			report: kimiReport([kimiLimit("5h", 1, Date.now() + 5 * HOUR_MS), kimiLimit("7d", 0.5)]),
			sibling: healthy(),
		});
		blocks.set("2:", Date.now() + 3 * DAY_MS);
		storage.sessions.pin("kimi-code", "s-rotate", 1);

		const mark = await storage.limits.markReached("kimi-code", "s-rotate", {
			credentialId: 1,
			retryAfterMs: 4 * DAY_MS,
			providerTimed: true,
		});

		expect(mark.switched).toBe(true);
		expect(blocks.has("2:")).toBe(false);
		expect(await storage.keys.get("kimi-code", "s-rotate")).toBe("access-2");
	});

	it("keeps the block when only a single partially-used gating window is reported", async () => {
		oauthMock();
		for (const limits of [
			[kimiLimit("5h", 0.1, Date.now() + 5 * HOUR_MS)],
			[kimiLimit("7d", 0.3, Date.now() + 5 * DAY_MS)],
			[kimiLimit("limit_month_total", 0.3, Date.now() + 20 * DAY_MS)],
		]) {
			const { storage, blocks } = await openStorage({ report: kimiReport(limits) });

			expect(await storage.keys.get("kimi-code", "s-partial")).toBe("access-2");
			expect(blocks.has("1:")).toBe(true);
		}
	});

	it("heals a single-window report only when its reset matches the stored deadline", async () => {
		oauthMock();
		const resetAt = Date.now() + 5 * HOUR_MS;
		const { storage, blocks } = await openStorage({ report: kimiReport([kimiLimit("5h", 0.1, resetAt)]) });
		blocks.set("1:", resetAt);

		expect(await storage.keys.get("kimi-code", "s-reset-match")).toBe("access-1");
		expect(blocks.has("1:")).toBe(false);
	});

	it("keeps the block while any gating window is exhausted", async () => {
		oauthMock();
		for (const windowId of ["5h", "7d", "limit_month_total", "limit_month_code"]) {
			const spent = kimiLimit(windowId, 1, Date.now() + 5 * DAY_MS);
			const other = windowId === "5h" ? kimiLimit("7d", 0.2) : kimiLimit("5h", 0.1);
			const { storage, blocks } = await openStorage({ report: kimiReport([other, spent]) });

			expect(await storage.keys.get("kimi-code", "s-spent")).toBe("access-2");
			expect(blocks.has("1:")).toBe(true);
		}
	});

	it("does not heal from an unknown-status or a non-quantitative window", async () => {
		oauthMock();
		for (const limits of [
			[kimiLimit("5h", 0.1), { ...kimiLimit("7d", 0.2), status: "unknown" as const }],
			[kimiLimit("5h", 0.1), { ...kimiLimit("7d", 0), amount: { unit: "percent" as const } }],
		]) {
			const { storage, blocks } = await openStorage({ report: kimiReport(limits) });

			expect(await storage.keys.get("kimi-code", "s-unusable")).toBe("access-2");
			expect(blocks.has("1:")).toBe(true);
		}
	});

	it("does not heal from a stale report, a failed probe, or inside the post-429 window", async () => {
		oauthMock();
		const cases = [
			makeStorage({
				report: kimiReport([kimiLimit("5h", 0.1), kimiLimit("7d", 0.2)], { fetchedAt: Date.now() - HOUR_MS }),
			}),
			makeStorage({ report: null }),
		];
		for (const stale of cases) {
			storages.push(stale.storage);
			await stale.storage.credentials.reload();
			await stale.storage.health.model("kimi-code", { reserveFraction: 0.1 });
			expect(stale.blocks.has("1:")).toBe(true);
		}

		const fresh = await openStorage({ report: healthy() });
		await fresh.storage.limits.markReached("kimi-code", "fresh-429", {
			credentialId: 1,
			retryAfterMs: 3 * DAY_MS,
			providerTimed: true,
		});
		await fresh.storage.health.model("kimi-code", { reserveFraction: 0.1 });
		expect(fresh.blocks.has("1:")).toBe(true);
	});

	it("does not heal an independent auth or account-policy block", async () => {
		oauthMock();
		for (const scope of ["auth", "account-policy"]) {
			const { storage, blocks } = await openStorage({ report: healthy(), blockScope: scope });

			expect(await storage.keys.get("kimi-code", "s-protected")).toBe("access-2");
			expect(blocks.has(`1:${scope}`)).toBe(true);
		}
	});
});

describe("Kimi usage-block healing across processes sharing one SQLite store", () => {
	it("a sibling's live fetch retires the marking process's mirror without resurrecting the deadline", async () => {
		oauthMock();
		let tempDir = "";
		let storeA: SqliteAuthCredentialStore | null = null;
		let storeB: SqliteAuthCredentialStore | null = null;
		let storageA: AuthStorage | null = null;
		let storageB: AuthStorage | null = null;
		try {
			tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pi-ai-auth-kimi-healing-"));
			storeA = await SqliteAuthCredentialStore.open(path.join(tempDir, "agent.db"));
			storeB = await SqliteAuthCredentialStore.open(path.join(tempDir, "agent.db"));
			const usageProvider: UsageProvider = {
				id: "kimi-code",
				async fetchUsage(params) {
					const accountId = params.credential.accountId;
					if (!accountId) return null;
					const exhausted = accountId === "account-1";
					return kimiReport(
						[
							kimiLimit("5h", exhausted ? 1 : 0.1, Date.now() + 5 * HOUR_MS),
							kimiLimit("7d", exhausted ? 0.5 : 0.2),
						],
						{ accountId },
					);
				},
			};
			const openStorage = (store: SqliteAuthCredentialStore) =>
				new AuthStorage(store, {
					usageProviderResolver: provider => (provider === "kimi-code" ? usageProvider : undefined),
				});
			storageA = openStorage(storeA);
			storageB = openStorage(storeB);
			const base = Date.now();
			setSystemTime(new Date(base));
			const credentials = [1, 2].map(index => ({
				type: "oauth" as const,
				access: `access-${index}`,
				refresh: `refresh-${index}`,
				expires: base + 24 * HOUR_MS,
				accountId: `account-${index}`,
			}));
			await storageA.credentials.set("kimi-code", credentials);
			await storageB.credentials.reload();
			const secondRow = storeA
				.listAuthCredentials("kimi-code")
				.find(row => row.credential.type === "oauth" && row.credential.accountId === "account-2");
			if (!secondRow) throw new Error("expected second Kimi credential");

			await storageA.limits.markReached("kimi-code", undefined, {
				credentialId: secondRow.id,
				retryAfterMs: 4 * DAY_MS,
				providerTimed: true,
			});
			expect(storeA.getCredentialBlock(secondRow.id, "kimi-code:oauth", "")).toBeDefined();

			// Past the post-429 window, a sibling's live fetch heals the row.
			setSystemTime(new Date(base + 6 * 60_000));
			expect(await storageB.keys.get("kimi-code", "s-sibling")).toBe("access-2");
			expect(storeA.getCredentialBlock(secondRow.id, "kimi-code:oauth", "")).toBeUndefined();

			// The marking process retires its stale mirror, and a later short
			// 429 does not resurrect the superseded deadline.
			setSystemTime(new Date(base + 7 * 60_000));
			expect(await storageA.keys.get("kimi-code", "s-mirror")).toBe("access-2");
			await storageA.limits.markReached("kimi-code", undefined, {
				credentialId: secondRow.id,
				retryAfterMs: 60_000,
			});
			const revived = storeA.getCredentialBlock(secondRow.id, "kimi-code:oauth", "");
			expect(revived).toBeDefined();
			expect(revived ?? 0).toBeLessThan(base + 9 * 60_000);
		} finally {
			setSystemTime();
			vi.restoreAllMocks();
			storageA?.close();
			storageB?.close();
			if (tempDir) await removeWithRetries(tempDir);
		}
	});
});
