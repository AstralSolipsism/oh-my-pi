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
import { ProviderHttpError } from "@oh-my-pi/pi-ai/error";
import * as oauthUtils from "@oh-my-pi/pi-ai/registry/oauth";
import type { FetchImpl } from "@oh-my-pi/pi-ai/types";
import type { UsageLimit, UsageProvider, UsageReport } from "@oh-my-pi/pi-ai/usage";
import { kimiUsageProvider } from "@oh-my-pi/pi-ai/usage/kimi";
import { removeWithRetries } from "../../utils/src/temp";

const HOUR_MS = 60 * 60_000;
const DAY_MS = 24 * HOUR_MS;
const storages: AuthStorage[] = [];

/**
 * A quota 429 (or monthly termination 403) persists an unscoped cooldown for
 * the reset it reported, but the provider can restore quota days before that
 * deadline. A fresh live report must lift the cooldown only when it covers
 * every meter that could have set the block; exhausted, unknown, partial, or
 * failed reports never may.
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

interface HarnessOptions {
	/** Account 1's live report; `null` is a failed probe. */
	report?: UsageReport | null;
	/** Account 2's live answer; defaults to a nearly-spent sibling. */
	sibling?: UsageReport;
	/** Scope of account 1's days-long seeded block; the unscoped key by default. */
	blockScope?: string;
}

/** Two OAuth accounts: 1 carries a days-long block and answers `report`; 2 answers `sibling`. */
function makeStorage(options?: HarnessOptions): { storage: AuthStorage; blocks: Map<string, number> } {
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
async function openStorage(options?: HarnessOptions) {
	const harness = makeStorage(options);
	storages.push(harness.storage);
	await harness.storage.credentials.reload();
	return harness;
}

const oauthMock = () =>
	vi.spyOn(oauthUtils, "getOAuthApiKey").mockImplementation(async (_provider, credentials) => {
		const credential = credentials["kimi-code"];
		return credential ? { apiKey: credential.access, newCredentials: credential } : null;
	});

/** A complete, healthy report over every healing window. */
const healthy = () =>
	kimiReport([
		kimiLimit("5h", 0.1),
		kimiLimit("7d", 0.2),
		kimiLimit("limit_month_total", 0.3),
		kimiLimit("limit_month_code", 0.3),
	]);

/** A complete healthy report without the burst window, proven unspent by the 0% week. */
const zeroWeekComplete = () =>
	kimiReport([kimiLimit("7d", 0), kimiLimit("limit_month_total", 0.3), kimiLimit("limit_month_code", 0.3)]);

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

	it("recovers a stale account-wide block through a usage pass alone", async () => {
		oauthMock();
		const { storage, blocks } = await openStorage({ report: healthy() });

		await storage.usage.reports();

		expect(blocks.has("1:")).toBe(false);
	});

	it("recovers a stale account-wide block through a health check alone", async () => {
		oauthMock();
		const { storage, blocks } = await openStorage({ report: healthy() });

		const health = await storage.health.model("kimi-code", { reserveFraction: 0.1 });

		expect(blocks.has("1:")).toBe(false);
		expect(health.accounts.find(account => account.credentialId === 1)?.state).toBe("healthy");
	});

	it("recovers from a complete zero-week report that carries no reset time", async () => {
		oauthMock();
		const { storage, blocks } = await openStorage({ report: zeroWeekComplete() });

		expect(await storage.keys.get("kimi-code", "s-zero-week")).toBe("access-1");
		expect(blocks.has("1:")).toBe(false);
	});

	it("does not keep a healthy subscription blocked when only the one-shot top-up is spent", async () => {
		oauthMock();
		const monthlyReset = new Date(Date.now() + 20 * DAY_MS).toISOString();
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
			usages: {
				limit_month_total: { used_ratio: 0.3, reset_time: monthlyReset },
				limit_month_code: { used_ratio: 0.3, reset_time: monthlyReset },
			},
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

	it("keeps the block while any healing window is exhausted", async () => {
		oauthMock();
		for (const windowId of ["5h", "7d", "limit_month_total", "limit_month_code"]) {
			const report = healthy();
			const index = report.limits.findIndex(limit => limit.window?.id === windowId);
			report.limits[index] = kimiLimit(windowId, 1, Date.now() + 5 * DAY_MS);
			const { storage, blocks } = await openStorage({ report });

			expect(await storage.keys.get("kimi-code", "s-spent")).toBe("access-2");
			expect(blocks.has("1:")).toBe(true);
		}
	});

	it("does not heal from an unknown-status or a non-quantitative window", async () => {
		oauthMock();
		for (const replace of [
			{ ...kimiLimit("7d", 0.2), status: "unknown" as const },
			{ ...kimiLimit("7d", 0), amount: { unit: "percent" as const } },
		]) {
			const report = healthy();
			const index = report.limits.findIndex(limit => limit.window?.id === "7d");
			report.limits[index] = replace;
			const { storage, blocks } = await openStorage({ report });

			expect(await storage.keys.get("kimi-code", "s-unusable")).toBe("access-2");
			expect(blocks.has("1:")).toBe(true);
		}
	});

	it("does not heal from a stale report, a failed probe, or inside the post-429 window", async () => {
		oauthMock();
		const stale = makeStorage({ report: kimiReport(healthy().limits, { fetchedAt: Date.now() - HOUR_MS }) });
		storages.push(stale.storage);
		await stale.storage.credentials.reload();
		await stale.storage.health.model("kimi-code", { reserveFraction: 0.1 });
		expect(stale.blocks.has("1:")).toBe(true);

		const failed = makeStorage({ report: null });
		storages.push(failed.storage);
		await failed.storage.credentials.reload();
		await failed.storage.health.model("kimi-code", { reserveFraction: 0.1 });
		expect(failed.blocks.has("1:")).toBe(true);

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

	it("keeps a monthly cooldown when the report only vouches for the weekly window", async () => {
		// A monthly termination 403 leaves the same unscoped block while
		// /usages still answers a healthy week; the weekly row alone cannot
		// prove the monthly meter recovered, whatever its reset says.
		oauthMock();
		const report = await parsedReport({
			usage: {
				limit: "100",
				used: "0",
				remaining: "100",
				resetTime: new Date(Date.now() + 6 * DAY_MS + HOUR_MS).toISOString(),
			},
		});
		if (!report) throw new Error("expected a parsed weekly report");
		const { storage, blocks } = await openStorage({ report });

		await storage.usage.reports();

		expect(await storage.keys.get("kimi-code", "s-weekly-only")).toBe("access-2");
		expect(blocks.has("1:")).toBe(true);
	});

	it("keeps a monthly cooldown when only one of the two monthly meters is reported", async () => {
		oauthMock();
		// Both monthly meters share one billing reset, so a lone healthy meter
		// whose reset equals the stored deadline still cannot vouch for the
		// meter the report omitted.
		const monthlyReset = Date.now() + 20 * DAY_MS;
		for (const reported of ["limit_month_total", "limit_month_code"]) {
			const { storage, blocks } = await openStorage({
				report: kimiReport([kimiLimit("5h", 0.1), kimiLimit("7d", 0.2), kimiLimit(reported, 0.3, monthlyReset)]),
			});
			blocks.set("1:", monthlyReset);

			await storage.usage.reports();

			expect(blocks.has("1:")).toBe(true);
		}

		// Without the weekly row the report is partial even with both monthly
		// meters, and the default three-day deadline matches neither monthly
		// reset, so the block stands.
		const withoutWeekly = await openStorage({
			report: kimiReport([
				kimiLimit("5h", 0.1),
				kimiLimit("limit_month_total", 0.3, monthlyReset),
				kimiLimit("limit_month_code", 0.3, monthlyReset),
			]),
		});
		await withoutWeekly.storage.usage.reports();
		expect(withoutWeekly.blocks.has("1:")).toBe(true);

		// With both meters present the shared reset does match, so the block
		// heals through the reset-match path even without the weekly row.
		const complete = await openStorage({
			report: kimiReport([
				kimiLimit("5h", 0.1),
				kimiLimit("limit_month_total", 0.3, monthlyReset),
				kimiLimit("limit_month_code", 0.3, monthlyReset),
			]),
		});
		complete.blocks.set("1:", monthlyReset);

		await complete.storage.usage.reports();

		expect(complete.blocks.has("1:")).toBe(false);
	});

	it("still selects an unblocked account whose monthly code meter is spent", async () => {
		// Hard-blocking on monthly meters is a selection-policy change this
		// healing fix must not smuggle in: an otherwise-healthy login keeps
		// serving and no block row is written for it.
		oauthMock();
		const { storage, blocks } = await openStorage({
			report: kimiReport([kimiLimit("5h", 0.1), kimiLimit("7d", 0.2), kimiLimit("limit_month_code", 1)]),
		});
		blocks.delete("1:");

		expect(await storage.keys.get("kimi-code", "s-unblocked")).toBe("access-1");
		expect(blocks.has("1:")).toBe(false);
	});
});

describe("Kimi usage-block healing across processes sharing one SQLite store", () => {
	it("a monthly 403 cooldown survives a healthy weekly-only report; a sibling's complete fetch retires the mirror", async () => {
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
			const monthlyReset = new Date(Date.now() + 20 * DAY_MS).toISOString();
			// Recovery payloads keyed by bearer token: account 1 only ever
			// answers its healthy week (the monthly-403 shape), account 2
			// answers a complete report.
			const payloads = new Map<string, unknown>([
				["access-1", { usage: { limit: "100", used: "0", remaining: "100" } }],
				[
					"access-2",
					{
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
						usages: {
							limit_month_total: { used_ratio: 0.3, reset_time: monthlyReset },
							limit_month_code: { used_ratio: 0.3, reset_time: monthlyReset },
						},
					},
				],
			]);
			const fetchMock = Object.assign(
				async (request: string | Request | URL, init?: RequestInit) => {
					const headers = request instanceof Request ? request.headers : new Headers(init?.headers);
					const token = headers.get("authorization")?.replace(/^Bearer /, "") ?? "";
					return new Response(JSON.stringify(payloads.get(token) ?? {}), {
						status: 200,
						headers: { "content-type": "application/json" },
					});
				},
				{ preconnect: fetch.preconnect },
			);
			vi.spyOn(globalThis, "fetch").mockImplementation(fetchMock);
			const openStorage = (store: SqliteAuthCredentialStore) =>
				new AuthStorage(store, {
					usageProviderResolver: provider => (provider === "kimi-code" ? kimiUsageProvider : undefined),
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
			const firstRow = storeA
				.listAuthCredentials("kimi-code")
				.find(row => row.credential.type === "oauth" && row.credential.accountId === "account-1");
			if (!firstRow) throw new Error("expected first Kimi credential");

			// The monthly termination 403 rotates into a 4-day unscoped block.
			const terminated = new ProviderHttpError(
				`403 {"error":{"type":"access_terminated_error"}} retry-after-ms=${4 * DAY_MS}`,
				403,
			);
			const rotation = await storageA.limits.rotate("kimi-code", undefined, {
				error: terminated,
				credentialId: firstRow.id,
			});
			expect(rotation.switched).toBe(true);
			expect(storeA.getCredentialBlock(firstRow.id, "kimi-code:oauth", "")).toBeDefined();

			// Past the post-429 window, the healthy weekly-only report the
			// provider keeps answering must not clear the monthly cooldown.
			setSystemTime(new Date(base + 6 * 60_000));
			await storageA.usage.reports();
			expect(storeA.getCredentialBlock(firstRow.id, "kimi-code:oauth", "")).toBeDefined();
			expect(await storageA.keys.get("kimi-code", "s-monthly-cooldown")).toBe("access-2");

			// A sibling's complete live fetch heals its own block, the marking
			// process retires its stale mirror, and a later short 429 does not
			// resurrect the superseded deadline.
			const secondRow = storeA
				.listAuthCredentials("kimi-code")
				.find(row => row.credential.type === "oauth" && row.credential.accountId === "account-2");
			if (!secondRow) throw new Error("expected second Kimi credential");
			setSystemTime(new Date(base + 7 * 60_000));
			await storageA.limits.markReached("kimi-code", undefined, {
				credentialId: secondRow.id,
				retryAfterMs: 3 * DAY_MS,
				providerTimed: true,
			});
			setSystemTime(new Date(base + 14 * 60_000));
			expect(await storageB.keys.get("kimi-code", "s-sibling")).toBe("access-2");
			expect(storeA.getCredentialBlock(secondRow.id, "kimi-code:oauth", "")).toBeUndefined();

			setSystemTime(new Date(base + 15 * 60_000));
			expect(await storageA.keys.get("kimi-code", "s-mirror")).toBe("access-2");
			await storageA.limits.markReached("kimi-code", undefined, {
				credentialId: secondRow.id,
				retryAfterMs: 60_000,
			});
			const revived = storeA.getCredentialBlock(secondRow.id, "kimi-code:oauth", "");
			expect(revived).toBeDefined();
			expect(revived ?? 0).toBeLessThan(base + 17 * 60_000);
		} finally {
			setSystemTime();
			vi.restoreAllMocks();
			storageA?.close();
			storageB?.close();
			if (tempDir) await removeWithRetries(tempDir);
		}
	});
});
