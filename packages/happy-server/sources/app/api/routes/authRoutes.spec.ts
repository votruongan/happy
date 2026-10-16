import fastify from "fastify";
import * as privacyKit from "privacy-kit";
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from "fastify-type-provider-zod";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type Fastify } from "../types";

interface AuthRequestRow {
    id: string;
    publicKey: string;
    supportsV2: boolean;
    response: string | null;
    responseAccountId: string | null;
}

const { tables, dbMock, resetTables } = vi.hoisted(() => {
    const tables = {
        terminalAuthRequest: new Map<string, AuthRequestRow>(),
        accountAuthRequest: new Map<string, AuthRequestRow>(),
    };

    // Mirrors the Prisma calls the routes make. updateMany only matches rows
    // whose `response` is still null, like the real conditional update.
    const model = (table: Map<string, AuthRequestRow>) => ({
        findUnique: vi.fn(async (args: any) => {
            const row = table.get(args.where.publicKey);
            return row ? { ...row } : null;
        }),
        updateMany: vi.fn(async (args: any) => {
            const row = table.get(args.where.publicKey);
            if (!row || (args.where.response === null && row.response !== null)) {
                return { count: 0 };
            }
            Object.assign(row, args.data);
            return { count: 1 };
        }),
        upsert: vi.fn(async (args: any) => {
            let row = table.get(args.where.publicKey);
            if (!row) {
                row = { id: `req-${table.size + 1}`, supportsV2: false, response: null, responseAccountId: null, ...args.create };
                table.set(args.where.publicKey, row!);
            }
            return { ...row! };
        }),
    });

    const dbMock = {
        terminalAuthRequest: model(tables.terminalAuthRequest),
        accountAuthRequest: model(tables.accountAuthRequest),
    };

    const resetTables = () => {
        tables.terminalAuthRequest.clear();
        tables.accountAuthRequest.clear();
    };

    return { tables, dbMock, resetTables };
});

vi.mock("@/storage/db", () => ({ db: dbMock }));
vi.mock("@/app/auth/auth", () => ({
    auth: { createToken: vi.fn(async (userId: string) => `token-for-${userId}`) },
}));

import { authRoutes } from "./authRoutes";

async function createApp() {
    const app = fastify();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    const typed = app.withTypeProvider<ZodTypeProvider>() as unknown as Fastify;
    typed.decorate("authenticate", async (request: any, reply: any) => {
        const userId = request.headers["x-user-id"];
        if (typeof userId !== "string") {
            return reply.code(401).send({ error: "Unauthorized" });
        }
        request.userId = userId;
    });
    authRoutes(typed);
    await typed.ready();
    return typed;
}

const publicKey = privacyKit.encodeBase64(new Uint8Array(32).fill(7));
const publicKeyHex = privacyKit.encodeHex(new Uint8Array(32).fill(7));

const flows = [
    { name: "terminal", request: "/v1/auth/request", response: "/v1/auth/response", table: "terminalAuthRequest" as const },
    { name: "account", request: "/v1/auth/account/request", response: "/v1/auth/account/response", table: "accountAuthRequest" as const },
];

describe.each(flows)("authRoutes — $name pairing answers", (flow) => {
    let app: Fastify;
    beforeEach(() => { resetTables(); });
    afterEach(async () => { if (app) await app.close(); });

    async function request() {
        return app.inject({ method: "POST", url: flow.request, payload: { publicKey } });
    }

    async function answer(userId: string, response: string) {
        return app.inject({
            method: "POST",
            url: flow.response,
            headers: { "x-user-id": userId },
            payload: { publicKey, response },
        });
    }

    it("stores the first answer and gives the requester that account's token", async () => {
        app = await createApp();
        await request();

        const res = await answer("owner", "owner-reply");
        expect(res.statusCode).toBe(200);

        const poll = await request();
        expect(poll.json()).toEqual({ state: "authorized", token: "token-for-owner", response: "owner-reply" });
    });

    it("refuses a second answer from another account with 409 and keeps the first", async () => {
        app = await createApp();
        await request();
        await answer("attacker", "forged-reply");

        const res = await answer("owner", "owner-reply");
        expect(res.statusCode).toBe(409);
        expect(res.json()).toEqual({ error: "already-answered" });

        const row = tables[flow.table].get(publicKeyHex)!;
        expect(row.response).toBe("forged-reply");
        expect(row.responseAccountId).toBe("attacker");
    });

    it("refuses a different second answer from the same account", async () => {
        app = await createApp();
        await request();
        await answer("owner", "first-reply");

        const res = await answer("owner", "second-reply");
        expect(res.statusCode).toBe(409);
        expect(tables[flow.table].get(publicKeyHex)!.response).toBe("first-reply");
    });

    it("accepts a retry of the stored answer by the same account", async () => {
        app = await createApp();
        await request();
        await answer("owner", "owner-reply");

        const res = await answer("owner", "owner-reply");
        expect(res.statusCode).toBe(200);
    });

    it("lets exactly one of two racing answers win", async () => {
        app = await createApp();
        await request();

        const results = await Promise.all([answer("a", "reply-a"), answer("b", "reply-b")]);
        const codes = results.map((r) => r.statusCode).sort();
        expect(codes).toEqual([200, 409]);

        const winner = results[0].statusCode === 200 ? "a" : "b";
        expect(tables[flow.table].get(publicKeyHex)!.responseAccountId).toBe(winner);
    });

    it("returns 404 for an unknown request", async () => {
        app = await createApp();

        const res = await answer("owner", "owner-reply");
        expect(res.statusCode).toBe(404);
    });
});
