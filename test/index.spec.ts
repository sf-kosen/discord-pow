import { describe, it, expect, vi } from "vitest";
import worker, { NonceStore } from "../src/index";

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;
const ADDITIONAL_VERIFIED_ROLE_ID_2026 = "1504117815333093426";
const ADDITIONAL_VERIFIED_ROLE_ID_2027 = "1504117815333093426";

class MemoryStorage {
  private values = new Map<string, unknown>();

  async get<T>(key: string): Promise<T | undefined> {
    return this.values.get(key) as T | undefined;
  }

  async put<T>(key: string, value: T): Promise<void> {
    this.values.set(key, value);
  }
}

class MemoryDurableObjectNamespace {
  private objects = new Map<
    string,
    { fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> }
  >();

  idFromName(name: string): string {
    return name;
  }

  get(id: string) {
    let object = this.objects.get(id);
    if (!object) {
      const durableObject = new NonceStore({ storage: new MemoryStorage() } as any);
      object = {
        fetch: (input: RequestInfo | URL, init?: RequestInit) =>
          durableObject.fetch(input instanceof Request ? input : new Request(input, init)),
      };
      this.objects.set(id, object);
    }
    return object;
  }
}

function createTestEnv(overrides: Record<string, unknown> = {}) {
  return {
    POW_SECRET: "test-secret",
    DISCORD_BOT_TOKEN: "test-bot-token",
    DISCORD_PUBLIC_KEY: "00",
    VERIFIED_ROLE_ID: "role-id",
    NONCE_STORE: new MemoryDurableObjectNamespace(),
    ...overrides,
  } as any;
}

function u8ToBase64Url(u8: Uint8Array): string {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  const b64 = btoa(s);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hmacSha256Base64Url(secret: string, data: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return u8ToBase64Url(new Uint8Array(sig));
}

async function sha256Utf8(data: string): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(data));
  return new Uint8Array(digest);
}

function hasLeadingZeroBits(buf: Uint8Array, zeroBits: number): boolean {
  let bits = zeroBits;
  for (let i = 0; i < buf.length; i++) {
    if (bits <= 0) return true;
    const b = buf[i];
    if (bits >= 8) {
      if (b !== 0) return false;
      bits -= 8;
    } else {
      const mask = 0xff << (8 - bits);
      return (b & mask) === 0;
    }
  }
  return bits <= 0;
}

async function findPowNonce(token: string, diff: number): Promise<string> {
  let nonce = 0;
  while (true) {
    const h = await sha256Utf8(`${token}.${nonce}`);
    if (hasLeadingZeroBits(h, diff)) return String(nonce);
    nonce += 1;
    if (nonce > 1_000_000) throw new Error("nonce search exceeded");
  }
}

async function makeToken(
  secret: string,
  guildId: string,
  userId: string,
  roleId: string,
  exp: number,
  diff: number
): Promise<string> {
  const tokenNonce = crypto.getRandomValues(new Uint8Array(16));
  const nonceB64u = u8ToBase64Url(tokenNonce);
  const payload = `pow.v1.${nonceB64u}.${guildId}.${userId}.${roleId}.${exp}.${diff}`;
  const sig = await hmacSha256Base64Url(secret, payload);
  return `${payload}.${sig}`;
}

describe("nonce replay protection", () => {
  it("serves /verify with no-store and no-referrer headers", async () => {
    const env = createTestEnv();
    const request = new IncomingRequest("http://example.com/verify");
    const res = await worker.fetch(request, env);
    expect(res.headers.get("cache-control")).toContain("no-store");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("permissions-policy")).toContain("camera=()");
  });

  it("rejects the second submit with the same token nonce", async () => {
    const testEnv = createTestEnv();

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    try {
      const diff = 1;
      const now = Math.floor(Date.now() / 1000);
      const exp = now + 600;
      const token = await makeToken(
        testEnv.POW_SECRET,
        "guild",
        "user",
        testEnv.VERIFIED_ROLE_ID,
        exp,
        diff
      );
      const powNonce = await findPowNonce(token, diff);

      const body = JSON.stringify({ token, nonce: powNonce, user_id: "user", guild_id: "guild" });
      const request = new IncomingRequest("http://example.com/api/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });

      const res1 = await worker.fetch(request, testEnv);
      expect(res1.status).toBe(200);
      expect(await res1.json()).toEqual({ ok: true });

      const replayRequest = new IncomingRequest("http://example.com/api/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
      const res2 = await worker.fetch(replayRequest, testEnv);
      expect(res2.status).toBe(409);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("grants the student role and the 2026 additional verified role", async () => {
    const testEnv = createTestEnv();
    const grantedRoleIds: string[] = [];
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-13T00:00:00+09:00"));

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        grantedRoleIds.push(url.split("/").pop() ?? "");
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    try {
      const diff = 1;
      const now = Math.floor(Date.now() / 1000);
      const exp = now + 600;
      const token = await makeToken(
        testEnv.POW_SECRET,
        "guild",
        "user",
        testEnv.VERIFIED_ROLE_ID,
        exp,
        diff
      );
      const powNonce = await findPowNonce(token, diff);

      const request = new IncomingRequest("http://example.com/api/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token, nonce: powNonce, user_id: "user", guild_id: "guild" }),
      });

      const res = await worker.fetch(request, testEnv);
      expect(res.status).toBe(200);
      expect(grantedRoleIds).toEqual([testEnv.VERIFIED_ROLE_ID, ADDITIONAL_VERIFIED_ROLE_ID_2026]);
    } finally {
      vi.unstubAllGlobals();
      vi.useRealTimers();
    }
  });

  it("grants the student role and the 2027 additional verified role after New Year in Japan", async () => {
    const testEnv = createTestEnv();
    const grantedRoleIds: string[] = [];
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2027-01-01T00:00:00+09:00"));

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        grantedRoleIds.push(url.split("/").pop() ?? "");
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    try {
      const diff = 1;
      const now = Math.floor(Date.now() / 1000);
      const exp = now + 600;
      const token = await makeToken(
        testEnv.POW_SECRET,
        "guild",
        "user",
        testEnv.VERIFIED_ROLE_ID,
        exp,
        diff
      );
      const powNonce = await findPowNonce(token, diff);

      const request = new IncomingRequest("http://example.com/api/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token, nonce: powNonce, user_id: "user", guild_id: "guild" }),
      });

      const res = await worker.fetch(request, testEnv);
      expect(res.status).toBe(200);
      expect(grantedRoleIds).toEqual([testEnv.VERIFIED_ROLE_ID, ADDITIONAL_VERIFIED_ROLE_ID_2027]);
    } finally {
      vi.unstubAllGlobals();
      vi.useRealTimers();
    }
  });

  it("rejects submit for a guild outside the allowlist", async () => {
    const testEnv = createTestEnv({ ALLOWED_GUILD_IDS: "other-guild" });

    const diff = 1;
    const now = Math.floor(Date.now() / 1000);
    const exp = now + 600;
    const token = await makeToken(
      testEnv.POW_SECRET,
      "guild",
      "user",
      testEnv.VERIFIED_ROLE_ID,
      exp,
      diff
    );
    const powNonce = await findPowNonce(token, diff);

    const request = new IncomingRequest("http://example.com/api/submit", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, nonce: powNonce, user_id: "user", guild_id: "guild" }),
    });

    const res = await worker.fetch(request, testEnv);
    expect(res.status).toBe(403);
  });

  it("rejects when submit user_id mismatches token", async () => {
    const testEnv = createTestEnv();

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    try {
      const diff = 1;
      const now = Math.floor(Date.now() / 1000);
      const exp = now + 600;
      const token = await makeToken(
        testEnv.POW_SECRET,
        "guild",
        "user",
        testEnv.VERIFIED_ROLE_ID,
        exp,
        diff
      );
      const powNonce = await findPowNonce(token, diff);

      const request = new IncomingRequest("http://example.com/api/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token, nonce: powNonce, user_id: "other", guild_id: "guild" }),
      });

      const res = await worker.fetch(request, testEnv);
      expect(res.status).toBe(400);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("rejects when submit guild_id mismatches token", async () => {
    const testEnv = createTestEnv();

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    try {
      const diff = 1;
      const now = Math.floor(Date.now() / 1000);
      const exp = now + 600;
      const token = await makeToken(
        testEnv.POW_SECRET,
        "guild",
        "user",
        testEnv.VERIFIED_ROLE_ID,
        exp,
        diff
      );
      const powNonce = await findPowNonce(token, diff);

      const request = new IncomingRequest("http://example.com/api/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token, nonce: powNonce, user_id: "user", guild_id: "other" }),
      });

      const res = await worker.fetch(request, testEnv);
      expect(res.status).toBe(400);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("rejects when token role_id mismatches env", async () => {
    const testEnv = createTestEnv();

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    try {
      const diff = 1;
      const now = Math.floor(Date.now() / 1000);
      const exp = now + 600;
      const token = await makeToken(
        testEnv.POW_SECRET,
        "guild",
        "user",
        "other-role",
        exp,
        diff
      );
      const powNonce = await findPowNonce(token, diff);

      const request = new IncomingRequest("http://example.com/api/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token, nonce: powNonce, user_id: "user", guild_id: "guild" }),
      });

      const res = await worker.fetch(request, testEnv);
      expect(res.status).toBe(400);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("rejects when token difficulty is tampered", async () => {
    const testEnv = createTestEnv();

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    try {
      const diff = 1;
      const now = Math.floor(Date.now() / 1000);
      const exp = now + 600;
      const token = await makeToken(
        testEnv.POW_SECRET,
        "guild",
        "user",
        testEnv.VERIFIED_ROLE_ID,
        exp,
        diff
      );
      const parts = token.split(".");
      parts[7] = "2";
      const tampered = parts.join(".");

      const request = new IncomingRequest("http://example.com/api/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: tampered, nonce: "0", user_id: "user", guild_id: "guild" }),
      });

      const res = await worker.fetch(request, testEnv);
      expect(res.status).toBe(400);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
