import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import worker from "../src/index";

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

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
    const request = new IncomingRequest("http://example.com/verify");
    const ctx = createExecutionContext();
    const res = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.headers.get("cache-control")).toContain("no-store");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("rejects the second submit with the same token nonce", async () => {
    const testEnv = env as any;
    testEnv.POW_SECRET = "test-secret";
    testEnv.DISCORD_BOT_TOKEN = "test-bot-token";
    testEnv.VERIFIED_ROLE_ID = "role-id";

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        return new Response("", { status: 204 });
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

      const ctx1 = createExecutionContext();
      const res1 = await worker.fetch(request, testEnv, ctx1);
      await waitOnExecutionContext(ctx1);
      expect(res1.status).toBe(200);
      expect(await res1.json()).toEqual({ ok: true });

      const ctx2 = createExecutionContext();
      const res2 = await worker.fetch(request, testEnv, ctx2);
      await waitOnExecutionContext(ctx2);
      expect(res2.status).toBe(409);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("rejects when submit user_id mismatches token", async () => {
    const testEnv = env as any;
    testEnv.POW_SECRET = "test-secret";
    testEnv.DISCORD_BOT_TOKEN = "test-bot-token";
    testEnv.VERIFIED_ROLE_ID = "role-id";

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        return new Response("", { status: 204 });
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

      const ctx = createExecutionContext();
      const res = await worker.fetch(request, testEnv, ctx);
      await waitOnExecutionContext(ctx);
      expect(res.status).toBe(400);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("rejects when submit guild_id mismatches token", async () => {
    const testEnv = env as any;
    testEnv.POW_SECRET = "test-secret";
    testEnv.DISCORD_BOT_TOKEN = "test-bot-token";
    testEnv.VERIFIED_ROLE_ID = "role-id";

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        return new Response("", { status: 204 });
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

      const ctx = createExecutionContext();
      const res = await worker.fetch(request, testEnv, ctx);
      await waitOnExecutionContext(ctx);
      expect(res.status).toBe(400);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("rejects when token role_id mismatches env", async () => {
    const testEnv = env as any;
    testEnv.POW_SECRET = "test-secret";
    testEnv.DISCORD_BOT_TOKEN = "test-bot-token";
    testEnv.VERIFIED_ROLE_ID = "role-id";

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        return new Response("", { status: 204 });
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

      const ctx = createExecutionContext();
      const res = await worker.fetch(request, testEnv, ctx);
      await waitOnExecutionContext(ctx);
      expect(res.status).toBe(400);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
