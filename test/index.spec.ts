import { describe, it, expect, vi } from "vitest";
import nacl from "tweetnacl";
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

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
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

// Hono forwards env bindings via app.fetch(req, env, ctx).
function fetchApp(request: Request, env: any): Promise<Response> {
  return worker.fetch(request, env);
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

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function signedInteractionRequest(
  interaction: Record<string, unknown>,
  keyPair: nacl.SignKeyPair,
  timestamp = Math.floor(Date.now() / 1000)
): IncomingRequest {
  const body = JSON.stringify(interaction);
  const signature = nacl.sign.detached(
    new TextEncoder().encode(String(timestamp) + body),
    keyPair.secretKey
  );
  return new IncomingRequest("http://example.com/interactions", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-signature-ed25519": bytesToHex(signature),
      "x-signature-timestamp": String(timestamp),
    },
    body,
  });
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
    const res = await fetchApp(request, env);
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

      const res1 = await fetchApp(request, testEnv);
      expect(res1.status).toBe(200);
      expect(await res1.json()).toEqual({ ok: true });

      const replayRequest = new IncomingRequest("http://example.com/api/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
      const res2 = await fetchApp(replayRequest, testEnv);
      expect(res2.status).toBe(409);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("allows a retry after a retryable role grant failure", async () => {
    const testEnv = createTestEnv();
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
    let discordCalls = 0;

    vi.stubGlobal("setTimeout", ((callback: () => void) => {
      callback();
      return 0;
    }) as any);
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        discordCalls += 1;
        return new Response(null, { status: discordCalls <= 3 ? 500 : 204 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    const makeRequest = () =>
      new IncomingRequest("http://example.com/api/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token, nonce: powNonce, user_id: "user", guild_id: "guild" }),
      });

    try {
      const firstResponse = await fetchApp(makeRequest(), testEnv);
      expect(firstResponse.status).toBe(503);

      const secondResponse = await fetchApp(makeRequest(), testEnv);
      expect(secondResponse.status).toBe(200);
      expect(discordCalls).toBe(5);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("finalizes the nonce when a successful role grant crosses the claim lease", async () => {
    const testEnv = createTestEnv({ VERIFIED_ROLE_ID: ADDITIONAL_VERIFIED_ROLE_ID_2026 });
    let discordCalls = 0;
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-13T00:00:00Z"));

    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://discord.com/api/v10/")) {
        discordCalls += 1;
        vi.setSystemTime(new Date(Date.now() + 31_000));
        return new Response(null, { status: 204 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    try {
      const diff = 1;
      const now = Math.floor(Date.now() / 1000);
      const token = await makeToken(
        testEnv.POW_SECRET,
        "guild",
        "user",
        testEnv.VERIFIED_ROLE_ID,
        now + 600,
        diff
      );
      const powNonce = await findPowNonce(token, diff);
      const body = JSON.stringify({ token, nonce: powNonce, user_id: "user", guild_id: "guild" });
      const makeRequest = () =>
        new IncomingRequest("http://example.com/api/submit", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body,
        });

      const firstResponse = await fetchApp(makeRequest(), testEnv);
      expect(firstResponse.status).toBe(200);

      const secondResponse = await fetchApp(makeRequest(), testEnv);
      expect(secondResponse.status).toBe(409);
      expect(discordCalls).toBe(1);
    } finally {
      vi.unstubAllGlobals();
      vi.useRealTimers();
    }
  });

  it("rejects completion from a claim replaced after its lease expires", async () => {
    const store = new NonceStore({ storage: new MemoryStorage() } as any);
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-13T00:00:00Z"));

    const post = (path: string, body: Record<string, unknown>) =>
      store.fetch(
        new Request(`https://nonce-store${path}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        })
      );

    try {
      const expiresAt = Math.floor(Date.now() / 1000) + 600;
      expect((await post("/claim", { expiresAt, claimId: "claim-a" })).status).toBe(200);

      vi.setSystemTime(new Date(Date.now() + 31_000));
      expect((await post("/claim", { expiresAt, claimId: "claim-b" })).status).toBe(200);
      expect((await post("/complete", { claimId: "claim-a" })).status).toBe(409);
      expect((await post("/complete", { claimId: "claim-b" })).status).toBe(200);
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects a token and nonce at their exact expiry second", async () => {
    const testEnv = createTestEnv();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-13T00:00:00Z"));

    try {
      const exp = Math.floor(Date.now() / 1000);
      const token = await makeToken(
        testEnv.POW_SECRET,
        "guild",
        "user",
        testEnv.VERIFIED_ROLE_ID,
        exp,
        1
      );
      const powNonce = await findPowNonce(token, 1);
      const request = new IncomingRequest("http://example.com/api/submit", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token, nonce: powNonce, user_id: "user", guild_id: "guild" }),
      });

      const response = await fetchApp(request, testEnv);
      expect(response.status).toBe(400);

      const store = new NonceStore({ storage: new MemoryStorage() } as any);
      const nonceResponse = await store.fetch(
        new Request("https://nonce-store/mark", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ expiresAt: exp }),
        })
      );
      expect(nonceResponse.status).toBe(400);
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects malformed, stale, and duplicate Discord interactions", async () => {
    const keyPair = nacl.sign.keyPair();
    const testEnv = createTestEnv({ DISCORD_PUBLIC_KEY: bytesToHex(keyPair.publicKey) });
    const interaction = { id: "interaction-1", type: 1 };
    const body = JSON.stringify(interaction);
    const now = Math.floor(Date.now() / 1000);

    const malformed = new IncomingRequest("http://example.com/interactions", {
      method: "POST",
      headers: {
        "x-signature-ed25519": "00",
        "x-signature-timestamp": String(now),
      },
      body,
    });
    expect((await fetchApp(malformed, testEnv)).status).toBe(401);

    const stale = signedInteractionRequest(interaction, keyPair, now - 301);
    expect((await fetchApp(stale, testEnv)).status).toBe(401);

    const valid = signedInteractionRequest(interaction, keyPair, now);
    expect((await fetchApp(valid, testEnv)).status).toBe(200);
    const duplicate = signedInteractionRequest(interaction, keyPair, now);
    expect((await fetchApp(duplicate, testEnv)).status).toBe(409);
  });

  it("disables pow_submit unless explicitly enabled", async () => {
    const keyPair = nacl.sign.keyPair();
    const testEnv = createTestEnv({ DISCORD_PUBLIC_KEY: bytesToHex(keyPair.publicKey) });
    const request = signedInteractionRequest(
      { id: "pow-submit-disabled", type: 2, data: { name: "pow_submit" }, guild_id: "guild", member: { user: { id: "user" } } },
      keyPair
    );

    const response = await fetchApp(request, testEnv);
    expect(response.status).toBe(200);
    expect((await response.json() as any).data.content).toBe("pow_submit is disabled.");
  });

  it("uses the configured default difficulty for mobile-origin interactions", async () => {
    const keyPair = nacl.sign.keyPair();
    const testEnv = createTestEnv({
      DISCORD_PUBLIC_KEY: bytesToHex(keyPair.publicKey),
      POW_DIFFICULTY_DEFAULT: "22",
      POW_DIFFICULTY_MOBILE: "1",
    });
    const request = signedInteractionRequest(
      { id: "mobile-difficulty", type: 2, data: { name: "pow" }, guild_id: "guild", member: { user: { id: "user" } } },
      keyPair
    );
    request.headers.set("user-agent", "Discord/1.0 (Android; Mobile)");

    const response = await fetchApp(request, testEnv);
    expect(response.status).toBe(200);
    expect((await response.json() as any).data.content).toContain("difficulty=22");
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

      const res = await fetchApp(request, testEnv);
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

      const res = await fetchApp(request, testEnv);
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

    const res = await fetchApp(request, testEnv);
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

      const res = await fetchApp(request, testEnv);
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

      const res = await fetchApp(request, testEnv);
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

      const res = await fetchApp(request, testEnv);
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

      const res = await fetchApp(request, testEnv);
      expect(res.status).toBe(400);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
