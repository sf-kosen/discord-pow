import { NONCE_CLAIM_LEASE_SEC, RATE_LIMIT_WINDOW_SEC } from "./lib/constants";
import { sha256Base64Url, u8ToBase64Url } from "./lib/crypto";
import type { Env } from "./lib/env";

// -------------------- client helpers (repositories call these) --------------------

export async function checkRateLimit(
  env: Env,
  key: string,
  limit: number,
  windowSec = RATE_LIMIT_WINDOW_SEC
): Promise<{ ok: true } | { ok: false; retryAfterSec: number }> {
  if (limit <= 0) return { ok: true };
  const keyHash = await sha256Base64Url(key);
  const id = env.NONCE_STORE.idFromName(`rate:${keyHash}`);
  const stub = env.NONCE_STORE.get(id);
  const res = await stub.fetch("https://nonce-store/rate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ limit, windowSec }),
  });
  if (res.status !== 429) return { ok: true };
  const retryAfterSec = Number(res.headers.get("retry-after") ?? windowSec);
  return { ok: false, retryAfterSec };
}

export async function claimNonce(
  env: Env,
  tokenNonce: string,
  expiresAt: number
): Promise<{ ok: true; claimId: string; nonceHash: string } | { ok: false; status: number; msg: string }> {
  const nonceHash = await sha256Base64Url(tokenNonce);
  const id = env.NONCE_STORE.idFromName(nonceHash);
  const stub = env.NONCE_STORE.get(id);
  const claimId = u8ToBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const res = await stub.fetch("https://nonce-store/claim", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ expiresAt, claimId }),
  });

  if (res.status === 409) return { ok: false, status: 409, msg: "nonce already used or processing" };
  if (!res.ok) return { ok: false, status: res.status, msg: "nonce check failed" };
  return { ok: true, claimId, nonceHash };
}

export async function completeNonce(
  env: Env,
  tokenNonce: string,
  claimId: string
): Promise<{ ok: true } | { ok: false; status: number; msg: string }> {
  const nonceHash = await sha256Base64Url(tokenNonce);
  const id = env.NONCE_STORE.idFromName(nonceHash);
  const stub = env.NONCE_STORE.get(id);
  const res = await stub.fetch("https://nonce-store/complete", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ claimId }),
  });

  if (!res.ok) return { ok: false, status: res.status, msg: "nonce completion failed" };
  return { ok: true };
}

export async function releaseNonce(
  env: Env,
  tokenNonce: string,
  claimId: string
): Promise<{ ok: true } | { ok: false; status: number; msg: string }> {
  const nonceHash = await sha256Base64Url(tokenNonce);
  const id = env.NONCE_STORE.idFromName(nonceHash);
  const stub = env.NONCE_STORE.get(id);
  const res = await stub.fetch("https://nonce-store/release", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ claimId }),
  });

  if (!res.ok) return { ok: false, status: res.status, msg: "nonce release failed" };
  return { ok: true };
}

export async function markInteraction(
  env: Env,
  interactionId: string,
  expiresAt: number
): Promise<{ ok: true } | { ok: false; status: number; msg: string }> {
  const interactionHash = await sha256Base64Url(interactionId);
  const id = env.NONCE_STORE.idFromName(`interaction:${interactionHash}`);
  const stub = env.NONCE_STORE.get(id);
  const res = await stub.fetch("https://nonce-store/mark", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ expiresAt }),
  });

  if (res.status === 409) return { ok: false, status: 409, msg: "interaction already processed" };
  if (!res.ok) return { ok: false, status: res.status, msg: "interaction replay check failed" };
  return { ok: true };
}

// -------------------- Durable Object --------------------

export class NonceStore {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(req: Request): Promise<Response> {
    if (req.method !== "POST") return new Response("method not allowed", { status: 405 });
    const url = new URL(req.url);

    let body: any;
    try {
      body = await req.json();
    } catch {
      return new Response("invalid json", { status: 400 });
    }

    if (url.pathname === "/rate") {
      return this.handleRateLimit(body);
    }

    if (url.pathname === "/claim") {
      return this.handleClaim(body);
    }
    if (url.pathname === "/complete") {
      return this.handleComplete(body);
    }
    if (url.pathname === "/release") {
      return this.handleRelease(body);
    }
    if (url.pathname === "/mark" || url.pathname === "/check") {
      // /check remains supported for older Worker revisions during rollout.
      if (url.pathname === "/check" && body?.claimId) return this.handleClaim(body);
      return this.handleMark(body);
    }

    return new Response("not found", { status: 404 });
  }

  private async withConcurrencyLock<T>(callback: () => Promise<T>): Promise<T> {
    const state = this.state as DurableObjectState & {
      blockConcurrencyWhile?: <R>(callback: () => Promise<R>) => Promise<R>;
    };
    if (typeof state.blockConcurrencyWhile === "function") {
      return state.blockConcurrencyWhile(callback);
    }
    return callback();
  }

  private async handleClaim(body: any): Promise<Response> {
    const expiresAt = Number(body?.expiresAt ?? 0);
    const claimId = String(body?.claimId ?? "");
    if (!Number.isFinite(expiresAt) || expiresAt <= 0 || !claimId) {
      return new Response("invalid claim", { status: 400 });
    }

    return this.withConcurrencyLock(async () => {
      const now = Math.floor(Date.now() / 1000);
      if (now >= expiresAt) return new Response("expired", { status: 400 });

      const existing = await this.state.storage.get<any>("used");
      if (existing && Number(existing.expiresAt ?? 0) > now) {
        const processing = existing.status === "processing";
        const leaseUntil = Number(existing.leaseUntil ?? 0);
        if (!processing || !Number.isFinite(leaseUntil) || leaseUntil > now) {
          return new Response("used", { status: 409 });
        }
      }

      await this.state.storage.put("used", {
        status: "processing",
        claimId,
        claimedAt: now,
        leaseUntil: Math.min(expiresAt, now + NONCE_CLAIM_LEASE_SEC),
        expiresAt,
      });
      return new Response("ok");
    });
  }

  private async handleComplete(body: any): Promise<Response> {
    const claimId = String(body?.claimId ?? "");
    if (!claimId) return new Response("invalid claim", { status: 400 });

    return this.withConcurrencyLock(async () => {
      const now = Math.floor(Date.now() / 1000);
      const existing = await this.state.storage.get<any>("used");
      if (existing?.status === "used" && Number(existing.expiresAt ?? 0) > now) {
        return existing.claimId === claimId
          ? new Response("ok")
          : new Response("claim mismatch", { status: 409 });
      }
      if (!existing || existing.status !== "processing" || existing.claimId !== claimId) {
        return new Response("claim mismatch", { status: 409 });
      }
      if (now >= Number(existing.expiresAt ?? 0)) {
        return new Response("expired", { status: 400 });
      }
      // A late completion is safe while no newer claim has replaced this owner.
      await this.state.storage.put("used", {
        status: "used",
        claimId,
        usedAt: now,
        expiresAt: existing.expiresAt,
      });
      return new Response("ok");
    });
  }

  private async handleRelease(body: any): Promise<Response> {
    const claimId = String(body?.claimId ?? "");
    if (!claimId) return new Response("invalid claim", { status: 400 });

    return this.withConcurrencyLock(async () => {
      const existing = await this.state.storage.get<any>("used");
      if (!existing) return new Response("ok");
      if (existing.status !== "processing" || existing.claimId !== claimId) {
        return new Response("claim mismatch", { status: 409 });
      }

      await this.state.storage.delete("used");
      return new Response("ok");
    });
  }

  private async handleMark(body: any): Promise<Response> {
    const expiresAt = Number(body?.expiresAt ?? 0);
    if (!Number.isFinite(expiresAt) || expiresAt <= 0) {
      return new Response("invalid expiresAt", { status: 400 });
    }

    return this.withConcurrencyLock(async () => {
      const now = Math.floor(Date.now() / 1000);
      if (now >= expiresAt) return new Response("expired", { status: 400 });

      const existing = await this.state.storage.get<any>("used");
      if (existing && Number(existing.expiresAt ?? 0) > now) {
        return new Response("used", { status: 409 });
      }

      await this.state.storage.put("used", { status: "used", usedAt: now, expiresAt });
      return new Response("ok");
    });
  }

  private async handleRateLimit(body: any): Promise<Response> {
    const limit = Number(body?.limit ?? 0);
    const windowSec = Number(body?.windowSec ?? RATE_LIMIT_WINDOW_SEC);
    if (!Number.isFinite(limit) || limit <= 0) return new Response("ok");
    if (!Number.isFinite(windowSec) || windowSec <= 0) {
      return new Response("invalid windowSec", { status: 400 });
    }

    const now = Math.floor(Date.now() / 1000);
    const bucket = await this.state.storage.get<{ count: number; resetAt: number }>("rate");
    const current =
      bucket && bucket.resetAt > now
        ? bucket
        : { count: 0, resetAt: now + Math.floor(windowSec) };

    if (current.count >= limit) {
      const retryAfter = Math.max(1, current.resetAt - now);
      return new Response("rate limited", {
        status: 429,
        headers: { "retry-after": String(retryAfter) },
      });
    }

    current.count += 1;
    await this.state.storage.put("rate", current);
    return new Response("ok");
  }
}
