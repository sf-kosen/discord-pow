import {
  ADDITIONAL_ROLE_2027_START_MS,
  ADDITIONAL_VERIFIED_ROLE_ID_2026,
  ADDITIONAL_VERIFIED_ROLE_ID_2027,
  DISCORD_API_TIMEOUT_MS,
  ROLE_GRANT_BASE_DELAY_MS,
  ROLE_GRANT_COMPLETION_MARGIN_MS,
  ROLE_GRANT_MAX_ATTEMPTS,
  ROLE_GRANT_OPERATION_TIMEOUT_MS,
} from "../../lib/constants";
import type { Env } from "../../lib/env";
import { claimNonce, completeNonce, releaseNonce } from "../../nonce-store";

function isRetryableRoleGrantStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function logRoleGrantResult(input: {
  guildId: string;
  userId: string;
  roleId: string;
  nonceHash: string;
  result: "success" | "failure";
  status: number;
  attempts: number;
  retryable: boolean;
  reason?: string;
}) {
  console.log(
    JSON.stringify({
      event: "role_grant",
      guild_id: input.guildId,
      user_id: input.userId,
      role_id: input.roleId,
      nonce_hash: input.nonceHash,
      result: input.result,
      status: input.status,
      attempts: input.attempts,
      retryable: input.retryable,
      reason: input.reason,
    })
  );
}

function describeRoleGrantFailure(status: number): string {
  if (status === 403) return "missing permission or role hierarchy";
  if (status === 404) return "guild member or role not found";
  if (status === 429) return "discord rate limited";
  if (status >= 500) return "discord server error";
  return "discord rejected role grant";
}

function getAdditionalVerifiedRoleId(now = new Date()): string {
  if (now.getTime() >= ADDITIONAL_ROLE_2027_START_MS) return ADDITIONAL_VERIFIED_ROLE_ID_2027;
  return ADDITIONAL_VERIFIED_ROLE_ID_2026;
}

function getRoleIdsToGrant(env: Env): string[] {
  return Array.from(new Set([env.VERIFIED_ROLE_ID, getAdditionalVerifiedRoleId()]));
}

async function addRoleDetailed(
  env: Env,
  guildId: string,
  userId: string,
  roleId: string,
  deadlineMs: number
) {
  const url = `https://discord.com/api/v10/guilds/${guildId}/members/${userId}/roles/${roleId}`;
  const remainingMs = deadlineMs - Date.now() - ROLE_GRANT_COMPLETION_MARGIN_MS;
  if (remainingMs <= 0) {
    return { ok: false, status: 504, retryAfterSec: undefined };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(
    () => controller.abort(),
    Math.min(DISCORD_API_TIMEOUT_MS, remainingMs)
  );
  try {
    const r = await fetch(url, {
      method: "PUT",
      headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
      signal: controller.signal,
    });
    const retryAfterRaw = r.headers.get("retry-after");
    const retryAfter = retryAfterRaw ? Number(retryAfterRaw) : NaN;
    const retryAfterSec = Number.isFinite(retryAfter) ? retryAfter : undefined;
    return { ok: r.status === 204 || r.ok, status: r.status, retryAfterSec };
  } catch {
    return { ok: false, status: controller.signal.aborted ? 504 : 503, retryAfterSec: undefined };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function addRoleWithRetry(
  env: Env,
  guildId: string,
  userId: string,
  nonceHash: string,
  deadlineMs: number
): Promise<{ ok: boolean; status: number; attempts: number; retryable: boolean }> {
  let lastResult: { ok: boolean; status: number; attempts: number; retryable: boolean } | null = null;
  for (const roleId of getRoleIdsToGrant(env)) {
    const result = await addSingleRoleWithRetry(env, guildId, userId, roleId, nonceHash, deadlineMs);
    lastResult = result;
    if (!result.ok) return result;
  }
  return lastResult ?? { ok: true, status: 204, attempts: 0, retryable: false };
}

async function addSingleRoleWithRetry(
  env: Env,
  guildId: string,
  userId: string,
  roleId: string,
  nonceHash: string,
  deadlineMs: number
): Promise<{ ok: boolean; status: number; attempts: number; retryable: boolean }> {
  let lastStatus = 500;
  let lastRetryable = false;
  let attempts = 0;
  for (let attempt = 1; attempt <= ROLE_GRANT_MAX_ATTEMPTS; attempt++) {
    if (Date.now() >= deadlineMs - ROLE_GRANT_COMPLETION_MARGIN_MS) {
      lastStatus = 504;
      lastRetryable = true;
      break;
    }

    attempts = attempt;
    const res = await addRoleDetailed(env, guildId, userId, roleId, deadlineMs);
    lastStatus = res.status;
    lastRetryable = isRetryableRoleGrantStatus(res.status);
    if (res.ok) {
      logRoleGrantResult({
        guildId,
        userId,
        roleId,
        nonceHash,
        result: "success",
        status: res.status,
        attempts: attempt,
        retryable: false,
      });
      return { ok: true, status: res.status, attempts: attempt, retryable: false };
    }

    if (!lastRetryable || attempt == ROLE_GRANT_MAX_ATTEMPTS) break;

    let delayMs = ROLE_GRANT_BASE_DELAY_MS * Math.pow(2, attempt - 1);
    if (res.retryAfterSec && Number.isFinite(res.retryAfterSec)) {
      delayMs = Math.max(delayMs, Math.ceil(res.retryAfterSec * 1000));
    }
    const jitterMs = Math.floor(Math.random() * 100);
    const boundedDelayMs = delayMs + jitterMs;
    if (boundedDelayMs >= deadlineMs - Date.now() - ROLE_GRANT_COMPLETION_MARGIN_MS) break;
    await sleep(boundedDelayMs);
  }

  logRoleGrantResult({
    guildId,
    userId,
    roleId,
    nonceHash,
    result: "failure",
    status: lastStatus,
    attempts,
    retryable: lastRetryable,
    reason: describeRoleGrantFailure(lastStatus),
  });
  return {
    ok: false,
    status: lastStatus,
    attempts,
    retryable: lastRetryable,
  };
}

export async function grantRolesForVerifiedToken(
  env: Env,
  tokenNonce: string,
  expiresAt: number,
  guildId: string,
  userId: string
): Promise<{ ok: true } | { ok: false; status: number; msg: string }> {
  const deadlineMs = Math.min(
    Date.now() + ROLE_GRANT_OPERATION_TIMEOUT_MS,
    expiresAt * 1000
  );
  const claim = await claimNonce(env, tokenNonce, expiresAt);
  if (!claim.ok) return claim;

  const roleResult = await addRoleWithRetry(env, guildId, userId, claim.nonceHash, deadlineMs);
  if (!roleResult.ok) {
    const released = await releaseNonce(env, tokenNonce, claim.claimId);
    if (!released.ok) {
      console.error(
        JSON.stringify({
          event: "nonce_release_failed",
          nonce_hash: claim.nonceHash,
          status: released.status,
        })
      );
    }
    return {
      ok: false,
      status: roleResult.retryable ? 503 : 500,
      msg: "failed to add role",
    };
  }

  const completed = await completeNonce(env, tokenNonce, claim.claimId);
  if (!completed.ok) return { ok: false, status: 500, msg: "failed to finalize nonce" };
  return { ok: true };
}
