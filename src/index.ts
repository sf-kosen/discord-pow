import nacl from "tweetnacl";

interface Env {
  DISCORD_PUBLIC_KEY: string; // hex
  DISCORD_BOT_TOKEN: string;
  VERIFIED_ROLE_ID: string;
  POW_SECRET: string;
  POW_COMMAND_NAME?: string;
  ENABLE_VERIFY_BUTTON?: string;
  NONCE_STORE: DurableObjectNamespace;
}

// まずはUX優先で軽め推奨（重ければ下げ、軽すぎれば上げる）
const POW_TTL_SEC = 600; // 10 min
const DIFFICULTY_DEFAULT = 20; // 16-20 range
const DIFFICULTY_MOBILE = 16;
const ROLE_GRANT_MAX_ATTEMPTS = 3;
const ROLE_GRANT_BASE_DELAY_MS = 200;

// -------------------- util --------------------
function hexToU8(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("invalid hex");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
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

async function sha256Base64Url(data: string): Promise<string> {
  return u8ToBase64Url(await sha256Utf8(data));
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

function constantTimeEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const ae = new TextEncoder().encode(a);
  const be = new TextEncoder().encode(b);
  let diff = 0;
  for (let i = 0; i < ae.length; i++) diff |= (ae[i] ^ be[i]);
  return diff === 0;
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      // 最低限のCSP（必要なら後で調整）
      "content-security-policy": "default-src 'self'; connect-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    },
  });
}

function js(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/javascript; charset=utf-8",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}

function css(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/css; charset=utf-8",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}


function getDifficultyForUserAgent(userAgent: string | null): number {
  const ua = (userAgent ?? "").toLowerCase();
  if (
    ua.includes("mobile") ||
    ua.includes("android") ||
    ua.includes("iphone") ||
    ua.includes("ipad")
  ) {
    return DIFFICULTY_MOBILE;
  }
  return DIFFICULTY_DEFAULT;
}

function isEnabled(value: string | undefined): boolean {
  if (value === undefined) return true;
  const v = value.trim().toLowerCase();
  return v !== "0" && v !== "false" && v !== "off";
}

function ephemeral(content: string) {
  return { type: 4, data: { content, flags: 64 } };
}

function ephemeralWithLink(content: string, url: string) {
  // Link button (style=5)
  return {
    type: 4,
    data: {
      content,
      flags: 64,
      components: [
        {
          type: 1,
          components: [{ type: 2, style: 5, label: "PoW認証を開始", url }],
        },
      ],
    },
  };
}

function ephemeralWithLinkLabel(content: string, url: string, label: string) {
  return {
    type: 4,
    data: {
      content,
      flags: 64,
      components: [
        {
          type: 1,
          components: [{ type: 2, style: 5, label, url }],
        },
      ],
    },
  };
}

function parseOptions(interaction: any): Record<string, any> {
  const opts = interaction?.data?.options ?? [];
  const out: Record<string, any> = {};
  for (const o of opts) out[o.name] = o.value;
  return out;
}

// -------------------- Discord verification --------------------
async function verifyDiscordSig(req: Request, env: Env, bodyText: string): Promise<boolean> {
  const sigHex = req.headers.get("x-signature-ed25519");
  const ts = req.headers.get("x-signature-timestamp");
  if (!sigHex || !ts) return false;

  const msg = new TextEncoder().encode(ts + bodyText);
  const sig = hexToU8(sigHex);
  const pub = hexToU8(env.DISCORD_PUBLIC_KEY);
  return nacl.sign.detached.verify(msg, sig, pub);
}

// -------------------- token / pow --------------------
async function makeToken(env: Env, guildId: string, userId: string, difficulty: number): Promise<string> {
  const ts = Math.floor(Date.now() / 1000);
  const exp = ts + POW_TTL_SEC;
  const tokenNonce = crypto.getRandomValues(new Uint8Array(16));
  const nonceB64u = u8ToBase64Url(tokenNonce);

  // pow.v1.nonce.guildId.userId.roleId.exp.diff.sig
  const payload = `pow.v1.${nonceB64u}.${guildId}.${userId}.${env.VERIFIED_ROLE_ID}.${exp}.${difficulty}`;
  const sig = await hmacSha256Base64Url(env.POW_SECRET, payload);
  return `${payload}.${sig}`;
}

function parseToken(token: string) {
  const parts = token.split(".");
  if (parts.length !== 9 || parts[0] !== "pow" || parts[1] !== "v1") return null;
  const payload = parts.slice(0, 8).join(".");
  return {
    nonce: parts[2],
    guildId: parts[3],
    userId: parts[4],
    roleId: parts[5],
    exp: Number(parts[6]),
    diff: Number(parts[7]),
    sig: parts[8],
    payload,
  };
}

async function verifyTokenAndPow(
  env: Env,
  tokenRaw: string,
  nonceRaw: string,
  expected?: { userId?: string; guildId?: string }
) {
  const token = tokenRaw.trim();
  const nonce = nonceRaw.trim();

  const parsed = parseToken(token);
  if (!parsed) return { ok: false, msg: "token形式が不正です。" as const };
  if (!parsed.nonce) return { ok: false, msg: "invalid token nonce" as const };

  if (!Number.isFinite(parsed.exp) || !Number.isFinite(parsed.diff)) {
    return { ok: false, msg: "tokenが壊れています。" as const };
  }

  const now = Math.floor(Date.now() / 1000);
  if (now > parsed.exp) {
    return { ok: false, msg: "期限切れです。Discordで /pow からやり直してください。" as const };
  }

  if (parsed.roleId !== env.VERIFIED_ROLE_ID) {
    return { ok: false, msg: "role mismatch" as const };
  }

  if (expected?.userId && expected.userId !== parsed.userId) {
    return { ok: false, msg: "user mismatch" as const };
  }

  if (expected?.guildId && expected.guildId !== parsed.guildId) {
    return { ok: false, msg: "guild mismatch" as const };
  }

  const expectedSig = await hmacSha256Base64Url(env.POW_SECRET, parsed.payload);
  if (!constantTimeEq(expectedSig, parsed.sig)) {
    return { ok: false, msg: "署名が不正です。" as const };
  }

  const h = await sha256Utf8(`${token}.${nonce}`);
  if (!hasLeadingZeroBits(h, parsed.diff)) {
    const hex4 = Array.from(h.slice(0, 4))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return {
      ok: false,
      msg: "PoWが不正です（条件未達）。" as const,
      debug: { diff: parsed.diff, hash_first4: hex4 },
    };
  }

  return {
    ok: true as const,
    guildId: parsed.guildId,
    userId: parsed.userId,
    tokenNonce: parsed.nonce,
    expiresAt: parsed.exp,
  };
}

async function checkAndMarkNonce(
  env: Env,
  tokenNonce: string,
  expiresAt: number
): Promise<{ ok: true } | { ok: false; status: number; msg: string }> {
  const nonceHash = await sha256Base64Url(tokenNonce);
  const id = env.NONCE_STORE.idFromName(nonceHash);
  const stub = env.NONCE_STORE.get(id);
  const res = await stub.fetch("https://nonce-store/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ expiresAt }),
  });

  if (res.status === 409) return { ok: false, status: 409, msg: "nonce already used" };
  if (!res.ok) return { ok: false, status: res.status, msg: "nonce check failed" };
  return { ok: true };
}

// -------------------- role grant --------------------
function isRetryableRoleGrantStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function logRoleGrantResult(input: {
  guildId: string;
  userId: string;
  nonceHash: string;
  result: "success" | "failure";
  status: number;
  attempts: number;
  retryable: boolean;
}) {
  console.log(
    JSON.stringify({
      event: "role_grant",
      guild_id: input.guildId,
      user_id: input.userId,
      nonce_hash: input.nonceHash,
      result: input.result,
      status: input.status,
      attempts: input.attempts,
      retryable: input.retryable,
    })
  );
}

async function addRoleDetailed(env: Env, guildId: string, userId: string) {
  const url = `https://discord.com/api/v10/guilds/${guildId}/members/${userId}/roles/${env.VERIFIED_ROLE_ID}`;
  const r = await fetch(url, {
    method: "PUT",
    headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
  });
  const retryAfterRaw = r.headers.get("retry-after");
  const retryAfter = retryAfterRaw ? Number(retryAfterRaw) : NaN;
  const retryAfterSec = Number.isFinite(retryAfter) ? retryAfter : undefined;
  return { ok: r.status === 204 || r.ok, status: r.status, retryAfterSec };
}

async function addRoleWithRetry(
  env: Env,
  guildId: string,
  userId: string,
  nonceHash: string
): Promise<{ ok: boolean; status: number; attempts: number; retryable: boolean }> {
  let lastStatus = 500;
  let lastRetryable = false;
  let attempts = 0;
  for (let attempt = 1; attempt <= ROLE_GRANT_MAX_ATTEMPTS; attempt++) {
    attempts = attempt;
    const res = await addRoleDetailed(env, guildId, userId);
    lastStatus = res.status;
    lastRetryable = isRetryableRoleGrantStatus(res.status);
    if (res.ok) {
      logRoleGrantResult({
        guildId,
        userId,
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
    await sleep(delayMs + jitterMs);
  }

  logRoleGrantResult({
    guildId,
    userId,
    nonceHash,
    result: "failure",
    status: lastStatus,
    attempts,
    retryable: lastRetryable,
  });
  return {
    ok: false,
    status: lastStatus,
    attempts,
    retryable: lastRetryable,
  };
}

// -------------------- verify page --------------------
function verifyPageHtml(): string {
  // tokenはURLフラグメント(#token=)から読む（サーバーに送られない）
  return `<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>PoW認証</title>
  <meta http-equiv="Cache-Control" content="no-store" />
  <link rel="stylesheet" href="/verify.css" />
</head>
<body>
  <h1>PoW認証</h1>
  <div class="card">
    <p class="muted">このページでPoWを計算し、完了すると自動でDiscordのロールが付与されます。</p>
    <div class="row">
      <button id="start">計算を開始</button>
      <span id="status" class="muted">待機中</span>
    </div>
    <p class="muted">進捗: <span id="progress">-</span></p>
    <pre id="detail">-</pre>
    <p class="small muted">注意: 失敗する場合はBotの権限（Manage Roles）とロール階層（Botロールが対象ロールより上）を確認してください。</p>
  </div>
  <script src="/verify.js" defer></script>
</body>
</html>`;
}


function verifyPageCss(): string {
  return `    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:820px;margin:40px auto;padding:0 16px;line-height:1.6}
    .card{border:1px solid #ddd;border-radius:12px;padding:16px}
    .row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
    button{padding:10px 14px;border-radius:10px;border:1px solid #333;background:#111;color:#fff;cursor:pointer}
    button:disabled{opacity:.5;cursor:not-allowed}
    .muted{color:#666}
    .ok{color:#0a7}
    .ng{color:#c33}
    pre{white-space:pre-wrap;word-break:break-all;background:#f7f7f7;padding:10px;border-radius:10px}
    .small{font-size:13px}`;
}

function verifyPageJs(): string {
  return `const startBtn = document.getElementById("start");
const statusEl = document.getElementById("status");
const progressEl = document.getElementById("progress");
const detailEl = document.getElementById("detail");

function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = cls || "muted";
}

function getTokenFromHash() {
  const h = location.hash || "";
  const m = h.match(/[#&]token=([^&]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

const token = (getTokenFromHash() || "").trim();
if (!token) {
  setStatus("URLが不正です（tokenなし）", "ng");
  startBtn.disabled = true;
  detailEl.textContent = "Discordで /pow を実行してURLを開き直してください。";
}

function parseTokenParts(tok) {
  const parts = tok.split(".");
  if (parts.length !== 9) return null;
  return {
    guildId: parts[3],
    userId: parts[4],
    roleId: parts[5],
    exp: Number(parts[6]),
    diff: Number(parts[7]),
  };
}

const parsed = token ? parseTokenParts(token) : null;
const diff = parsed ? parsed.diff : NaN;
const submitUserId = parsed ? String(parsed.userId ?? "").trim() : "";
const submitGuildId = parsed ? String(parsed.guildId ?? "").trim() : "";
if (token && (!parsed || !submitUserId || !submitGuildId || !Number.isFinite(diff))) {
  setStatus("token形式が不正です", "ng");
  startBtn.disabled = true;
  detailEl.textContent = "tokenが壊れている可能性があります。Discordで /pow をやり直してください。";
}

function makeWorker() {
  return new Worker("/verify-worker.js");
}

startBtn.onclick = async () => {
  startBtn.disabled = true;
  setStatus("計算中…（タブを閉じないでください）", "muted");
  detailEl.textContent = "difficulty=" + diff + "\\n";

  const n = Math.max(1, Math.min(navigator.hardwareConcurrency || 2, 8)); // 最大8並列
  detailEl.textContent += "workers=" + n + "\\n";

  let done = false;
  const workers = [];
  const startedAll = Date.now();

  function stopAll() {
    for (const w of workers) {
      try { w.postMessage({ type: "stop" }); w.terminate(); } catch {}
    }
  }

  for (let i = 0; i < n; i++) {
    const w = makeWorker();
    workers.push(w);

    w.onmessage = async (ev) => {
      const msg = ev.data;
      if (done) return;

      if (msg.type === "progress") {
        const elapsed = ((Date.now() - startedAll) / 1000).toFixed(1);
        progressEl.textContent = "≈ " + elapsed + "s (parallel " + n + ")";
        return;
      }

      if (msg.type === "found") {
        done = true;
        stopAll();

        progressEl.textContent = "nonce=" + msg.nonce + " / " + (msg.ms/1000).toFixed(1) + "s (worker)";
        detailEl.textContent += "nonce found: " + msg.nonce + "\\n送信中…\\n";
        setStatus("検証中…", "muted");

        const r = await fetch("/api/submit", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            token: token.trim(),
            nonce: String(msg.nonce).trim(),
            user_id: submitUserId,
            guild_id: submitGuildId,
          })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) {
          setStatus("失敗: " + ((j && (j.error || j.msg)) ? (j.error || j.msg) : ("HTTP " + r.status)), "ng");
          detailEl.textContent += "error: " + JSON.stringify(j) + "\\n";
          startBtn.disabled = false;
          return;
        }

        setStatus("認証完了（ロール付与済み）", "ok");
        detailEl.textContent += "done\\n";
      }
    };

    w.postMessage({ token, diff, start: i, step: n });
  }
};`;
}

function verifyWorkerJs(): string {
  return `
    function hasLeadingZeroBits(bytes, zeroBits) {
      let bits = zeroBits;
      for (let i = 0; i < bytes.length; i++) {
        if (bits <= 0) return true;
        const b = bytes[i];
        if (bits >= 8) { if (b !== 0) return false; bits -= 8; }
        else { const mask = 0xff << (8 - bits); return (b & mask) === 0; }
      }
      return bits <= 0;
    }

    async function sha256Utf8(str) {
      const enc = new TextEncoder();
      const buf = enc.encode(str);
      const digest = await crypto.subtle.digest("SHA-256", buf);
      return new Uint8Array(digest);
    }

    let stop = false;
    self.onmessage = async (e) => {
      const { token, diff, start, step } = e.data;
      let nonce = start;
      const started = Date.now();
      while (!stop) {
        const h = await sha256Utf8(token + "." + nonce);
        if (hasLeadingZeroBits(h, diff)) {
          self.postMessage({ type: "found", nonce, ms: Date.now() - started });
          return;
        }
        nonce += step;
        if (nonce % (step * 5000) === 0) {
          self.postMessage({ type: "progress", nonce, ms: Date.now() - started });
        }
      }
    };

    self.addEventListener("message", (e) => {
      if (e.data && e.data.type === "stop") stop = true;
    });
  `;
}

// -------------------- worker --------------------
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    // ---- Interactions ----
    if (url.pathname === "/interactions") {
      if (req.method !== "POST") return new Response("method not allowed", { status: 405 });

      const bodyText = await req.text();
      const okSig = await verifyDiscordSig(req, env, bodyText);
      if (!okSig) return new Response("invalid signature", { status: 401 });

      const interaction = JSON.parse(bodyText);
      const difficulty = getDifficultyForUserAgent(req.headers.get("user-agent"));

      // PING
      if (interaction.type === 1) return json({ type: 1 });

      // Message Component (button)
      if (interaction.type === 3) {
        if (!isEnabled(env.ENABLE_VERIFY_BUTTON)) {
          return json(ephemeral("現在この認証ボタンは無効です。"));
        }

        const customId = interaction.data?.custom_id;
        if (customId !== "pow_start") return json(ephemeral("未対応のボタンです。"));

        const guildId = interaction.guild_id ?? interaction.guild?.id;
        const userId = interaction.member?.user?.id ?? interaction.user?.id;
        if (!guildId || !userId) return json(ephemeral("サーバー内で実行してください。"));

        const token = await makeToken(env, guildId, userId, difficulty);
        const verifyUrl = `${url.origin}/verify#token=${encodeURIComponent(token)}`;
        const content =
          "リンクを開いてPoWを完了してください（完了後に自動でロールが付きます）。";

        return json(ephemeralWithLinkLabel(content, verifyUrl, "PoWを解く"));
      }

      // Slash command
      if (interaction.type === 2) {
        const name = interaction.data?.name;
        const guildId = interaction.guild_id;
        const userId = interaction?.member?.user?.id;
        const cmd = env.POW_COMMAND_NAME ?? "pow";

        if (!guildId || !userId) return json(ephemeral("このコマンドはサーバー内で実行してください。"));

        if (name === cmd) {
          const token = await makeToken(env, guildId, userId, difficulty);
          // tokenは#（フラグメント）へ。
          const verifyUrl = `${url.origin}/verify#token=${encodeURIComponent(token)}`;

          const content =
            `PoW認証URLを発行しました（有効 ${POW_TTL_SEC}s / difficulty=${difficulty}）。\n` +
            `ボタンから開いて計算すると自動でロールが付与されます。`;

          return json(ephemeralWithLink(content, verifyUrl));
        }

        // 互換: 手動提出用（コマンドが残っていても壊れない）
        if (name === "pow_submit") {
          const opts = parseOptions(interaction);
          const token = String((opts.token ?? opts.challenge ?? "")).trim();
          const nonce = String((opts.nonce ?? "")).trim();
          if (!token || !nonce) return json(ephemeral("token(challenge) と nonce を指定してください。"));

          const v = await verifyTokenAndPow(env, token, nonce, { userId, guildId });
          if (!v.ok) return json(ephemeral(v.msg));

          const nonceCheck = await checkAndMarkNonce(env, v.tokenNonce, v.expiresAt);
          if (!nonceCheck.ok) return json(ephemeral(nonceCheck.msg));
          const nonceHash = await sha256Base64Url(v.tokenNonce);
          const res = await addRoleWithRetry(env, v.guildId, v.userId, nonceHash);
          if (!res.ok) {
            return json(ephemeral("Failed to add role. status=" + res.status));
          }
          return json(ephemeral("Role granted."));
        }

        return json(ephemeral("未対応のコマンドです。"));
      }

      return json(ephemeral("未対応のリクエストです。"));
    }

    // ---- Verify page ----
    if (url.pathname === "/verify") {
      return html(verifyPageHtml());
    }
    if (url.pathname === "/verify.js") {
      return js(verifyPageJs());
    }
    if (url.pathname === "/verify-worker.js") {
      return js(verifyWorkerJs());
    }
    if (url.pathname === "/verify.css") {
      return css(verifyPageCss());
    }

    // ---- Submit ----
    if (url.pathname === "/api/submit") {
      if (req.method !== "POST") return new Response("method not allowed", { status: 405 });

      let body: any;
      try {
        body = await req.json();
      } catch {
        return json({ ok: false, error: "invalid json" }, 400);
      }

      const token = String(body?.token ?? "").trim();
      const nonce = String(body?.nonce ?? "").trim();
      const submitUserId = String(body?.user_id ?? "").trim();
      const submitGuildId = String(body?.guild_id ?? "").trim();
      if (!token || !nonce || !submitUserId || !submitGuildId) {
        return json({ ok: false, error: "missing token/nonce/user_id/guild_id" }, 400);
      }

      const v = await verifyTokenAndPow(env, token, nonce, {
        userId: submitUserId,
        guildId: submitGuildId,
      });
      if (!v.ok) return json({ ok: false, error: v.msg, debug: (v as any).debug }, 400);

      const nonceCheck = await checkAndMarkNonce(env, v.tokenNonce, v.expiresAt);
      if (!nonceCheck.ok) return json({ ok: false, error: nonceCheck.msg }, nonceCheck.status);
      const nonceHash = await sha256Base64Url(v.tokenNonce);
      const res = await addRoleWithRetry(env, v.guildId, v.userId, nonceHash);
      if (!res.ok) {
        return json({ ok: false, error: "failed to add role", status: res.status }, 500);
      }

      return json({ ok: true });
    }

    return new Response("not found", { status: 404 });
  },
};

export class NonceStore {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(req: Request): Promise<Response> {
    if (req.method !== "POST") return new Response("method not allowed", { status: 405 });

    let body: any;
    try {
      body = await req.json();
    } catch {
      return new Response("invalid json", { status: 400 });
    }

    const expiresAt = Number(body?.expiresAt ?? 0);
    if (!Number.isFinite(expiresAt) || expiresAt <= 0) {
      return new Response("invalid expiresAt", { status: 400 });
    }

    const now = Math.floor(Date.now() / 1000);
    if (now > expiresAt) return new Response("expired", { status: 400 });

    const existing = await this.state.storage.get("used");
    if (existing) return new Response("used", { status: 409 });

    await this.state.storage.put("used", { usedAt: now }, { expiration: expiresAt });
    return new Response("ok");
  }
}
