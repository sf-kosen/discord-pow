export function VerifyPage() {
  // tokenはURLフラグメント(#token=)から読む（サーバーに送られない）
  return (
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
          <p class="muted">
            進捗: <span id="progress">-</span>
          </p>
          <pre id="detail">-</pre>
          <p class="small muted">
            注意: 失敗する場合はBotの権限（Manage Roles）とロール階層（Botロールが対象ロールより上）を確認してください。
          </p>
        </div>
        <script src="/verify.js" defer></script>
      </body>
    </html>
  );
}

export function verifyPageHtml(): string {
  return `<!doctype html>\n${String(<VerifyPage />)}`;
}

export function verifyPageCss(): string {
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

export function verifyPageJs(): string {
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

        let r;
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 10000);
          try {
            r = await fetch("/api/submit", {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                token: token.trim(),
                nonce: String(msg.nonce).trim(),
                user_id: submitUserId,
                guild_id: submitGuildId,
              }),
              signal: controller.signal,
            });
          } finally {
            clearTimeout(timeoutId);
          }
        } catch (error) {
          setStatus("通信に失敗しました。もう一度お試しください。", "ng");
          detailEl.textContent += "network error: " + String(error) + "\\n";
          startBtn.disabled = false;
          return;
        }

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

export function verifyWorkerJs(): string {
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