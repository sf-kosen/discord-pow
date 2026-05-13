# discord-pow

Cloudflare Workers 上で動く、PoW 形式の Discord ロール認証。`/pow` を実行すると短時間有効の PoW トークンを発行し、ブラウザで計算が完了すると Worker がロールを付与します。

## 特徴
- `/pow` スラッシュコマンドで短時間有効の PoW トークンを発行
- ブラウザ側で PoW を計算（クライアントのインストール不要）
- HMAC 署名トークンの検証とロール付与

## 要件
- Node.js + npm
- Cloudflare Workers + Wrangler v4
- Discord アプリケーション + Bot（"Manage Roles" 権限）

## セットアップ
1) 依存関係をインストール
```bash
npm install
```

2) Guild コマンドを登録
```bash
# PowerShell 例
$env:DISCORD_APPLICATION_ID="<app_id>"
# 互換: $env:DISCORD_APP_ID="<app_id>"
$env:DISCORD_GUILD_ID="<guild_id>"
$env:DISCORD_BOT_TOKEN="<bot_token>"
# 任意: $env:POW_COMMAND_NAME="pow"
node register_commands.mjs
```

3) Worker の secrets を設定
```bash
wrangler secret put DISCORD_PUBLIC_KEY
wrangler secret put DISCORD_BOT_TOKEN
wrangler secret put VERIFIED_ROLE_ID
wrangler secret put POW_SECRET
```

4) デプロイ
```bash
wrangler deploy
```

5) Discord の Interaction エンドポイントを設定
- `https://<your-worker-domain>/interactions`

## #verify 常設ボタン（認証開始）
1) 常設メッセージを投稿
```bash
# PowerShell 例
$env:VERIFY_CHANNEL_ID="<verify_channel_id>"
$env:DISCORD_BOT_TOKEN="<bot_token>"
npm run post:verify
```

2) 動作確認
- #verify の「認証開始」を押すと、ephemeral で「PoWを解く」ボタンが出る
- そのリンクで PoW を解くとロールが付与される
- `/pow` でも従来通り動作する

補足
- 必要なら `ENABLE_VERIFY_BUTTON=false` を vars に設定してボタンを無効化できる
- 互換用の `/pow_submit` を使う場合のみ `ENABLE_POW_SUBMIT=true` を vars に設定する

## v2 並行稼働
1) Discord Developer Portal で v2 用の Application / Bot を作成

2) v2 用コマンド登録（POW_COMMAND_NAME は pow2 など推奨）
```bash
# PowerShell 例
$env:DISCORD_APPLICATION_ID="<v2_app_id>"
$env:DISCORD_GUILD_ID="<guild_id>"
$env:DISCORD_BOT_TOKEN="<v2_bot_token>"
$env:POW_COMMAND_NAME="pow2"
npm run register:v2
```

3) v2 Worker の secrets を設定（必ず --env v2 を付ける）
```bash
wrangler secret put DISCORD_PUBLIC_KEY --env v2
wrangler secret put DISCORD_BOT_TOKEN --env v2
wrangler secret put VERIFIED_ROLE_ID --env v2
wrangler secret put POW_SECRET --env v2
```

4) v2 デプロイ
```bash
npm run deploy:v2
```

5) v2 の Interaction エンドポイントを設定
- `https://<your-v2-worker-domain>/interactions`

注意
- 旧Bot（v1）には触らない
- 本番Guildに入れるなら v2 のコマンド名は `/pow2` や `/pow-beta` を推奨
- v2 の検証は別Guild推奨

## 使い方
- サーバー内で `/pow` を実行
- 表示された URL を開き、PoW が完了すると自動でロールが付与されます

## 脅威モデル / 運用メモ
- リプレイ対策: token内のnonceはワンタイム（TTL内でも再利用不可）
- 防げること: token改ざん、別ユーザー/ギルド/ロールへの転用、単純な連打の抑止
- 防げないこと: GPU/分散での高速解、アカウント共有・代理解、PoWの完全迂回
- difficulty目安: まずはPC=20、スマホ=16あたりから開始し、体感時間に合わせて調整
- レート制限推奨: `/interactions` と `/api/submit` にWAF/Rate Limitを適用

## 設定
- `src/index.ts`:
  - `POW_TTL_SEC` トークンの有効期限（秒、未指定時 600）
  - `POW_DIFFICULTY_DEFAULT` / `POW_DIFFICULTY_MOBILE` PoW 難易度（先頭 0 ビット数、未指定時 20 / 16）
  - `ALLOWED_GUILD_IDS` 許可するGuild IDのカンマ区切り。未指定時は制限なし
  - `INTERACTIONS_RATE_LIMIT_PER_MIN` `/interactions` のIP単位レート制限。未指定時 60/min、0で無効
  - `SUBMIT_RATE_LIMIT_PER_MIN` `/api/submit` のIP単位レート制限。未指定時 20/min、0で無効
  - `ENABLE_VERIFY_BUTTON=false` で常設ボタンを無効化
  - `ENABLE_POW_SUBMIT=true` で互換用 `/pow_submit` を有効化

## Secrets
- `DISCORD_PUBLIC_KEY`
- `DISCORD_BOT_TOKEN`
- `VERIFIED_ROLE_ID`
- `POW_SECRET`

## エンドポイント
- `POST /interactions`: Discord interaction handler
- `GET /verify`: PoW ページ
- `POST /api/submit`: PoW 提出エンドポイント

## 防御実装メモ
- `/interactions` と `/api/submit` は `NONCE_STORE` Durable Object を使って固定窓のレート制限を行います
- token nonce は `NONCE_STORE` に保存され、期限内の再利用は `409` で拒否されます
- `ALLOWED_GUILD_IDS` を設定すると、想定外Guildからの発行・提出を拒否できます
- レスポンスには `no-store`, `no-referrer`, `nosniff`, `Permissions-Policy`, `COOP`, `CORP` を付与しています

## 注意
- Bot ロールが付与対象ロールより上位にあることを確認してください
- `VERIFIED_ROLE_ID` は学生ロール ID を指定します
- 認証成功時は学生ロールに加えて、2026年中は `1455864840630308925`、2027年以降は `1504117815333093426` のロールも付与します

## License / ライセンス
MIT License. See `LICENSE`.
MIT License（詳細は `LICENSE`）
