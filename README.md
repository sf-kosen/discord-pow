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

2) Guild コマンドを登録（テストに最速）
```bash
# PowerShell 例
$env:DISCORD_APP_ID="<app_id>"
$env:DISCORD_GUILD_ID="<guild_id>"
$env:DISCORD_BOT_TOKEN="<bot_token>"
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

## 使い方
- サーバー内で `/pow` を実行
- 表示された URL を開き、PoW が完了すると自動でロールが付与されます

## 設定
- `src/index.ts`:
  - `POW_TTL_SEC` トークンの有効期限（秒）
  - `DIFFICULTY` PoW 難易度（先頭 0 ビット数）

## エンドポイント
- `POST /interactions`: Discord interaction handler
- `GET /verify`: PoW ページ
- `POST /api/submit`: PoW 提出エンドポイント

## 注意
- Bot ロールが付与対象ロールより上位にあることを確認してください
- `VERIFIED_ROLE_ID` は付与したいロール ID を指定します

## License / ライセンス
MIT License. See `LICENSE`.
MIT License（詳細は `LICENSE`）
