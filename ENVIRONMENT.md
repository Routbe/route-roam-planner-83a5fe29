# Environment variables

## Deploy to Vercel (GitHub)

1. Import the GitHub repo in Vercel. Framework preset: **Other**. Use the committed `vercel.json`: build command **`bun run build:vercel`**, output directory unset. The build first runs `scripts/check-release-env.ts`, then `NITRO_PRESET=vercel vite build` selects the Nitro Vercel preset (Build Output API, `.vercel/output`). Security headers (HSTS, CSP with frame-ancestors, nosniff, Referrer-Policy, COOP/COEP on /secure) come only from `src/lib/security-headers.ts` at runtime; `vercel.json` deliberately adds none, because a second CSP or frame header would be intersected by browsers and break route-specific policies. Lovable keeps its managed preview target. Verify `.vercel/output/config.json` in the Vercel build before promoting a release; a Vercel deployment has not been verified here.
2. Paste every variable from *Required on Vercel* below, plus the optional groups you use, in Vercel → Settings → Environment Variables (Production and Preview).
3. Review pending `db/NNNN_*.sql` migrations separately. Never run owner-level migrations automatically in a Vercel build. Use the Neon gateway migration workflow or the Neon SQL editor after reviewing the exact statements; then run `bun run db:check` using gateway credentials (schema drift against `db/schema.snapshot.json`). Never apply these scripts to Lovable Cloud.
4. Point each OAuth provider's callback to `<PUBLIC_ORIGIN>/api/auth/callback/<provider>` (using the normalized HTTPS origin).
5. A daily scheduler must call `/api/public/cron/cleanup-assets`; the committed `vercel.json` schedules it at 03:00 UTC (other hosts: any external scheduler). Configure **`CRON_SECRET`** in Vercel: Vercel sends it as a bearer token. `LOVABLE_CRON_SECRET` is the handler's fallback for other schedulers. Other queues, including outbound webhooks and audit checkpoints, need their own reviewed schedules; the daily cleanup does not deliver webhooks.

`NODE_ENV` is set by Vercel; never set it yourself.

## Required for release validation

- `DATABASE_URL` — Server-only Neon PostgreSQL URL, read at request time when gateway credentials are absent. Configure it in Vercel Production (and Preview when used), then redeploy; a build-only variable cannot supply a running server.
- `PUBLIC_ORIGIN` — Canonical authentication origin. Valid HTTPS URLs are normalized to their origin, including URLs with trailing slashes or paths. Invalid formatting warns rather than blocking compilation.

## Additional runtime requirements (not build gates)

- `LOVABLE_API_KEY` / `NEON_API_KEY` — Optional linked-gateway transport (preferred when both exist), not required for DATABASE_URL deployments. Never prefix secrets with `VITE_`.
- `BETTER_AUTH_SECRET` — Signs sessions. 32+ random characters, identical on every deploy (changing it signs everyone out).
- `BETTER_AUTH_URL` — Public base URL, e.g. https://rout.be (no trailing slash).
- `NEXT_PUBLIC_APP_URL` — Same public URL; used for auth callbacks and links in emails.
- `PUBLIC_SITE_URL` — Public URL used in share links and metadata.
- `PUBLIC_ORIGIN` takes precedence over legacy authentication URL aliases for callbacks, trusted origins and passkeys. Cookies remain Secure, HttpOnly, SameSite=Lax and host-only.

## Database at runtime

- Both database transports, Better Auth sessions, and ALTCHA replay checks use the same atomic adapter. Every batch switches to `rout_app`, sets transaction-local caller context, and verifies the role is neither owner, superuser, nor RLS-bypassing. The database must contain the reviewed schema and grant the runtime login permission to use `rout_app`; code never invents missing credentials or bypasses this guard.
- `MIGRATION_URL` — Legacy local migration tooling only; not a runtime credential and not needed on Vercel. Prefer the reviewed gateway/Neon SQL editor workflow.

## Release verification

Run `bun run release:check` in a secure environment with the intended deployment settings. It prints only missing setting names and configuration errors, never values. Run `bun run test -- --maxWorkers=2` and `bunx tsgo --noEmit` before release. Required setting presence is not evidence that credentials work.

The release validator requires only DATABASE_URL and PUBLIC_ORIGIN. The runtime reads credentials lazily; passing a release check is not evidence of database reachability. Use your actual HTTPS domain and register its callbacks with each enabled provider. Keep signing/encryption keys stable when deployments share a database. Use a separate isolated database and matching keys for an independent preview environment.

### Known release blockers

- The current linked Neon connection uses an owner role and is rejected; link a `rout_app` connection before testing authenticated flows.
- Better Auth uses the shared Kysely atomic adapter with interactive transactions disabled. Real signup/sign-in/callback tests on Vercel are required before declaring authentication release-ready; never fake `BEGIN`/`COMMIT` success.
- Storage, mail delivery, payments, Wallet signatures and provider callbacks require real credentials and an end-to-end check on the deployed domain.
- The Vercel account, domain/DNS, production secret values and deployed build output have not been inspected here.

## Secrets (32+ random characters each)

- `APP_SESSION_SECRET` — Server-only random secret.
- `SESSION_SECRET` — Server-only random secret.
- `OAUTH_STATE_SECRET` — Server-only random secret.
- `MASTODON_STATE_SECRET` — Server-only random secret.
- `NEON_AUTH_COOKIE_SECRET` — Server-only random secret.
- `BOOKING_TOKEN_SECRET` — Server-only random secret.
- `GO_LINK_SECRET` — Server-only random secret.
- `ALTCHA_HMAC_KEY` — Server-only random secret.
- `CONTACT_HASH_SALT` — Server-only random secret.
- `BOOKING_HMAC_KEY` — Server-only random secret; hashes external calendar event ids (booking engine).
- `ADMIN_BOOTSTRAP_TOKEN` — Server-only random secret.
- `LOVABLE_CRON_SECRET` — Server-only random secret.
- `CRON_SECRET` — Required for Vercel's scheduled cleanup; Vercel sends a bearer header. Avoid query-string secrets.
- `TELEGRAM_BOT_TOKEN` — Server-only BotFather token for the phone-verification bot (`/api/public/telegram/webhook`).

## Sign-in providers (optional; tile shows a notice when missing)

- `GOOGLE_CLIENT_ID` — OAuth app credential.
- `GOOGLE_CLIENT_SECRET` — OAuth app credential.
- `APPLE_CLIENT_ID` — OAuth app credential.
- `APPLE_CLIENT_SECRET` — OAuth app credential.
- `APPLE_APP_BUNDLE_IDENTIFIER` — OAuth app credential.
- `GITHUB_CLIENT_ID` — OAuth app credential.
- `GITHUB_CLIENT_SECRET` — OAuth app credential.
- `GITHUB_TOKEN` (alias `GITHUB_PUBLIC_TOKEN`) — optional server-side token so keyless GitHub profile cards avoid rate limits.
- `GITLAB_CLIENT_ID` — OAuth app credential.
- `GITLAB_CLIENT_SECRET` — OAuth app credential.
- `INFOMANIAK_CLIENT_ID` — OAuth app credential.
- `INFOMANIAK_CLIENT_SECRET` — OAuth app credential.
- `PROTON_CLIENT_ID`, `PROTON_CLIENT_SECRET`, `PROTON_DISCOVERY_URL` — Proton OIDC (scopes openid profile email); callback `/api/auth/oauth2/callback/proton`. Proton offers no public OIDC for third parties yet; stays inactive until all three are set.
- `OIDC_CLIENT_ID` — External Keycloak-compatible provider credential (optional).
- `OIDC_CLIENT_SECRET` — External Keycloak-compatible provider credential (optional).
- `OIDC_DISCOVERY_URL` — External Keycloak-compatible provider credential (optional). Without all three, "ROUT ID" uses our own native OIDC provider (`/.well-known/openid-configuration`, first-party PKCE client `rout_native_self`, db/78) — no external keys needed.

## Login via ROUT (provider role)

- `ROUT_PROVIDER_PAIRWISE_SECRET` — Server-only, 32+ random characters, immutable across deployments. HMAC secret for pairwise OIDC subjects. Rotating it changes every pairwise identity; never derive it from the signing KEK or client secrets.

- `ROUT_CLIENT_ID` — ROUT as identity provider.
- `ROUT_CLIENT_SECRET` — ROUT as identity provider.
- `ROUT_API_KEY` — ROUT as identity provider.

## File storage (Scaleway)

- `SCALEWAY_ACCESS_KEY` — Scaleway Object Storage.
- `SCALEWAY_SECRET_KEY` — Scaleway Object Storage.
- `SCALEWAY_ENDPOINT` — Scaleway Object Storage.
- `SCALEWAY_REGION` — Scaleway Object Storage.
- `SCALEWAY_DEFAULT_BUCKET` — Scaleway Object Storage.
- `SCALEWAY_CLIENT_BUCKET` — Member profile photos and uploaded media, plus per-member key documents: `users/<uid>/prekey-bundle.json` and `users/<uid>/booking-key.json`, and sealed profile-card requests at `users/<uid>/inquiries/<pid>.json`. Without it no host can publish a booking key, so every booking page and every profile-card request form refuses new requests (`host_key_missing`).
- `SCALEWAY_INTERNAL_BUCKET` — ROUT-owned assets; never member uploads.

## Email

- `BREVO_API_KEY` — Transactional email / forwarding.
- `BREVO_SENDER_EMAIL` — Transactional email / forwarding.
- `BREVO_SENDER_NAME` — Transactional email / forwarding.
- `BREVO_REPLY_TO_EMAIL` — Transactional email / forwarding.
- `BREVO_ADMIN_EMAIL` — Transactional email / forwarding.
- `BREVO_SMS_SENDER` — Transactional email / forwarding.
- `EMAIL_FROM` — Transactional email / forwarding.
- `IMPROVMX_API_KEY` — Transactional email / forwarding.
- `CONTACT_ADMIN_EMAIL` — Transactional email / forwarding.
- `ADMIN_EMAIL` — Transactional email / forwarding.
- `OWNER_EMAILS` — Transactional email / forwarding.

## Payments

- `STRIPE_SECRET_KEY` — Payments and payouts.
- `STRIPE_PUBLISHABLE_KEY` — Payments and payouts.
- `STRIPE_WEBHOOK_SECRET` — Payments and payouts.
- `BUNQ_API_KEY` — Payments and payouts.
- `BUNQ_ENV` — Payments and payouts.
- `BUNQ_OAUTH_CLIENT_ID` — Payments and payouts.
- `BUNQ_OAUTH_CLIENT_SECRET` — Payments and payouts.
- `BUNQ_PRIVATE_KEY` — Payments and payouts.
- `BUNQ_PUBLIC_KEY` — Payments and payouts.
- `BANKING_WEBHOOK_SECRET` — Payments and payouts.
- `BANKING_WEBHOOK_HMAC_SECRET` — Payments and payouts.
- `PAYMENT_BENEFICIARY` — Payments and payouts.
- `PIX_KEY` — Payments and payouts.
- `PIX_CITY` — Payments and payouts.
- `UPI_VPA` — Payments and payouts.
- `PROMO_CODES` — Payments and payouts.

## Company details (invoices)

- `ROUT_COMPANY_NAME` — Shown on invoices.
- `ROUT_COMPANY_ADDRESS` — Shown on invoices.
- `ROUT_VAT_NUMBER` — Shown on invoices.
- `ROUT_BILLING_EMAIL` — Shown on invoices.

## Notifications

- `KCHAT_WEBHOOK_URL` — kChat alerts.
- `KCHAT_USERNAME` — kChat alerts.

## Details

## PSP_ENCRYPTION_KEY
Server-only. AES-256-GCM key material for creator PSP secrets (`psp_credentials`). At least 32 random characters.

## MIGRATION_URL
Legacy owner connection used only by local migration tooling (never at runtime or in a Vercel build). Prefer reviewed migrations through the gateway or Neon SQL editor. Not needed on Vercel.

## GITLAB_ISSUER
Optional GitLab server URL (default https://gitlab.com, no trailing slash). Set for self-managed GitLab.

## GITLAB_REDIRECT_URI
Optional. Defaults to <BETTER_AUTH_URL>/api/auth/callback/gitlab (e.g. https://rout.be/api/auth/callback/gitlab). Must match the GitLab application exactly.

## OAUTH_CLIENT_SECRET_PEPPER
Optional, server-only, 32+ random characters. Pepper for "Login met ROUT" client-secret hashes. Falls back to the auth secret. Changing it invalidates every app secret created since (rotate them in the console).

## ROUT_PROVIDER_SIGNING_KEK
Server-only, 32+ random characters, identical on every deployment that shares the database (Vercel Production + Preview and the Lovable preview). Key-encryption key for the "Login met ROUT" signing keys: each private key is stored AES-256-GCM sealed with a per-key key derived via HMAC from this value. Without it a KEK is derived from the auth secret (with a warning). Changing it makes the next signature rotate to a new key automatically; tokens from the old key stay valid for 48 hours. After every deployment runs the sealed-key code, run `bun scripts/seal-signing-keys.ts` once to replace the legacy plaintext key.

## SMS_PROVIDER
Optional: `android-gateway` (default), `twilio` or `brevo`. Without the keys below, phone verification shows "not configured" and sends nothing.

## SMS_API_KEY
Server-only. Android gateway bearer token, Brevo API key, or Twilio `<AccountSID>:<AuthToken>`.

## SMS_SENDER_ID
Sender name or number (required for Twilio and Brevo).

## SMS_GATEWAY_URL
sms-gate.app base URL, e.g. `https://api.sms-gate.app` (cloud). `/3rdparty/v1/message` is appended; body `{phoneNumbers, textMessage:{text}, deviceId}`.

## SMS_GATEWAY_USER / SMS_GATEWAY_PASSWORD / SMS_GATEWAY_DEVICE_ID
Server-only. Cloud-server username/password and device id from the SMS Gateway Android app (basic auth).

## SMS_ALLOW_INTERNATIONAL
Optional `true`: also send outbound SMS to non-Belgian numbers (default: only +32; others verify via Telegram/inbound SMS).

## SMS_INBOUND_TOKEN
Server-only random token; set the sms-gate.app `sms:received` webhook to `https://rout.be/api/public/sms/inbound?token=<value>`.

## PHONE_ENCRYPTION_KEY
Server-only, 32+ random characters. Encrypts stored phone numbers (AES-GCM) and hashes codes.

## SPOTIFY_CLIENT_ID / SPOTIFY_CLIENT_SECRET
Live Presence (Studio → Verbindingen & Integraties). Create an app at developer.spotify.com/dashboard and add the redirect URI `<PUBLIC_SITE_URL>/api/public/spotify/callback`. Needs `PSP_ENCRYPTION_KEY` too (tokens are encrypted).

## Identity verification (KYC)
- `IDENTITY_HASH_PEPPER` — Server-only random secret used to HMAC provider person IDs into `unique_human_id`. Never rotate after launch (would break the 1-person rule).
- `W_IDENTITY_ISSUER`, `W_IDENTITY_CLIENT_ID`, `W_IDENTITY_CLIENT_SECRET` — W Identity OIDC client. Redirect URI: `https://rout.be/api/public/identity/w-callback`.
- `DIDIT_API_KEY`, `DIDIT_WORKFLOW_ID`, `DIDIT_WEBHOOK_SECRET` — Didit passport scan. Webhook URL: `https://rout.be/api/public/identity/didit-webhook`. Max 500 successful scans per month.

## Cron schedule
`vercel.json` schedules `/api/public/cron/cleanup-assets` (daily, removes expired `user_assets` and `shared_files` from storage and database), plus expired ALTCHA rows, security codes and the DNS check — one daily job, since Vercel Hobby allows only one. Codes are also purged lazily on issue, ALTCHA on ~5% of challenges, and integration statuses refresh on visit (stale-while-revalidate). Vercel sends `Authorization: Bearer $CRON_SECRET`. On other hosts call the same URLs from any scheduler with that header (or `x-cron-secret`); `cleanup-assets` and `purge-shared-files` accept either `CRON_SECRET` or `LOVABLE_CRON_SECRET`, compare in constant time and never accept the secret in the URL. Each run drains expired files oldest-first for up to ~20 s, keeps rows whose storage delete failed for the next run, and reports `more: true` when work remains.

## Telegram
Register the webhook once with `TELEGRAM_BOT_TOKEN=... bun scripts/telegram-set-webhook.ts https://rout.be` (secret token is derived from the bot token).

- `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET_NAME`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` — Generic aliases for the Scaleway variables above (used when the SCALEWAY_* name is unset). Badge/crest uploads go here, public-read.

## Snapchat (Snap Kit)

- `SNAPCHAT_CLIENT_ID`, `SNAPCHAT_CLIENT_SECRET` — Snap Kit Login Kit + Bitmoji Kit. Redirect URI is fixed to `https://rout.be/api/public/snapchat/callback` (from `SITE_ORIGIN`, never the request host); register exactly that in Snap Kit. No location/Snap Map is ever used.

## Deployment mode (admin split)

- `VITE_APP_MODE` — `public` on rout.be (all /admin pages, /api/admin and admin server functions return 404/403), `admin` on rout.dlp.li (only portal + sign-in, no social login, noindex). Unset = everything served (preview).
- `APP_MODE` — Optional server-side override of the same value.

## VITE_PUBLIC_SITE_URL
Public site base URL (e.g. https://rout.be) used for stamp claim links created on the admin portal. Optional; defaults to https://rout.be in admin mode.

## YouTube vault
Reuses `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` and `PSP_ENCRYPTION_KEY`. Add redirect URI `https://rout.be/api/public/youtube/callback` in Google Cloud and enable YouTube Data API v3.

- `ROUT_AUDIT_SIGNING_SECRET` — HMAC key for daily audit checkpoints (`/api/public/cron/audit-checkpoint`).

- `STEAM_WEB_API_KEY` — optional; Steam live card. Without it the card stays hidden.

## Private e-mail relay (Login met ROUT)
- `EMAIL_INBOUND_TOKEN` — shared token in the Brevo Inbound Parsing webhook URL: `https://<site>/api/public/email-forward?token=<value>`. Without it the endpoint answers 401.
- `ROUT_FORWARD_EMAIL_DOMAIN` — optional; relay domain (default `mail.rout.be`). Its MX must point to Brevo inbound.
- Uses `ROUT_PROVIDER_PAIRWISE_SECRET` to derive relay addresses and `BREVO_API_KEY` to forward.

## Wallet passes
- Apple: `APPLE_WALLET_PASS_TYPE_ID`, `APPLE_WALLET_TEAM_ID`, `APPLE_WALLET_CERT_PEM` (Pass Type ID certificate), `APPLE_WALLET_KEY_PEM` (its private key), optional `APPLE_WALLET_KEY_PASSPHRASE`, `APPLE_WALLET_WWDR_PEM` (Apple WWDR G4). PEM values may use `\n` escapes.
- Google: `GOOGLE_WALLET_ISSUER_ID`, `GOOGLE_WALLET_SERVICE_ACCOUNT_EMAIL`, `GOOGLE_WALLET_PRIVATE_KEY` (service account PKCS#8 key).
- Also accepted: `APPLE_PASS_TYPE_ID`, `APPLE_TEAM_ID`, `APPLE_PASS_CERTIFICATE`, `APPLE_PASS_KEY`, `APPLE_PASS_KEY_PASSPHRASE`, `APPLE_WWDR_CERTIFICATE`, and `GOOGLE_WALLET_SERVICE_ACCOUNT` (the full service-account JSON) instead of the Google email + key.
- Missing or partial values switch that wallet off: the share menu shows a friendly fallback and `/api/wallet/...` answers 503 with an unsigned demo payload.

## Selective disclosure & music
- `ROUT_SYBIL_PEPPER` — Server-only HMAC pepper for per-app human nullifiers and disclosure IP hashes. Keep the existing live value across deployments: changing it changes the app's uniqueness identifiers.
- `LASTFM_API_KEY` — Optional Last.fm API credential for the first-party 30-second music relay. Without it no live track is returned. Visitors never call Last.fm directly.

## Schema drift & checksums (Cluster E, 2026-10-31)

- Live Neon weekt op negen punten af van de migration replay (RLS-grants en een
  audit-sequence). Delta-migratie `db/0143_schema_grants_alignment.sql` lijnt
  de grants declaratief uit (rol `rout_app`, deny-by-default voor server-only
  tabellen). Historische migraties zijn immuut en worden nooit aangepast.
- De checksum van historische `91_shadowban.sql` wijkt af van de live
  registratie. Oorzaak: het bestand is na live-applicatie ooit herschreven.
  De drift wordt gerapporteerd maar nooit stil hersteld; de live staat blijft
  leidend en correcties lopen uitsluitend via nieuwe delta-bestanden.

## Server keys read by code (added 2026-11-15)

Every value below is server-only, never `VITE_`-prefixed, and must stay identical across deployments that share the Neon database (changing it makes existing data unreadable or links invalid). Missing keys fail closed: the feature refuses, nothing falls back to a weaker key.

- `ROUT_VAULT_KEK` — Master KEK of the server vault (`src/lib/vault/server-kek.ts`): 64–512 characters `[A-Za-z0-9]`. Only wraps the server vault's RVE1 seed (AES-256-GCM, `vault_enclave.server_keys`); `vtk_`/`sdm_` tokens cannot be opened without it. Missing → `vault_kek_missing`. Never rotate without a reviewed re-wrap.
- `ROUT_RECOVERY_FACTOR_SECRET` — Server guardian factor of recovery (`src/lib/recovery/server-factor.server.ts`): 64–512 characters `[A-Za-z0-9]`, HKDF per member. Opens exactly one recovery share, never two. Missing → `recovery_factor_secret_missing`; changing it invalidates every server share.
- `ROUT_SUBJECT_MASTER_KEY` — OAuth subject vault (`src/lib/oauth/subject-vault.server.ts`), at least 32 characters. Missing → `subject_master_missing`.
- `SUBSCRIBER_ENCRYPTION_KEY` — Encrypts newsletter subscriber addresses outside the database (`src/lib/subscribers/subscriber-crypto.server.ts`).
- `QA_HMAC_SECRET` — Master for anonymous-question purpose keys (sender, abuse, rate-limit buckets; `src/lib/qa/privacy-keys.server.ts`).
- `CARD_LIVENESS_SECRET` — ROUT Card live-code key, at least 32 characters (`src/lib/wallet/card-liveness.server.ts`).
- `WALLET_ID_SECRET` — Wallet pass id derivation, at least 32 characters; without it no wallet card is issued.
- `WALLET_ASSET_ORIGIN` — Optional `https://` origin for wallet pass images; defaults to the public site.
- `POW_SECRET` — Proof-of-work challenge HMAC, at least 32 characters; falls back to `BETTER_AUTH_SECRET`.
- `PUBLIC_REF_SECRET` — Opaque public profile references; without it none are issued or accepted.
- `REVIEW_LINK_SECRET` — Signs review decision links, at least 32 characters.
- `AUTH_SECRET` — Alias of `BETTER_AUTH_SECRET`.
- `BLUESKY_ALLOWED_AUTH_SERVERS` — Optional comma-separated extra https origins for Bluesky sign-in.

## Mail transport (added 2026-11-15)
- `MAIL_PROVIDER` — `smtp` (default) or `brevo`.
- `SMTP_HOST` (default `mail.infomaniak.com`), `SMTP_PORT` (default 465), `SMTP_USER_AUTH` / `SMTP_PASS_AUTH` (auth mailbox), `SMTP_USER_SYSTEM` / `SMTP_PASS_SYSTEM` (system mailbox).
- `FALLBACK_MAIL_API_KEY`, `FALLBACK_MAIL_API_URL` — Optional Postmark-compatible fallback (default endpoint api.postmarkapp.com).
- `ERROR_REPORT_EMAIL` — Recipient of automatic error reports; falls back to `ADMIN_EMAIL`, then the contact address.

## Ghost Mode rewrite (sovereign AI, added 2026-11-15)
- `SOVEREIGN_AI_API_KEY` with either `INFOMANIAK_AI_PRODUCT_ID` (Infomaniak AI Tools) or `SOVEREIGN_AI_BASE_URL` (any OpenAI-compatible https endpoint); optional `SOVEREIGN_AI_MODEL`, `SOVEREIGN_AI_FALLBACK_MODEL`. Not configured → the rewrite is unavailable; text is never logged.

## Omni media worker (worker/, separate host)
- `OMNI_DATABASE_URL`, `OMNI_APP_ORIGIN`, `OMNI_EVENTS_URL`, `OMNI_REALTIME_SECRET`, `OMNI_RENDER_HOSTS`, `CHROMIUM_PATH`, `HOST`, `PORT` — read only by the worker daemon (see `worker/README.md`), never by the web app.

Storage names are exactly those in "File storage (Scaleway)" above (`SCALEWAY_DEFAULT_BUCKET`, `SCALEWAY_CLIENT_BUCKET`, `SCALEWAY_INTERNAL_BUCKET`); a variable named `SCALEWAY_BUCKET` is not read by any code. Without client-bucket credentials `/@handle/prekey-bundle.json` answers 503 `storage_unavailable` (no-store); a configured bucket without a published document answers 404 `not_available`.
