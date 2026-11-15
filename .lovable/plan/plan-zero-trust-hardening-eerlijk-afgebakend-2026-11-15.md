# Plan: Zero-trust hardening, eerlijk afgebakend

Er verandert niets aan Neon, geen nieuwe SQL-migratie, `CODE_SCHEMA_LEVEL` blijft "0277".

## Wat ik NIET doe zoals gevraagd, en waarom
1. **Geen tekstwijziging in `db/0277_...sql`.** Elke byte telt mee in de SHA-256 die Neon heeft vastgelegd (`2ae4306f...`). Een commentaar aanpassen breekt de migratiegeschiedenis-check. De correctie komt in `db-pending/README.md` en in de kop van het rollback-bestand.
2. **Geen databaseregel "alleen versleutelde gastgegevens".** Dat vraagt een migratie, en die is verboden. Die regel komt later als aparte EXPAND/CONTRACT-stap, met certificering en jouw GO.
3. **Geen "100% gecertificeerd" in roadmap, HANDOVER of AGENTS.** Je eigen dossier noemt nog open punten: hardware-PRF-test, live merge-test, prekey-publicatie en de Vercel-herkomst. Ik vink alleen af wat in deze ronde aantoonbaar slaagt. De rest blijft open staan, met de reden erbij.
4. **Neon wordt niet aangeraakt.** Daarom draai ik geen `tenant-backfill --gateway` en geen `verify-live-merge`.

## Fase 1: versleutelde gastgegevens bij boekingen
- Er is geen apart RVE2-formaat nodig. De bestaande `crypto-enclave/booking-seal.ts` (RVE1 `bkh`/`bkg`, ML-KEM-1024 + X25519, vaste paddingbuckets) is precies wat je projectregel voorschrijft. Ik sluit die aan, ik bouw niets nieuws.
- **Bij de gast in de browser:** naam, e-mail, notitie en intake-antwoorden worden in de crypto-worker verzegeld met de publieke hostsleutel (`bkh`) en een gastsleutel (`bkg`, uit het manage-link-fragment).
- **Op de server** (`book.server.ts`): plaintextvelden worden geweigerd. Alleen geldige RVE1-enveloppen gaan in de bestaande kolommen, met een vaste vervangtekst voor de naam.
- **Bij de host** (agenda): ontsleutelen gebeurt alleen in de worker via `withCredential`, en het resultaat wordt daarna gewist.
- **Gevolgen die je moet aanvaarden:**
  - Bevestigingsmails, ICS-bestanden en Stripe-checkout krijgen geen naam of e-mail van de gast meer van de server.
  - Betaalde boekingen kunnen geen klant-e-mail meer aan Stripe meegeven.
  - De gast krijgt de bevestiging via de manage-link op het scherm in plaats van per mail. Het alternatief is dat de browser die mail zelf start.
  - Hosts zonder gepubliceerde hostsleutel kunnen geen boekingen meer ontvangen. Ze krijgen een duidelijke melding.

## Fase 2: controles op de server en /dev afsluiten
- Ik loop alle `*.functions.ts` en `*.server.ts` na die achter `/dashboard`, `/studio`, `/admin`, `/console` en `/agenda` hangen.
- Elke serverfunctie die niet bewust openbaar is, krijgt de bestaande `requireAuth`-middleware (`src/lib/auth/middleware.ts`). Admin-functies behouden daarbovenop hun admin- en 2FA-check.
- Er komt een test die faalt zodra een niet-openbare serverfunctie zonder `requireAuth` wordt toegevoegd, met een expliciete lijst van bewust openbare functies.
- **`/dev/emails`:** dezelfde afsluiting als `/dev/material-lab` (`if (!import.meta.env.DEV) throw notFound()`). De bijbehorende testmail-functie krijgt op de server ook een productie-weigering. `process.env.NODE_ENV` is in de edge-runtime niet betrouwbaar, daarom gebruik ik dat niet.

## Fase 3: documentatie en Vercel
- **`ENVIRONMENT.md`:** alle variabelen aanvullen die de code leest maar die nog niet beschreven staan, onder meer:
  - `ROUT_VAULT_KEK` en `ROUT_RECOVERY_FACTOR_SECRET`
  - `ROUT_SUBJECT_MASTER_KEY`, `PSP_ENCRYPTION_KEY`, `SUBSCRIBER_ENCRYPTION_KEY`
  - `QA_HMAC_SECRET`, `CARD_LIVENESS_SECRET`, `WALLET_ID_SECRET`
  - `POW_SECRET`, `ROUT_SYBIL_PEPPER`, `REVIEW_LINK_SECRET`, `PUBLIC_REF_SECRET`
  - de SMTP-instellingen en `SOVEREIGN_AI_*`
  - de `SCALEWAY_*`-namen precies zoals de code ze leest (`SCALEWAY_DEFAULT_BUCKET` / `SCALEWAY_CLIENT_BUCKET`, niet `SCALEWAY_BUCKET`)
  
  Daarnaast haal ik de tegenstrijdige zinnen over `vercel.json` weg.
- **Vercel:** `vercel.json` met beveiligingsheaders (HSTS, nosniff, frame-ancestors, referrer-policy, permissions-policy) en het script `build:vercel` (`VERCEL=1 vite build`, Nitro-Vercel-preset). De Lovable-preview blijft ongewijzigd. Of een echte Vercel-build slaagt, kan ik hier niet aantonen. Dat meld ik zo.
- **Migratiedocumentatie:** de 0265-instructie wordt "verhoogt CODE_SCHEMA_LEVEL nooit naar beneden; voorganger is 0264". De verkeerde rollback-naam corrigeer ik in de README en in de kop van de rollback-bestanden.

## Fase 4: controle
- `bunx vitest run` (booking-, auth-, migratiegeschiedenis- en nieuwe guard-tests), `tsgo --noEmit` en `bun run verify:rls` (offline Z3).
- Ik meld de echte aantallen geslaagde en mislukte tests, zonder vooraf "3.180+ groen" aan te nemen.
- **Prekey-endpoint:** ik controleer dat ontbrekende Scaleway-gegevens een nette `404 not_available` geven zonder crash, en voeg daar een test voor toe als die nog ontbreekt.
- **Documenten:** een appendix in `docs/HANDOVER.md` met deze ronde en de nog open punten. De genummerde secties blijven letterlijk zoals ze zijn. `roadmap.md` werk ik alleen bij voor wat echt af is. `AGENTS.md` krijgt regels voor de nieuwe server-guard-test en de `/dev`-afsluiting.

## Technische details
- `book.$eventTypeId.tsx`, `BookPublic`, `book.server.ts`, `booking.functions.ts`, `details.server.ts`, `manage.server.ts`, de mailing in de booking-engine, `crypto-enclave/booking-seal.ts` (alleen aansluiten, geen nieuwe crypto) en de hostagenda-weergave.
- Wasm-pinnen worden niet aangeraakt.
