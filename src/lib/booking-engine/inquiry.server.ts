/**
 * Sealed profile-card requests (sealed-inquiry.ts), server side. Server-only.
 *
 * The server never sees the visitor's name, e-mail or message. Order of checks:
 *   1. the BLAKE3 Hashcash proof over the exact envelope bytes (no database involved);
 *   2. the db/0278 schema probe (fails closed: nothing is written anywhere else);
 *   3. the envelope is an RVE1 bkh host copy for the host's published booking key;
 *   4. one definer call, rout_inquiry_create_sealed, stores envelope, BLAKE3 hash, nonce and
 *      epoch bucket in public.inquiries (the unique hash refuses a replayed proof).
 * The host gets a mail without guest data and reads the request in Studio, inside the crypto worker.
 *
 * Legacy (before 0278): envelopes in object storage at users/<uid>/inquiries/<pid>.json with
 * placeholder rows in booking_requests. Those are only read, so existing requests stay
 * visible; nothing writes request JSON to object storage anymore.
 */
import { sql } from "@/lib/neon";
import { sendSealedBookingRequestToHost } from "@/lib/brevo/client";
import { checkSealedPow } from "@/lib/crypto-enclave/sealed-pow";
import { b64uDecode, isHostEnvelopeFor, isSealedGuestEmail } from "./sealed-booking";
import { inquiryDoc, inquiryObjectKey, type HostInquiry, type InquiryOutcome, type InquiryRequest } from "./sealed-inquiry";
import { bytesToHex, sealedSchemaReady } from "./sealed-schema.server";

type Row = Record<string, unknown>;

/** Read-only access to pre-0278 request documents. */
export type LegacyInquiryReader = { get: (key: string) => Promise<Uint8Array | null> };

function siteOrigin(): string {
  return (process.env["PUBLIC_SITE_URL"] ?? "https://rout.be").replace(/\/$/, "");
}

export async function legacyInquiryReader(): Promise<LegacyInquiryReader | null> {
  const { getObject, storageConfigured } = await import("@/lib/storage/s3.server");
  if (!storageConfigured("client")) return null;
  return {
    get: async (key) => {
      const r = await getObject("client", key);
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`inquiry_storage_${r.status}`);
      return new Uint8Array(await r.arrayBuffer());
    },
  };
}

/** Public key of the host behind a profile's request form; nothing about the host's account. */
export async function profileBookingKey(handle: string): Promise<{ ok: true; ref: string; publicKey: string } | { ok: false; reason: "unavailable" | "host_key_missing" }> {
  if (!(await sealedSchemaReady())) return { ok: false, reason: "unavailable" };
  const { hostFor } = await import("@/lib/booking.server");
  const host = await hostFor(handle);
  if (!host) return { ok: false, reason: "unavailable" };
  const { profileHostKey } = await import("./host-booking-key.server");
  const key = await profileHostKey(host.id);
  if (!key) return { ok: false, reason: "host_key_missing" };
  return { ok: true, ref: key.ref, publicKey: key.publicKey };
}

const CREATE_REASONS = new Set(["invalid", "pow_stale", "past_date", "unavailable", "rate_limited"]);

/** Stores one sealed request; plaintext never reaches this function (parseInquiryRequest refuses it). */
export async function createSealedInquiry(req: InquiryRequest): Promise<InquiryOutcome> {
  const envelope = b64uDecode(req.sealed.envelope);
  if (!envelope) return { ok: false, reason: "invalid" };
  const pow = checkSealedPow("inquiry", req.sealed.pid, [{ ref: req.sealed.ref, envelope }], req.pow, Date.now());
  if (!pow.ok) {
    envelope.fill(0);
    return { ok: false, reason: pow.reason };
  }
  const hash = pow.hashes.get(req.sealed.ref)!;
  try {
    if (!(await sealedSchemaReady())) return { ok: false, reason: "unavailable" };
    const { hostFor } = await import("@/lib/booking.server");
    const host = await hostFor(req.handle);
    if (!host) return { ok: false, reason: "unavailable" };
    const { profileHostKey } = await import("./host-booking-key.server");
    const key = await profileHostKey(host.id);
    if (!key) return { ok: false, reason: "host_key_missing" };
    // The envelope must be bound to this host's key: same reference, same kid, a padded RVE1 bkh size.
    if (req.sealed.ref !== key.ref || !isHostEnvelopeFor(envelope, key.kid)) return { ok: false, reason: "invalid" };

    let r: { ok: boolean; reason?: string } | undefined;
    try {
      const rows = (await sql`
        select public.rout_inquiry_create_sealed(${host.id}::uuid, ${req.sealed.pid}::uuid, ${key.ref}::uuid,
          ${req.preferredDate}::date, ${req.preferredTime}, ${host.config.duration}::int, ${host.config.title},
          ${req.sealed.envelope}, decode(${bytesToHex(hash)}, 'hex'), ${req.pow.nonce}, ${req.pow.epoch}::int) as r
      `) as { r: { ok: boolean; reason?: string } }[];
      r = rows[0]?.r;
    } catch (error) {
      console.error("[inquiry] kon de aanvraag niet bewaren", error instanceof Error ? error.message : "error");
      return { ok: false, reason: "failed" };
    }
    if (!r?.ok) {
      // "duplicate" = same payload id or payload hash: a replayed proof is invalid, never stored twice.
      const reason = r?.reason && CREATE_REASONS.has(r.reason) ? r.reason : "invalid";
      return { ok: false, reason: reason as Exclude<InquiryOutcome, { ok: true }>["reason"] };
    }

    if (host.email) {
      await sendSealedBookingRequestToHost({
        to: host.email,
        date: req.preferredDate,
        time: req.preferredTime,
        durationMinutes: host.config.duration,
        studioUrl: `${siteOrigin()}/studio/booking`,
      }).catch(() => undefined);
    }
    return { ok: true, pid: req.sealed.pid };
  } finally {
    envelope.fill(0);
    hash.fill(0);
  }
}

const STATUS = new Set(["pending", "accepted", "declined"]);
const iso = (v: unknown) => String(v instanceof Date ? v.toISOString() : v);
const day = (v: unknown) => iso(v).slice(0, 10);

/**
 * The caller's own requests: sealed ones from public.inquiries (RLS inquiries_host_read) and
 * older rows from booking_requests (RLS booking_requests_host_read). Sealed entries carry only
 * their envelope; plaintext exists only for rows made before sealing.
 */
export async function listHostInquiries(userId: string, legacy?: LegacyInquiryReader | null): Promise<HostInquiry[]> {
  const ready = await sealedSchemaReady();
  const [sealedRows, oldRows] = await Promise.all([
    ready
      ? (sql`
          select id, payload_id, host_ref, encrypted_rve1_payload, preferred_date, preferred_time, duration_minutes, title, status, created_at
            from public.inquiries where host_user_id = ${userId}::uuid order by created_at desc limit 100
        ` as Promise<Row[]>)
      : Promise.resolve([] as Row[]),
    sql`
      select id, guest_name, guest_email, guest_message, preferred_date, preferred_time, duration_minutes, title, status, created_at
        from public.booking_requests where profile_id = ${userId}::uuid order by created_at desc limit 100
    ` as Promise<Row[]>,
  ]);
  const base = (r: Row) => {
    const status = String(r["status"]);
    return {
      id: String(r["id"]),
      date: day(r["preferred_date"]),
      time: String(r["preferred_time"]).slice(0, 5),
      durationMinutes: Number(r["duration_minutes"] ?? 30),
      title: (r["title"] as string | null) ?? null,
      status: (STATUS.has(status) ? status : "pending") as HostInquiry["status"],
      createdAt: iso(r["created_at"]),
    };
  };
  const fromNeon: HostInquiry[] = sealedRows.map((r) => ({
    ...base(r),
    sealed: { pid: String(r["payload_id"]), ref: String(r["host_ref"]), envelope: String(r["encrypted_rve1_payload"]) },
    legacy: null,
  }));

  const legacySealed = oldRows.filter((r) => isSealedGuestEmail(r["guest_email"]));
  const reader = legacySealed.length ? (legacy === undefined ? await legacyInquiryReader().catch(() => null) : legacy) : null;
  const docs = await Promise.all(legacySealed.map(async (r) => {
    const pid = String(r["guest_email"]).split("@")[0]!;
    try {
      const raw = reader ? await reader.get(inquiryObjectKey(userId, pid)) : null;
      const parsed = raw ? inquiryDoc.safeParse(JSON.parse(new TextDecoder().decode(raw))) : null;
      return parsed?.success && parsed.data.pid === pid ? parsed.data : null;
    } catch {
      return null;
    }
  }));
  const byId = new Map(legacySealed.map((r, i) => [String(r["id"]), docs[i] ?? null]));
  const fromLegacy: HostInquiry[] = oldRows.map((r) => {
    const sealed = isSealedGuestEmail(r["guest_email"]);
    const d = byId.get(String(r["id"])) ?? null;
    return {
      ...base(r),
      sealed: sealed && d ? { pid: d.pid, ref: d.ref, envelope: d.envelope } : null,
      legacy: sealed ? null : { name: String(r["guest_name"] ?? ""), email: String(r["guest_email"] ?? ""), message: (r["guest_message"] as string | null) ?? null },
    };
  });
  return [...fromNeon, ...fromLegacy].sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0)).slice(0, 100);
}

/** Host decision from Studio: a sealed request through rout_inquiry_resolve, else an older booking_requests row. */
export async function resolveHostInquiry(userId: string, id: string, action: "accept" | "decline"): Promise<{ ok: boolean }> {
  if (await sealedSchemaReady()) {
    const rows = (await sql`select public.rout_inquiry_resolve(${id}::uuid, ${action}) as ok`) as { ok: boolean | null }[];
    if (rows[0]?.ok) return { ok: true };
  }
  const own = (await sql`
    select id from public.booking_requests where id = ${id}::uuid and profile_id = ${userId}::uuid and status = 'pending' limit 1
  `) as Row[];
  if (!own[0]) return { ok: false };
  const { resolveBookingRequest } = await import("@/lib/booking.server");
  const r = await resolveBookingRequest(id, action);
  return { ok: r.ok };
}
