/**
 * Sealed profile-card requests (sealed-inquiry.ts), server side. Server-only.
 *
 * The server never sees the visitor's name, e-mail or message: it checks that
 * the envelope is an RVE1 host copy for the host's published booking key,
 * stores it in the client bucket and writes placeholders to Neon through the
 * existing definer rout_booking_request_create (db/0240). The host gets a mail
 * without guest data and reads the request in Studio, inside the crypto worker.
 */
import { sql } from "@/lib/neon";
import { sendSealedBookingRequestToHost } from "@/lib/brevo/client";
import { b64uDecode, hostRefOf, isHostEnvelopeFor, isSealedGuestEmail, SEALED_GUEST_NAME, sealedGuestEmail } from "./sealed-booking";
import { inquiryDoc, inquiryObjectKey, INQUIRY_DOC_VERSION, type HostInquiry, type InquiryOutcome, type InquiryRequest } from "./sealed-inquiry";

type Row = Record<string, unknown>;

export type InquiryStore = {
  get: (key: string) => Promise<Uint8Array | null>;
  put: (key: string, body: Uint8Array) => Promise<void>;
  remove: (key: string) => Promise<void>;
};

function siteOrigin(): string {
  return (process.env["PUBLIC_SITE_URL"] ?? "https://rout.be").replace(/\/$/, "");
}

export async function productionInquiryStore(): Promise<InquiryStore> {
  const { getObject, putObject, deleteObject } = await import("@/lib/storage/s3.server");
  return {
    get: async (key) => {
      const r = await getObject("client", key);
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`inquiry_storage_${r.status}`);
      return new Uint8Array(await r.arrayBuffer());
    },
    put: (key, body) => putObject("client", key, body, { contentType: "application/json", cacheControl: "no-store" }),
    remove: (key) => deleteObject("client", key),
  };
}

/** Public key of the host behind a profile's request form; nothing about the host's account. */
export async function profileBookingKey(handle: string): Promise<{ ok: true; ref: string; publicKey: string } | { ok: false; reason: "unavailable" | "host_key_missing" }> {
  const { hostFor } = await import("@/lib/booking.server");
  const host = await hostFor(handle);
  if (!host) return { ok: false, reason: "unavailable" };
  const keys = await import("./host-booking-key.server");
  if (!(await keys.bookingKeyStorageReady())) return { ok: false, reason: "host_key_missing" };
  const doc = await keys.readBookingKey(await keys.productionBookingKeyStore(), host.id);
  if (!doc) return { ok: false, reason: "host_key_missing" };
  return { ok: true, ref: hostRefOf(b64uDecode(doc.publicKey)!), publicKey: doc.publicKey };
}

/** Stores one sealed request; plaintext never reaches this function (parseInquiryRequest refuses it). */
export async function createSealedInquiry(req: InquiryRequest, store?: InquiryStore): Promise<InquiryOutcome> {
  const { hostFor } = await import("@/lib/booking.server");
  const host = await hostFor(req.handle);
  if (!host) return { ok: false, reason: "unavailable" };

  const keys = await import("./host-booking-key.server");
  if (!(await keys.bookingKeyStorageReady())) return { ok: false, reason: "host_key_missing" };
  const doc = await keys.readBookingKey(await keys.productionBookingKeyStore(), host.id);
  if (!doc) return { ok: false, reason: "host_key_missing" };

  // The envelope must be bound to this host's key: same reference, same kid, a padded RVE1 bkh size.
  const ref = hostRefOf(b64uDecode(doc.publicKey)!);
  const envelope = b64uDecode(req.sealed.envelope);
  if (req.sealed.ref !== ref || !envelope || !isHostEnvelopeFor(envelope, b64uDecode(doc.kid)!)) return { ok: false, reason: "invalid" };

  const s = store ?? (await productionInquiryStore());
  const key = inquiryObjectKey(host.id, req.sealed.pid);
  // A payload id is used once; an existing object is never overwritten.
  if (await s.get(key)) return { ok: false, reason: "invalid" };
  const body = { v: INQUIRY_DOC_VERSION, pid: req.sealed.pid, ref, envelope: req.sealed.envelope };
  await s.put(key, new TextEncoder().encode(JSON.stringify(body)));

  try {
    // Fixed placeholders: db/0240 demands a name (2..120) and an address with '@', neither may be the visitor's.
    await sql`
      select public.rout_booking_request_create(${host.id}::uuid, ${SEALED_GUEST_NAME}, ${sealedGuestEmail(req.sealed.pid)},
        ${req.preferredDate}::date, ${req.preferredTime}, ${null}, ${host.config.duration}::int, ${host.config.title}) as id
    `;
  } catch (error) {
    console.error("[inquiry] kon de aanvraag niet bewaren", error instanceof Error ? error.message : "error");
    await s.remove(key).catch(() => undefined);
    return { ok: false, reason: "failed" };
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
}

const STATUS = new Set(["pending", "accepted", "declined"]);

/** The caller's own requests (RLS booking_requests_host_read); sealed ones carry their envelope, never plaintext. */
export async function listHostInquiries(userId: string, store?: InquiryStore): Promise<HostInquiry[]> {
  const rows = (await sql`
    select id, guest_name, guest_email, guest_message, preferred_date, preferred_time, duration_minutes, title, status, created_at
      from public.booking_requests
     where profile_id = ${userId}::uuid
     order by created_at desc
     limit 100
  `) as Row[];
  const sealedRows = rows.filter((r) => isSealedGuestEmail(r["guest_email"]));
  const s = sealedRows.length ? (store ?? (await productionInquiryStore())) : null;
  const docs = await Promise.all(sealedRows.map(async (r) => {
    const pid = String(r["guest_email"]).split("@")[0]!;
    try {
      const raw = await s!.get(inquiryObjectKey(userId, pid));
      const parsed = raw ? inquiryDoc.safeParse(JSON.parse(new TextDecoder().decode(raw))) : null;
      return parsed?.success && parsed.data.pid === pid ? parsed.data : null;
    } catch {
      return null;
    }
  }));
  const byId = new Map(sealedRows.map((r, i) => [String(r["id"]), docs[i] ?? null]));
  return rows.map((r) => {
    const id = String(r["id"]);
    const sealed = isSealedGuestEmail(r["guest_email"]);
    const d = byId.get(id) ?? null;
    const status = String(r["status"]);
    return {
      id,
      date: String(r["preferred_date"] instanceof Date ? (r["preferred_date"] as Date).toISOString() : r["preferred_date"]).slice(0, 10),
      time: String(r["preferred_time"]).slice(0, 5),
      durationMinutes: Number(r["duration_minutes"] ?? 30),
      title: (r["title"] as string | null) ?? null,
      status: (STATUS.has(status) ? status : "pending") as HostInquiry["status"],
      createdAt: String(r["created_at"] instanceof Date ? (r["created_at"] as Date).toISOString() : r["created_at"]),
      sealed: sealed && d ? { pid: d.pid, ref: d.ref, envelope: d.envelope } : null,
      legacy: sealed ? null : { name: String(r["guest_name"] ?? ""), email: String(r["guest_email"] ?? ""), message: (r["guest_message"] as string | null) ?? null },
    };
  });
}

/** Host decision from Studio: only a pending request the caller can read through RLS. */
export async function resolveHostInquiry(userId: string, id: string, action: "accept" | "decline"): Promise<{ ok: boolean }> {
  const own = (await sql`
    select id from public.booking_requests where id = ${id}::uuid and profile_id = ${userId}::uuid and status = 'pending' limit 1
  `) as Row[];
  if (!own[0]) return { ok: false };
  const { resolveBookingRequest } = await import("@/lib/booking.server");
  const r = await resolveBookingRequest(id, action);
  return { ok: r.ok };
}
