/**
 * Transactional booking through db/0216 `rout_booking_create`. One call = one
 * transaction in the database: advisory locks per (host, UTC day) for every
 * day the block touches, event rules (active, grid, notice, horizon), cached
 * availability over the whole block, live overlap/capacity/calendar checks,
 * then the insert. The GiST EXCLUDE constraint stays the last line of defence.
 * Status and payment hold come from the event type, never from this code.
 * Sealed bookings (db/0278) enter through rout_booking_create_sealed, which wraps it.
 */
import { sql, withDbContext } from "@/lib/neon";
import type { BookingOutcome, BookingRequest } from "./types";
import { publicEventType } from "./public.server";
import { b64uDecode, isHostEnvelopeFor, MAX_SEALED_HOSTS } from "./sealed-booking";
import { eventTypeHostKeys, type EventTypeHostKey } from "./host-booking-key.server";
import { bytesToHex, sealedSchemaReady } from "./sealed-schema.server";
import { checkSealedPow } from "@/lib/crypto-enclave/sealed-pow";

const OUTCOMES = new Set(["slot_taken", "outside_availability", "too_soon", "too_far", "inactive", "invalid_input", "invalid_intake", "guest_limit", "host_key_missing", "pow_stale"]);

export function isSlotTakenError(err: unknown): boolean {
  const e = err as { code?: string; message?: string; body?: string };
  const text = `${e?.message ?? ""} ${e?.body ?? ""}`;
  return e?.code === "23P01" || /23P01|slot_taken|bookings_no_overlap/.test(text);
}

type CreateResult =
  | { ok: false; reason: string }
  | { ok: true; bookingIds: string[]; hostIds: string[]; token: string | null; status: string; holdExpiresAt: string | null; groupId: string | null };

export type SealedCopy = { ref: string; envelope: string; bytes: Uint8Array };

/** Decodes every host copy; null when any copy is not canonical base64url. */
export function decodeSealedCopies(sealed: BookingRequest["sealed"]): SealedCopy[] | null {
  const out: SealedCopy[] = [];
  for (const [ref, envelope] of Object.entries(sealed.hosts)) {
    const bytes = b64uDecode(envelope);
    if (!bytes) return null;
    out.push({ ref, envelope, bytes });
  }
  return out;
}

/**
 * Checks sealed guest details against the hosts' published keys: exactly one
 * envelope per host reference, each an RVE1 bkh header for that host's key id
 * in one of the padded sizes. The server cannot open them and never tries.
 */
export function sealedCopiesMatch(copies: SealedCopy[], hosts: EventTypeHostKey[]): boolean {
  if (copies.length !== hosts.length || copies.length > MAX_SEALED_HOSTS) return false;
  const byRef = new Map(copies.map((c) => [c.ref, c]));
  return hosts.every((h) => {
    const c = byRef.get(h.ref);
    return Boolean(c && isHostEnvelopeFor(c.bytes, h.kid));
  });
}

/**
 * Try to book; never throws for a lost race. Guest details arrive only sealed. Order:
 * proof-of-work over the exact ciphertext (no database involved), then the db/0278 schema
 * probe, then the hosts' keys, then one definer call that writes the booking rows
 * (placeholders only) and every host copy (public.booking_payloads) in one transaction.
 */
export async function bookSlot(req: BookingRequest): Promise<BookingOutcome> {
  const copies = decodeSealedCopies(req.sealed);
  if (!copies) return { ok: false, reason: "invalid_intake" };
  const pow = checkSealedPow("booking", req.sealed.pid, copies.map((c) => ({ ref: c.ref, envelope: c.bytes })), req.pow, Date.now());
  if (!pow.ok) return { ok: false, reason: pow.reason };

  if (!(await sealedSchemaReady())) return { ok: false, reason: "unavailable" };
  const et = await publicEventType(req.eventTypeId);
  if (!et || et.hostCount === 0) return { ok: false, reason: "inactive" };
  const paid = et.priceCents != null;
  if (paid && !process.env["STRIPE_SECRET_KEY"]) return { ok: false, reason: "payment_unavailable" };

  const hostKeys = await eventTypeHostKeys(et.id);
  if (!hostKeys.ok) return { ok: false, reason: hostKeys.reason };
  if (!sealedCopiesMatch(copies, hostKeys.hosts)) return { ok: false, reason: "invalid_intake" };
  const payload = JSON.stringify(copies.map((c) => ({ ref: c.ref, envelope: c.envelope, hash: bytesToHex(pow.hashes.get(c.ref)!) })));
  const useHold = Boolean(req.holdId && req.holdSecret && et.holdMinutes != null);

  let r: CreateResult;
  try {
    const rows = (await sql`select public.rout_booking_create_sealed(${et.id}::uuid, ${req.startUtc}::timestamptz,
        ${req.guestTimezone}, ${req.sealed.pid}::uuid, ${payload}::jsonb, ${req.pow.nonce}, ${req.pow.epoch}::int,
        ${useHold ? req.holdId : null}::uuid, ${useHold ? req.holdSecret : null}) as r`) as { r: CreateResult }[];
    r = rows[0]!.r;
  } catch (err) {
    if (isSlotTakenError(err)) return { ok: false, reason: "slot_taken" };
    // A replayed proof (same payload hash) trips the unique index on booking_payloads.
    if ((err as { code?: string })?.code === "23505") return { ok: false, reason: "pow_invalid" };
    throw err;
  } finally {
    for (const c of copies) c.bytes.fill(0);
    for (const h of pow.hashes.values()) h.fill(0);
  }
  if (!r.ok) {
    const reason = r.reason === "invalid_input" ? "invalid_intake" : r.reason;
    return { ok: false, reason: (OUTCOMES.has(r.reason) ? reason : "slot_taken") as Exclude<BookingOutcome, { ok: true }>["reason"] };
  }

  const firstId = r.bookingIds[0]!;
  let checkoutUrl: string | null = null;
  if (paid) {
    checkoutUrl = await createCheckoutHold(firstId, et, new Date(r.holdExpiresAt!), r.token).catch(async (e: unknown) => {
      console.error("[booking] checkout", e instanceof Error ? e.message : "error");
      await releaseBookingHold(firstId);
      return null;
    });
    if (!checkoutUrl) return { ok: false, reason: "payment_unavailable" };
  }
  if (r.status === "confirmed") void inviteAsHost(firstId, r.hostIds[0]!, "REQUEST");
  return { ok: true, bookingIds: r.bookingIds, bookingToken: r.token, status: r.status as "confirmed", hostUserIds: r.hostIds, checkoutUrl };
}

/** Guest mail runs as the host so it reads the booking through RLS, not around it. */
function inviteAsHost(bookingId: string, hostUserId: string, method: "REQUEST" | "CANCEL") {
  return withDbContext({ userId: hostUserId, workspaceId: null }, async () => {
    const { sendBookingInvite } = await import("./invite.server");
    return sendBookingInvite(bookingId, method);
  });
}

async function createCheckoutHold(
  bookingId: string, et: { title: string; currency: string; priceCents: number | null }, expires: Date, bookingToken: string | null,
): Promise<string> {
  const site = (process.env["PUBLIC_SITE_URL"] ?? "https://rout.be").replace(/\/$/, "");
  const body = new URLSearchParams({
    mode: "payment",
    // No customer_email: ROUT does not know the guest's address; Stripe asks for it on its own page.
    "line_items[0][quantity]": "1",
    "line_items[0][price_data][currency]": et.currency,
    "line_items[0][price_data][unit_amount]": String(et.priceCents),
    "line_items[0][price_data][product_data][name]": et.title,
    "metadata[kind]": "booking",
    "metadata[booking_id]": bookingId,
    "payment_intent_data[metadata][booking_id]": bookingId,
    expires_at: String(Math.floor(expires.getTime() / 1000) + 5),
    success_url: `${site}/booking/${bookingId}?paid=1${bookingToken ? `&token=${bookingToken}` : ""}`,
    cancel_url: `${site}/booking/${bookingId}?cancelled=1`,
  });
  const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env["STRIPE_SECRET_KEY"]}`, "Content-Type": "application/x-www-form-urlencoded", "Idempotency-Key": `booking-${bookingId}` },
    body,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`stripe ${res.status}: ${text.slice(0, 300)}`);
  const session = JSON.parse(text) as { id: string; url: string };
  const saved = (await sql`select public.rout_booking_set_checkout(${bookingId}::uuid, ${session.id}) as ok`) as { ok: boolean | null }[];
  if (!saved[0]?.ok) throw new Error("checkout_not_recorded");
  return session.url;
}

/** Webhook: payment done → whole group confirmed (or requested). Idempotent; needs the issued session. */
export async function confirmPaidBooking(bookingId: string, sessionId: string): Promise<string> {
  const rows = (await sql`select public.rout_booking_confirm_paid(${bookingId}::uuid, ${sessionId}) as r`) as { r: { status: string; hostIds: string[] } }[];
  const r = rows[0]?.r;
  if (r?.status === "confirmed" && r.hostIds[0]) void inviteAsHost(bookingId, r.hostIds[0], "REQUEST");
  return r?.status ?? "noop";
}

export async function releaseBookingHold(bookingId: string): Promise<string> {
  const rows = (await sql`select public.rout_booking_release_hold(${bookingId}::uuid) as n`) as { n: number }[];
  return Number(rows[0]?.n ?? 0) > 0 ? "released" : "noop";
}

/** Cron safety net for holds whose Stripe expiry webhook never arrived. */
export async function releaseExpiredHolds(): Promise<number> {
  const rows = (await sql`select public.rout_booking_release_expired(500) as n`) as { n: number }[];
  return Number(rows[0]?.n ?? 0);
}

export type HoldOutcome =
  | { ok: true; holdId: string; secret: string; expiresAt: string; startUtc: string }
  | { ok: false; reason: "slot_taken" | "outside_availability" | "too_soon" | "too_far" | "inactive" | "too_many_holds" | "unavailable" };

const HOLD_REASONS = new Set(["slot_taken", "outside_availability", "too_soon", "too_far", "inactive", "too_many_holds"]);

/**
 * Soft-lock a start for 5 minutes (db/0218). `clientKey` is a digest of the
 * visitor's network identity so one visitor cannot hold more than 3 slots.
 * Before 0218 is live this reports `unavailable` and the page books without a hold.
 */
export async function holdSlot(eventTypeId: string, startUtc: string, clientKey: string, replace: { id: string; secret: string } | null): Promise<HoldOutcome> {
  const et = await publicEventType(eventTypeId);
  if (!et || et.hostCount === 0) return { ok: false, reason: "inactive" };
  if (et.holdMinutes == null) return { ok: false, reason: "unavailable" };
  const rows = (await sql`select public.rout_booking_hold(${eventTypeId}::uuid, ${startUtc}::timestamptz, ${clientKey},
      ${replace?.id ?? null}::uuid, ${replace?.secret ?? null}) as r`) as { r: { ok: boolean; reason?: string; holdId?: string; secret?: string; expiresAt?: string; startUtc?: string } }[];
  const r = rows[0]?.r;
  if (r?.ok && r.holdId && r.secret && r.expiresAt) {
    return { ok: true, holdId: r.holdId, secret: r.secret, expiresAt: new Date(r.expiresAt).toISOString(), startUtc: new Date(r.startUtc ?? startUtc).toISOString() };
  }
  const reason = r?.reason && HOLD_REASONS.has(r.reason) ? r.reason : "slot_taken";
  return { ok: false, reason: reason as Exclude<HoldOutcome, { ok: true }>["reason"] };
}

export async function releaseSlotHold(holdId: string, secret: string): Promise<boolean> {
  const rows = (await sql`select public.rout_booking_hold_release(${holdId}::uuid, ${secret}) as ok`) as { ok: boolean | null }[];
  return Boolean(rows[0]?.ok);
}
