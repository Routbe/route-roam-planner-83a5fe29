/**
 * Host booking keys in Neon (db/0278 public.booking_host_keys). One row per host: the public
 * key, its RVE1 key id, the host reference (hostRefOf(publicKey), never the user id) and the
 * seed sealed under the host's workspace key. The server can neither open the seed nor make
 * envelopes the host would accept as its own. Writes go only through the definer
 * rout_booking_host_key_publish (caller from the transaction context); guests read keys only
 * through rout_booking_event_host_keys / rout_booking_profile_host_key (references, no ids).
 *
 * Legacy: before 0278 the document lived in the client bucket at users/<uid>/booking-key.json.
 * That object is only read, once, to carry an existing key into Neon unchanged (same kid), so
 * bookings sealed to it stay readable. Nothing writes booking keys to object storage anymore.
 */
import { keyId } from "@/lib/crypto-enclave/pqc-envelope";
import { b64uDecode, b64uEncode, hostBookingKeyDoc, hostRefOf, type HostBookingKeyDoc, type PublicHostKey } from "./sealed-booking";
import { sealedSchemaReady } from "./sealed-schema.server";

export const bookingKeyObjectKey = (userId: string) => `users/${userId}/booking-key.json`;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A document counts only when it parses strictly and its kid is the RVE1 key id of its public key. */
export function checkBookingKeyDoc(raw: unknown): HostBookingKeyDoc | null {
  const r = hostBookingKeyDoc.safeParse(raw);
  if (!r.success) return null;
  const pk = b64uDecode(r.data.publicKey);
  if (!pk || pk.length !== 1600) return null;
  return b64uEncode(keyId(pk)) === r.data.kid ? r.data : null;
}

export type EventTypeHostKey = { ref: string; kid: Uint8Array; publicKey: string };
export type EventTypeHostKeys = { ok: true; hosts: EventTypeHostKey[] } | { ok: false; reason: "inactive" | "host_key_missing" };

/** Re-checks what the database returns: kid = keyId(publicKey) and ref = hostRefOf(publicKey). */
export function checkPublicHostKey(raw: unknown): EventTypeHostKey | null {
  const k = raw as { ref?: unknown; kid?: unknown; publicKey?: unknown } | null;
  if (!k || typeof k.ref !== "string" || typeof k.kid !== "string" || typeof k.publicKey !== "string") return null;
  const pk = b64uDecode(k.publicKey);
  const kid = b64uDecode(k.kid);
  if (!pk || pk.length !== 1600 || !kid || kid.length !== 16) return null;
  if (b64uEncode(keyId(pk)) !== k.kid || hostRefOf(pk) !== k.ref) return null;
  return { ref: k.ref, kid, publicKey: k.publicKey };
}

export const publicHostKeys = (hosts: EventTypeHostKey[]): PublicHostKey[] => hosts.map((h) => ({ ref: h.ref, publicKey: h.publicKey }));

/** db/0278 is live: the only store for booking keys. */
export const bookingKeyStorageReady = sealedSchemaReady;

/** Every host of a public event type with a valid key, or host_key_missing when any host lacks one. */
export async function eventTypeHostKeys(eventTypeId: string): Promise<EventTypeHostKeys> {
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select public.rout_booking_event_host_keys(${eventTypeId}::uuid) as r`) as { r: { hosts: number; keys: unknown[] } | null }[];
  const r = rows[0]?.r;
  if (!r || !Number(r.hosts)) return { ok: false, reason: "inactive" };
  const hosts = (Array.isArray(r.keys) ? r.keys : []).map(checkPublicHostKey);
  if (hosts.length !== Number(r.hosts) || hosts.some((h) => h === null)) return { ok: false, reason: "host_key_missing" };
  return { ok: true, hosts: hosts as EventTypeHostKey[] };
}

/** Key behind a profile's visible request form, or null. */
export async function profileHostKey(profileId: string): Promise<EventTypeHostKey | null> {
  if (!UUID.test(profileId)) return null;
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select public.rout_booking_profile_host_key(${profileId}::uuid) as r`) as { r: unknown }[];
  return checkPublicHostKey(rows[0]?.r ?? null);
}

/** The caller's own key (RLS booking_host_keys_owner_read); runs inside the caller's db context. */
export async function readOwnBookingKey(userId: string): Promise<HostBookingKeyDoc | null> {
  if (!UUID.test(userId)) return null;
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select kid, public_key, sealed_seed, key_id from public.booking_host_keys where host_user_id = ${userId}::uuid limit 1`) as Record<string, unknown>[];
  const row = rows[0];
  if (!row) return null;
  return checkBookingKeyDoc({ v: 1, kid: row["kid"], publicKey: row["public_key"], sealedSeed: row["sealed_seed"], keyId: row["key_id"] });
}

export type PublishBookingKeyResult = { ok: true; kid: string } | { ok: false; reason: "input" | "exists" };

/**
 * Publishes the caller's own document through rout_booking_host_key_publish. A different key
 * never silently replaces a published one; `replace` is the host's explicit choice.
 */
export async function publishOwnBookingKey(raw: unknown, replace: boolean): Promise<PublishBookingKeyResult> {
  const doc = checkBookingKeyDoc(raw);
  if (!doc) return { ok: false, reason: "input" };
  const ref = hostRefOf(b64uDecode(doc.publicKey)!);
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select public.rout_booking_host_key_publish(${ref}::uuid, ${doc.kid}, ${doc.publicKey}, ${doc.sealedSeed}, ${doc.keyId}, ${replace}) as r`) as { r: { ok: boolean; kid?: string; reason?: string } | null }[];
  const r = rows[0]?.r;
  if (r?.ok) return { ok: true, kid: doc.kid };
  return { ok: false, reason: r?.reason === "exists" ? "exists" : "input" };
}

/** Pre-0278 document in object storage (read-only carryover). */
export async function readLegacyBookingKey(userId: string): Promise<HostBookingKeyDoc | null> {
  if (!UUID.test(userId)) return null;
  const { storageConfigured, getObject } = await import("@/lib/storage/s3.server");
  if (!storageConfigured("client")) return null;
  const r = await getObject("client", bookingKeyObjectKey(userId));
  if (r.status === 404 || !r.ok) return null;
  try {
    return checkBookingKeyDoc(JSON.parse(new TextDecoder().decode(new Uint8Array(await r.arrayBuffer()))));
  } catch {
    return null;
  }
}

/**
 * The caller's key: Neon first; otherwise a legacy document is copied into Neon unchanged
 * (same kid, never a replacement) so existing sealed bookings stay readable.
 */
export async function ownBookingKey(userId: string): Promise<HostBookingKeyDoc | null> {
  const own = await readOwnBookingKey(userId);
  if (own) return own;
  const legacy = await readLegacyBookingKey(userId).catch(() => null);
  if (!legacy) return null;
  const r = await publishOwnBookingKey(legacy, false);
  return r.ok ? legacy : null;
}
