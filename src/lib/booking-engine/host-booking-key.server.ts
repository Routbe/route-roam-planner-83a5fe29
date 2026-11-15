/**
 * Host booking keys (Fase 1) without SQL: one JSON document per member in the
 * client Scaleway bucket, `users/<uid>/booking-key.json`. It holds the public
 * key and the seed sealed under the member's workspace key; the server can
 * neither open the seed nor make envelopes the host would accept as its own.
 *
 * Host ids of an event type come from the existing definer function
 * rout_booking_stale_hosts (db/0216) with a negative age, which returns every
 * host of a public type. They never leave the server; guests get only
 * `{ ref, publicKey }`.
 */
import { keyId } from "@/lib/crypto-enclave/pqc-envelope";
import { b64uDecode, b64uEncode, hostBookingKeyDoc, hostRefOf, type HostBookingKeyDoc, type PublicHostKey } from "./sealed-booking";

export const bookingKeyObjectKey = (userId: string) => `users/${userId}/booking-key.json`;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type BookingKeyStore = {
  get: (key: string) => Promise<Uint8Array | null>;
  put: (key: string, body: Uint8Array) => Promise<void>;
};

/** A document counts only when it parses strictly and its kid is the RVE1 key id of its public key. */
export function checkBookingKeyDoc(raw: unknown): HostBookingKeyDoc | null {
  const r = hostBookingKeyDoc.safeParse(raw);
  if (!r.success) return null;
  const pk = b64uDecode(r.data.publicKey);
  if (!pk || pk.length !== 1600) return null;
  return b64uEncode(keyId(pk)) === r.data.kid ? r.data : null;
}

export async function readBookingKey(store: BookingKeyStore, userId: string): Promise<HostBookingKeyDoc | null> {
  if (!UUID.test(userId)) return null;
  const body = await store.get(bookingKeyObjectKey(userId));
  if (!body) return null;
  try {
    return checkBookingKeyDoc(JSON.parse(new TextDecoder().decode(body)));
  } catch {
    return null;
  }
}

export type PublishBookingKeyResult = { ok: true; kid: string } | { ok: false; reason: "input" | "exists" };

/**
 * Stores the caller's own document. A different key never silently replaces a
 * published one (bookings sealed to it would become unreadable); `replace`
 * is the host's explicit choice after losing the old Master Key.
 */
export async function publishBookingKey(store: BookingKeyStore, userId: string, raw: unknown, replace: boolean): Promise<PublishBookingKeyResult> {
  if (!UUID.test(userId)) return { ok: false, reason: "input" };
  const doc = checkBookingKeyDoc(raw);
  if (!doc) return { ok: false, reason: "input" };
  const current = await readBookingKey(store, userId);
  if (current && current.kid === doc.kid) return { ok: true, kid: doc.kid };
  if (current && !replace) return { ok: false, reason: "exists" };
  await store.put(bookingKeyObjectKey(userId), new TextEncoder().encode(JSON.stringify(doc)));
  return { ok: true, kid: doc.kid };
}

export type EventTypeHostKey = { hostUserId: string; ref: string; kid: Uint8Array; publicKey: string };
export type EventTypeHostKeys = { ok: true; hosts: EventTypeHostKey[] } | { ok: false; reason: "inactive" | "host_key_missing" };

/** Every host of the type with a valid published key, or host_key_missing when any host lacks one. */
export async function eventTypeHostKeys(store: BookingKeyStore, hostIds: string[]): Promise<EventTypeHostKeys> {
  if (hostIds.length === 0) return { ok: false, reason: "inactive" };
  const docs = await Promise.all(hostIds.map((id) => readBookingKey(store, id)));
  const hosts: EventTypeHostKey[] = [];
  for (let i = 0; i < hostIds.length; i++) {
    const doc = docs[i];
    if (!doc) return { ok: false, reason: "host_key_missing" };
    const pk = b64uDecode(doc.publicKey)!;
    hosts.push({ hostUserId: hostIds[i]!, ref: hostRefOf(pk), kid: b64uDecode(doc.kid)!, publicKey: doc.publicKey });
  }
  return { ok: true, hosts };
}

export const publicHostKeys = (hosts: EventTypeHostKey[]): PublicHostKey[] => hosts.map((h) => ({ ref: h.ref, publicKey: h.publicKey }));

// ---- Production wiring ---------------------------------------------------------

export async function bookingKeyStorageReady(): Promise<boolean> {
  const { storageConfigured } = await import("@/lib/storage/s3.server");
  return storageConfigured("client");
}

export async function productionBookingKeyStore(): Promise<BookingKeyStore> {
  const { getObject, putObject } = await import("@/lib/storage/s3.server");
  return {
    get: async (key) => {
      const r = await getObject("client", key);
      if (r.status === 404) return null;
      if (!r.ok) throw new Error(`booking_key_storage_${r.status}`);
      return new Uint8Array(await r.arrayBuffer());
    },
    put: (key, body) => putObject("client", key, body, { contentType: "application/json", cacheControl: "no-store" }),
  };
}

/** Host ids of a public event type, server-side only (see header). */
export async function eventTypeHostIds(eventTypeId: string): Promise<string[]> {
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select public.rout_booking_stale_hosts(${eventTypeId}::uuid, interval '-1000 years') as ids`) as { ids: string[] | null }[];
  return (rows[0]?.ids ?? []).filter((id) => UUID.test(id));
}
