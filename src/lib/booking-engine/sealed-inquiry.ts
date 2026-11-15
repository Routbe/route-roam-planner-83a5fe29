/**
 * Wire format of sealed profile-card requests ("kort aanvraagformulier").
 *
 * The visitor's browser seals name, e-mail and message in the crypto worker
 * (booking.seal → RVE1 kind bkh, ML-KEM-1024 + X25519) for the host's
 * published booking key (Scaleway `users/<uid>/booking-key.json`). Without a
 * migration, booking_requests (db/0240) cannot hold an envelope (message ≤ 500
 * characters), so:
 *
 *   - the envelope is stored next to the booking key, in the client bucket at
 *     `users/<hostId>/inquiries/<pid>.json`, as `{ v: 1, pid, ref, envelope }`;
 *   - the database row gets fixed placeholders: guest_name "RVE1",
 *     guest_email `<pid>@sealed.invalid`, guest_message null.
 *
 * Browser-safe: no server imports.
 */
import { z } from "zod";
import { HOST_ENVELOPE_SIZES } from "./sealed-booking";

export const INQUIRY_DOC_VERSION = 1;
/** Any of these keys in a request means plaintext guest data: refused before validation. */
export const PLAINTEXT_INQUIRY_FIELDS = ["guestName", "guestEmail", "guestMessage", "name", "email", "message", "note"] as const;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const B64U = /^[A-Za-z0-9_-]+$/;
const MAX_ENVELOPE_CHARS = Math.ceil((Math.max(...HOST_ENVELOPE_SIZES) * 4) / 3) + 4;

export const sealedInquiryPart = z
  .object({
    pid: z.string().regex(UUID),
    ref: z.string().regex(UUID),
    envelope: z.string().regex(B64U).max(MAX_ENVELOPE_CHARS),
  })
  .strict();

export const inquiryRequest = z
  .object({
    handle: z
      .string()
      .trim()
      .min(2)
      .max(40)
      .transform((v) => v.replace(/^@+/, "").toLowerCase()),
    preferredDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
    preferredTime: z.string().regex(/^\d{2}:\d{2}$/),
    sealed: sealedInquiryPart,
    altcha: z.string().max(4000).optional().nullable(),
  })
  .strict();
export type InquiryRequest = z.infer<typeof inquiryRequest>;

/** Refuses plaintext guest fields with one fixed error, then validates strictly. */
export function parseInquiryRequest(input: unknown): InquiryRequest {
  if (typeof input === "object" && input !== null && PLAINTEXT_INQUIRY_FIELDS.some((k) => Object.hasOwn(input, k))) {
    throw new Error("plaintext_refused");
  }
  return inquiryRequest.parse(input);
}

export const inquiryObjectKey = (hostId: string, pid: string) => `users/${hostId}/inquiries/${pid}.json`;

export const inquiryDoc = z
  .object({ v: z.literal(INQUIRY_DOC_VERSION), pid: z.string().regex(UUID), ref: z.string().regex(UUID), envelope: z.string().regex(B64U).max(MAX_ENVELOPE_CHARS) })
  .strict();
export type InquiryDoc = z.infer<typeof inquiryDoc>;

export type InquiryOutcome =
  | { ok: true; pid: string }
  | { ok: false; reason: "unavailable" | "host_key_missing" | "invalid" | "past_date" | "failed" };

/** One request as the host's Studio receives it; plaintext only for rows made before sealing. */
export type HostInquiry = {
  id: string;
  date: string;
  time: string;
  durationMinutes: number;
  title: string | null;
  status: "pending" | "accepted" | "declined";
  createdAt: string;
  sealed: { pid: string; ref: string; envelope: string } | null;
  legacy: { name: string; email: string; message: string | null } | null;
};
