import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth } from "@/lib/auth/middleware";
import { parseInquiryRequest } from "@/lib/booking-engine/sealed-inquiry";

const handle = z
  .string()
  .trim()
  .min(2)
  .max(40)
  .transform((v) => v.replace(/^@+/, "").toLowerCase());

/** Public: the host's booking public key for a profile's request form (no account data). */
export const getProfileBookingKey = createServerFn({ method: "GET" })
  .inputValidator((input: unknown) => z.object({ handle }).strict().parse(input))
  .handler(async ({ data }) => {
    try {
      return await (await import("@/lib/booking-engine/inquiry.server")).profileBookingKey(data.handle);
    } catch (e) {
      console.error("[inquiry] host key", e instanceof Error ? e.message : "error");
      return { ok: false as const, reason: "host_key_missing" as const };
    }
  });

/**
 * Public RPC for the short request form on profile cards. Name, e-mail and
 * message arrive only as an RVE1 envelope sealed in the visitor's browser;
 * any plaintext guest field is refused ("plaintext_refused").
 */
export const requestBooking = createServerFn({ method: "POST" })
  .inputValidator(parseInquiryRequest)
  .handler(async ({ data }) => {
    await (await import("@/lib/platform-features.server")).assertPlatformFeature("bookings");
    const today = new Date().toISOString().slice(0, 10);
    if (data.preferredDate < today) return { ok: false as const, reason: "past_date" as const };
    const { assertHuman } = await import("./altcha.server");
    await assertHuman(data.altcha ?? null);
    try {
      return await (await import("@/lib/booking-engine/inquiry.server")).createSealedInquiry(data);
    } catch (e) {
      console.error("[inquiry] create", e instanceof Error ? e.message : "error");
      return { ok: false as const, reason: "failed" as const };
    }
  });

/** The signed-in host's own profile-card requests; sealed ones come back as envelopes only. */
export const listMyBookingInquiries = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    try {
      return { ok: true as const, items: await (await import("@/lib/booking-engine/inquiry.server")).listHostInquiries(context.userId) };
    } catch (e) {
      console.error("[inquiry] list", e instanceof Error ? e.message : "error");
      return { ok: false as const, items: [] };
    }
  });

/** Accept or decline one of the caller's own pending requests. Sealed requests send no mail to the guest. */
export const resolveMyBookingInquiry = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((input: unknown) => z.object({ id: z.string().uuid(), action: z.enum(["accept", "decline"]) }).strict().parse(input))
  .handler(async ({ data, context }) => {
    try {
      return await (await import("@/lib/booking-engine/inquiry.server")).resolveHostInquiry(context.userId, data.id, data.action);
    } catch (e) {
      console.error("[inquiry] resolve", e instanceof Error ? e.message : "error");
      return { ok: false };
    }
  });
