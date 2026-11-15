/**
 * Korte aanvraagformulier op profielkaarten: host opzoeken en beslissingen
 * (accept/decline) verwerken. Nieuwe aanvragen komen alleen nog versleuteld
 * binnen via booking-engine/inquiry.server.ts; deze module mailt een gast
 * alleen nog voor oude, vóór de versleuteling bewaarde aanvragen. Server-only.
 */
import { bookingSigningSecret, checkBookingToken, signBookingToken } from "@/lib/booking-token";
import { sql } from "@/lib/neon";
import {
  sendBookingConfirmedToGuest,
  sendBookingDeclinedToGuest,
} from "@/lib/brevo/client";
import { isSealedGuestEmail } from "@/lib/booking-engine/sealed-booking";
import {
  buildIcs,
  googleCalendarUrl,
  parseBookingConfig,
  type BookingConfig,
} from "@/lib/booking";

type Row = Record<string, unknown>;

/** Signs one action for one request with an expiring HMAC-SHA256 token. */
export function bookingToken(id: string, action: "accept" | "decline"): string {
  return signBookingToken(bookingSigningSecret(), id, action);
}

export function verifyBookingToken(id: string, action: "accept" | "decline", token: string): boolean {
  let secret: string;
  try { secret = bookingSigningSecret(); } catch { return false; }
  return checkBookingToken(secret, id, action, token);
}

interface HostRow {
  id: string;
  username: string | null;
  display_name: string | null;
  email: string | null;
  config: BookingConfig;
}

/** Zoekt het profiel én de boekingsconfiguratie die de maker zelf instelde. */
export async function hostFor(handle: string): Promise<HostRow | null> {
  const rows = (await sql`
    select p.id, p.username, p.display_name, p.blocks
      from public.profiles p
     where lower(p.username) = ${handle.toLowerCase()}
     limit 1
  `) as Row[];
  const found = rows[0];
  if (!found) return null;
  // The host's address comes from the notification definer: only for a profile with a visible booking block.
  const { readNotifyAddress } = await import("@/lib/profile-private.server");
  const row: Row = { ...found, email: await readNotifyAddress(String(found["id"]), "booking_request") };
  const blocks = Array.isArray(row["blocks"]) ? (row["blocks"] as Row[]) : [];
  const block = blocks.find((b) => b?.["kind"] === "booking_request" && b?.["hidden"] !== true);
  if (!block) return null;
  return {
    id: String(row["id"]),
    username: (row["username"] as string | null) ?? null,
    display_name: (row["display_name"] as string | null) ?? null,
    email: (row["email"] as string | null) ?? null,
    config: parseBookingConfig(String(block["value"] ?? "")),
  };
}

/** Verwerkt de klik op accepteren/weigeren uit de hostmail. */
export async function resolveBookingRequest(
  id: string,
  action: "accept" | "decline",
): Promise<{ ok: boolean; message: string }> {
  const rows = (await sql`
    select id, profile_id, guest_name, guest_email, preferred_date, preferred_time,
           guest_message, duration_minutes, title
      from public.rout_booking_request_resolve(${id}::uuid, ${action})
  `) as Row[];
  const booking = rows[0];
  if (!booking) {
    return { ok: false, message: "Deze aanvraag is al afgehandeld of bestaat niet." };
  }

  const hostRows = (await sql`
    select display_name, username
      from public.profiles where id = ${String(booking["profile_id"])}::uuid limit 1
  `) as Row[];
  const { readNotifyAddress } = await import("@/lib/profile-private.server");
  const hostEmail = (await readNotifyAddress(String(booking["profile_id"]), "booking_request")) ?? "hallo@rout.be";
  const hostName =
    (hostRows[0]?.["display_name"] as string | null) ??
    (hostRows[0]?.["username"] as string | null) ??
    "ROUT";

  // Sealed request: ROUT has no address and no name; the host answers the guest from Studio.
  if (isSealedGuestEmail(booking["guest_email"])) {
    return {
      ok: true,
      message: action === "accept"
        ? "Aanvaard. ROUT mailt de gast niet: open je boekingen in Studio om de versleutelde gegevens te lezen en de gast zelf te antwoorden."
        : "Geweigerd. ROUT mailt de gast niet.",
    };
  }

  const guestEmail = String(booking["guest_email"]);
  const guestName = String(booking["guest_name"]);
  const date = String(booking["preferred_date"]).slice(0, 10);
  const time = String(booking["preferred_time"]).slice(0, 5);
  const title = String(booking["title"] ?? "Afspraak") || "Afspraak";
  const duration = Number(booking["duration_minutes"] ?? 30);

  if (action === "decline") {
    await sendBookingDeclinedToGuest({
      to: guestEmail,
      guestName,
      hostName,
      date,
      time,
    });
    return { ok: true, message: "Aanvraag geweigerd. De gast is verwittigd." };
  }

  const ics = buildIcs({
    uid: String(booking["id"]),
    title,
    date,
    time,
    durationMinutes: duration,
    guestName,
    guestEmail,
    hostEmail,
    description: String(booking["guest_message"] ?? ""),
  });
  const gcal = googleCalendarUrl({
    uid: String(booking["id"]),
    title,
    date,
    time,
    durationMinutes: duration,
    guestName,
    guestEmail,
    hostEmail,
    description: String(booking["guest_message"] ?? ""),
  });

  await sendBookingConfirmedToGuest({
    to: guestEmail,
    guestName,
    hostName,
    hostEmail,
    title,
    date,
    time,
    durationMinutes: duration,
    calendarUrl: gcal,
    ics,
  });

  return { ok: true, message: "Afspraak aanvaard. De gast kreeg een agenda-uitnodiging." };
}
