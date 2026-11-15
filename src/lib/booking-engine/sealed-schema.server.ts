/**
 * Runtime probe for db/0278 (booking_host_keys, inquiries, booking_payloads). Code may deploy
 * before the reviewed EXPAND migration is applied on Neon, so every sealed write path asks this
 * first and fails closed ("unavailable") instead of writing anywhere else. Cached for 60 s.
 */
import { sql } from "@/lib/neon";

let probe: { ok: boolean; at: number } | null = null;

export async function sealedSchemaReady(): Promise<boolean> {
  if (probe && Date.now() - probe.at < 60_000) return probe.ok;
  const rows = (await sql`select (to_regclass('public.booking_host_keys') is not null
      and to_regclass('public.inquiries') is not null
      and to_regclass('public.booking_payloads') is not null) as ok`) as { ok: boolean }[];
  probe = { ok: Boolean(rows[0]?.ok), at: Date.now() };
  return probe.ok;
}

/** Tests only. */
export function resetSealedSchemaProbe(): void {
  probe = null;
}

export const bytesToHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
