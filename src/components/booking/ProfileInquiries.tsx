import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { toast } from "sonner";
import { Check, Loader2, Lock, Mail, ShieldAlert, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useI18n } from "@/lib/i18n";
import { listMyBookingInquiries, resolveMyBookingInquiry } from "@/lib/booking.functions";
import { b64uDecode, hostRefOf, type HostBookingKeyDoc } from "@/lib/booking-engine/sealed-booking";
import type { HostInquiry } from "@/lib/booking-engine/sealed-inquiry";
import type { BookingPayload } from "@/lib/crypto-enclave/booking-seal";

const QK = ["profile-inquiries"];

/**
 * Profile-card requests for the signed-in host. Sealed requests are opened in
 * the crypto worker with the host's booking key; plaintext stays in component
 * memory only (gcTime 0). Replies go from the host's own mail app (mailto).
 */
export function ProfileInquiries({ userId, keyDoc }: { userId: string; keyDoc: HostBookingKeyDoc | null }) {
  const { t, locale } = useI18n();
  const qc = useQueryClient();
  const list = useServerFn(listMyBookingInquiries);
  const resolve = useServerFn(resolveMyBookingInquiry);
  const [busy, setBusy] = useState<string | null>(null);
  const q = useQuery({ queryKey: QK, queryFn: () => list() });
  const items = q.data?.items ?? [];
  const sealed = items.filter((i) => i.sealed);

  const opened = useQuery({
    queryKey: ["profile-inquiries-open", userId, keyDoc?.kid ?? null, sealed.map((i) => i.sealed!.pid).join(",")],
    enabled: Boolean(keyDoc) && sealed.length > 0,
    gcTime: 0,
    staleTime: Infinity,
    retry: false,
    queryFn: async () => {
      const { enclave } = await import("@/lib/crypto-enclave/client");
      const ref = hostRefOf(b64uDecode(keyDoc!.publicKey)!);
      const out = new Map<string, BookingPayload | null>();
      const batch: { id: string; payloadId: string; envelope: Uint8Array }[] = [];
      for (const i of sealed) {
        const envelope = i.sealed!.ref === ref ? b64uDecode(i.sealed!.envelope) : null;
        if (envelope) batch.push({ id: i.id, payloadId: i.sealed!.pid, envelope });
        else out.set(i.id, null);
      }
      if (batch.length > 0) {
        const { payloads } = await enclave.bookingKey.open(userId, keyDoc!, batch.map(({ payloadId, envelope }) => ({ payloadId, envelope })));
        batch.forEach((b, n) => out.set(b.id, payloads[n] ?? null));
      }
      return out;
    },
  });

  const act = async (id: string, action: "accept" | "decline") => {
    setBusy(id);
    const r = await resolve({ data: { id, action } }).catch(() => ({ ok: false }));
    setBusy(null);
    if (r.ok) toast.success(t("booking.inquiry.done"));
    else toast.error(t("booking.err.generic"));
    await qc.invalidateQueries({ queryKey: QK });
  };

  if (q.isLoading) return null;
  const dateFmt = new Intl.DateTimeFormat(locale, { dateStyle: "medium" });

  return (
    <section className="space-y-3 rounded-2xl border border-border bg-card p-4 text-card-foreground shadow-sm sm:p-6">
      <div className="space-y-1">
        <h3 className="flex items-center gap-2 font-semibold"><Lock className="h-4 w-4 text-primary" aria-hidden />{t("booking.inquiry.heading")}</h3>
        <p className="text-sm text-muted-foreground">{t("booking.inquiry.intro")}</p>
      </div>
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("booking.inquiry.empty")}</p>
      ) : (
        <ul className="space-y-2">
          {items.map((i) => (
            <InquiryRow
              key={i.id}
              item={i}
              when={`${dateFmt.format(new Date(`${i.date}T12:00:00Z`))} · ${i.time} · ${i.durationMinutes} min`}
              payload={i.sealed ? opened.data?.get(i.id) : undefined}
              opening={Boolean(i.sealed) && opened.isFetching}
              hasKey={Boolean(keyDoc)}
              busy={busy === i.id}
              onAct={act}
            />
          ))}
        </ul>
      )}
    </section>
  );
}

function InquiryRow({ item, when, payload, opening, hasKey, busy, onAct }: {
  item: HostInquiry; when: string; payload: BookingPayload | null | undefined; opening: boolean; hasKey: boolean; busy: boolean;
  onAct: (id: string, action: "accept" | "decline") => void;
}) {
  const { t } = useI18n();
  const contact = item.legacy ? { name: item.legacy.name, email: item.legacy.email, note: item.legacy.message } : payload ? { name: payload.name, email: payload.email, note: payload.note } : null;
  const mailto = contact?.email
    ? `mailto:${encodeURIComponent(contact.email)}?subject=${encodeURIComponent(t("booking.inquiry.replySubject", { date: item.date, time: item.time }))}`
    : null;
  return (
    <li className="flex flex-col gap-3 rounded-xl border border-border bg-background p-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0 space-y-1 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{when}</span>
          <Badge variant={item.status === "pending" ? "default" : "secondary"}>{t(`booking.inquiry.status.${item.status}`)}</Badge>
        </div>
        {item.legacy && <p className="text-xs text-muted-foreground">{t("booking.inquiry.legacy")}</p>}
        {contact ? (
          <>
            <p className="flex min-w-0 items-center gap-1.5 text-muted-foreground">
              {!item.legacy && <Lock className="h-3.5 w-3.5 shrink-0 text-primary" aria-hidden />}
              <span className="truncate">{[contact.name, contact.email].filter(Boolean).join(" · ")}</span>
            </p>
            {contact.note && <p className="whitespace-pre-wrap text-muted-foreground">{contact.note}</p>}
          </>
        ) : !item.sealed ? (
          <p className="flex items-center gap-1.5 text-destructive"><ShieldAlert className="h-3.5 w-3.5" />{t("booking.inquiry.missing")}</p>
        ) : !hasKey ? (
          <p className="flex items-center gap-1.5 text-muted-foreground"><Lock className="h-3.5 w-3.5" />{t("booking.inquiry.locked")}</p>
        ) : payload === null ? (
          <p className="flex items-center gap-1.5 text-destructive"><ShieldAlert className="h-3.5 w-3.5" />{t("booking.inquiry.unreadable")}</p>
        ) : (
          <p className="flex items-center gap-1.5 text-muted-foreground">
            {opening ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Lock className="h-3.5 w-3.5" />}{t("booking.inquiry.opening")}
          </p>
        )}
      </div>
      <div className="flex shrink-0 flex-wrap gap-2">
        {item.status === "pending" && (
          <>
            <Button size="sm" disabled={busy} onClick={() => onAct(item.id, "accept")}><Check className="h-4 w-4" />{t("booking.inquiry.accept")}</Button>
            <Button size="sm" variant="soft" disabled={busy} onClick={() => onAct(item.id, "decline")}><X className="h-4 w-4" />{t("booking.inquiry.decline")}</Button>
          </>
        )}
        {mailto && (
          <Button size="sm" variant="soft" asChild>
            <a href={mailto}><Mail className="h-4 w-4" />{t("booking.inquiry.reply")}</a>
          </Button>
        )}
      </div>
    </li>
  );
}
