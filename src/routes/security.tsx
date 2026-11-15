import { pathCardMeta } from "@/lib/path-cards";
import { createFileRoute } from "@tanstack/react-router";
import { ShieldCheck } from "lucide-react";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { PillarDetails } from "@/components/PrivacyBadge";
import { useI18n } from "@/lib/i18n";
import { PILLAR_IDS, pillar } from "@/lib/privacy-pillars";
import { securityStatus, type StatusLevel } from "@/lib/security-status";

const TITLE = "Trust Center | ROUT";
const DESC = "Hoe ROUT gegevens beschermt: lokale versleuteling, standaard OIDC, minimale gegevensdeling en gecontroleerde toegang.";

export const Route = createFileRoute("/security")({
  head: () => ({
    meta: [...pathCardMeta("/security", "nl"), 
      { title: TITLE },
      { name: "description", content: DESC },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESC },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: SecurityPage,
});

const SCHEMA = `create table public.calendar_events (
  id bigint generated always as identity primary key,
  calendar_id uuid not null references public.connected_calendars (id),
  provider_id text not null check (provider_id ~ '^[0-9a-f]{64}$'), -- HMAC-SHA256
  start_utc timestamptz not null,
  end_utc timestamptz not null,
  is_blocking boolean not null default true
); -- no title, description, location or attendee columns

create table public.availability_cache (
  user_id uuid not null,
  day date not null,
  free_bits bit(96) not null, -- 96 x 15 min, UTC
  primary key (user_id, day)
);`;

const SCOPE_CHECK = `// Every scoped request: the URL scope is verified server-side.
if (scope.type === "user" && scope.id !== userId) throw Forbidden;
if (scope.type === "workspace" && !(await getWorkspaceRole(userId, scope.id))) throw Forbidden;
// Free or unverified workspace: quota 0 MB -> 403 Storage Quota Exceeded`;

const OAUTH = `GET /oauth/authorize?client_id=…&scope=openid profile email&code_challenge=…
-> consent screen lists every requested scope
-> token only carries the scopes the user approved`;

const ROWS = ["calendar", "guests", "tracking", "signin", "donations", "teams"] as const;
const PROOFS = [["schema", SCHEMA], ["scope", SCOPE_CHECK], ["oauth", OAUTH]] as const;

function SecurityPage() {
  const { locale, t } = useI18n();
  return (
    <main className="mx-auto w-full max-w-4xl space-y-10 px-4 py-12">
      <header className="space-y-3">
        <p className="inline-flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-muted-foreground"><ShieldCheck className="size-4 text-primary" aria-hidden />Trust Center</p>
        <h1 className="font-display text-3xl tracking-tight sm:text-4xl">{t("trust.title")}</h1>
        <p className="max-w-2xl text-muted-foreground">{t("trust.lead")}</p>
      </header>

      {PILLAR_IDS.map((id) => (
        <section key={id} id={id} className="scroll-mt-24 rounded-2xl border border-border bg-card p-5 sm:p-6">
          <p className="mb-3 font-mono text-xs uppercase tracking-widest text-primary">{pillar(id, locale).label}</p>
          <PillarDetails p={pillar(id, locale)} />
        </section>
      ))}

      <StatusSection locale={locale} />

      <section className="space-y-3">
        <h2 className="font-display text-2xl">{t("trust.compare.heading")}</h2>
        <div className="overflow-x-auto rounded-2xl border border-border">
          <table className="w-full min-w-[32rem] text-left text-sm">
            <thead className="bg-muted/60 text-xs uppercase tracking-wide text-muted-foreground">
              <tr><th className="p-3">{t("trust.compare.area")}</th><th className="p-3">{t("trust.compare.saas")}</th><th className="p-3">ROUT</th></tr>
            </thead>
            <tbody>
              {ROWS.map((row) => (
                <tr key={row} className="border-t border-border"><td className="p-3 font-medium">{t(`trust.row.${row}.area`)}</td><td className="p-3 text-muted-foreground">{t(`trust.row.${row}.saas`)}</td><td className="p-3">{t(`trust.row.${row}.rout`)}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="font-display text-2xl">{t("trust.proof.heading")}</h2>
        <Accordion type="multiple" className="space-y-2">
          {PROOFS.map(([v, code]) => (
            <AccordionItem key={v} value={v} className="rounded-2xl border border-border bg-card px-4">
              <AccordionTrigger className="hover:no-underline">{t(`trust.proof.${v}`)}</AccordionTrigger>
              <AccordionContent><pre className="overflow-x-auto rounded-lg bg-muted p-3 font-mono text-xs leading-relaxed">{code}</pre></AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </section>

      <section className="space-y-2 rounded-2xl border border-border bg-card p-5">
        <h2 className="font-display text-2xl">{t("trust.manifest.heading")}</h2>
        <ul className="list-disc space-y-1 pl-5 text-sm">
          <li>{t("trust.manifest.donations")}</li>
          <li>{t("trust.manifest.keys")}</li>
          <li>{t("trust.manifest.proxy")}</li>
        </ul>
        <a href="/privacy" className="inline-flex pt-2 text-sm font-medium text-primary underline-offset-4 hover:underline">{t("trust.manifest.privacyLink")}</a>
      </section>
    </main>
  );
}

const LEVEL_CLASS: Record<StatusLevel, string> = {
  tested: "border-primary/40 bg-primary/10",
  building: "border-border bg-muted",
  open: "border-dashed border-border bg-background",
};

/** Honest per-item status of booking encryption and cryptography work (src/lib/security-status.ts). */
function StatusSection({ locale }: { locale: string }) {
  const s = securityStatus(locale);
  return (
    <section id="status" className="scroll-mt-24 space-y-3">
      <h2 className="font-display text-2xl">{s.heading}</h2>
      <p className="max-w-2xl text-sm text-muted-foreground">{s.intro}</p>
      <ul className="grid gap-3 sm:grid-cols-2">
        {s.items.map((item) => (
          <li key={item.id} id={item.id} className="scroll-mt-24 space-y-2 rounded-2xl border border-border bg-card p-4 text-sm">
            <span className={`inline-flex rounded-full border px-2.5 py-0.5 font-mono text-[11px] text-foreground ${LEVEL_CLASS[item.level]}`}>{s.levels[item.level]}</span>
            <p className="font-medium">{item.title}</p>
            <p className="text-muted-foreground">{item.body}</p>
            {item.open && <p className="text-muted-foreground"><span className="font-medium text-foreground">{s.openLabel}:</span> {item.open}</p>}
          </li>
        ))}
      </ul>
    </section>
  );
}
