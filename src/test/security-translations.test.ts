import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import trustNl from "@/locales/pages/trust.nl.json";
import trustEn from "@/locales/pages/trust.en.json";
import trustFr from "@/locales/pages/trust.fr.json";
import trustDe from "@/locales/pages/trust.de.json";
import rootNl from "@/locales/nl.json";
import rootEn from "@/locales/en.json";
import rootFr from "@/locales/fr.json";
import rootDe from "@/locales/de.json";
import studioNl from "@/locales/studio/nl.json";
import studioEn from "@/locales/studio/en.json";
import studioFr from "@/locales/studio/fr.json";
import studioDe from "@/locales/studio/de.json";
import { PILLAR_IDS, PILLAR_TEXTS, pillar } from "@/lib/privacy-pillars";

const LOCALES = ["nl", "en", "fr", "de"] as const;
type Bundle = Record<string, string>;

function expectParity(bundles: Record<string, Bundle>, prefix: string) {
  const keys = Object.keys(bundles.en!).filter((k) => k.startsWith(prefix)).sort();
  expect(keys.length).toBeGreaterThan(0);
  for (const [locale, bundle] of Object.entries(bundles)) {
    expect(Object.keys(bundle).filter((k) => k.startsWith(prefix)).sort(), locale).toEqual(keys);
    for (const k of keys) expect(bundle[k]?.trim(), `${locale}:${k}`).toBeTruthy();
  }
}

describe("Trust Center (/security) in NL, EN, FR and DE", () => {
  const trust = { nl: trustNl, en: trustEn, fr: trustFr, de: trustDe } as unknown as Record<string, Bundle>;

  it("every Trust Center text exists in all four languages", () => {
    expectParity(trust, "trust.");
  });

  it("French and German are real translations, not English copies", () => {
    for (const k of ["trust.title", "trust.lead", "trust.compare.heading", "trust.row.guests.rout", "trust.manifest.proxy"]) {
      expect(trust.fr![k], `fr:${k}`).not.toBe(trust.en![k]);
      expect(trust.de![k], `de:${k}`).not.toBe(trust.en![k]);
    }
  });

  it("the privacy pillars have the same shape in all four languages and resolve per locale", () => {
    for (const id of PILLAR_IDS) {
      const en = PILLAR_TEXTS.en[id];
      for (const l of LOCALES) {
        const p = PILLAR_TEXTS[l][id];
        expect([p.how.length, p.stored.length, p.notStored.length], `${l}:${id}`).toEqual([en.how.length, en.stored.length, en.notStored.length]);
      }
      expect(pillar(id, "fr").title).toBe(PILLAR_TEXTS.fr[id].title);
      expect(pillar(id, "de").title).toBe(PILLAR_TEXTS.de[id].title);
      expect(pillar(id, "fr").title).not.toBe(en.title);
      expect(pillar(id, "de").title).not.toBe(en.title);
    }
  });

  it("the page has no Dutch/English-only text switch left", () => {
    const src = readFileSync("src/routes/security.tsx", "utf8") + readFileSync("src/components/PrivacyBadge.tsx", "utf8");
    expect(src).not.toMatch(/\bnl \?/);
  });
});

describe("Cryptography page (/safety/cryptography) in NL, EN, FR and DE", () => {
  const read = (l: string) => readFileSync(`src/content/safety/cryptography${l === "nl" ? "" : `.${l}`}.mdx`, "utf8");
  const shape = (text: string) => ({ sections: (text.match(/^## /gm) ?? []).length, callouts: (text.match(/<Callout /g) ?? []).length });

  it("exists in every language with the same sections and warnings", () => {
    const nl = shape(read("nl"));
    expect(nl.sections).toBeGreaterThanOrEqual(6);
    for (const l of LOCALES) expect(shape(read(l)), l).toEqual(nl);
  });

  it("every language says the short request form is encrypted now and keeps the honest limits", () => {
    for (const l of LOCALES) {
      const text = read(l);
      expect(text, l).toContain("ML-KEM-1024 + X25519");
      expect(text, l).not.toMatch(/nog onversleuteld|still unencrypted|encore non chiffré|noch unverschlüsselt/);
      expect(text, l).toMatch(/4[.,]5/);
    }
  });
});

describe("profile-card request and Studio texts", () => {
  it("visitor-facing texts exist in all four languages", () => {
    const root = { nl: rootNl, en: rootEn, fr: rootFr, de: rootDe } as unknown as Record<string, Bundle>;
    expectParity(root, "profile.sealed");
    expectParity(root, "privacy.section.bookings.");
  });

  it("host-facing Studio texts exist in all four languages", () => {
    expectParity({ nl: studioNl, en: studioEn, fr: studioFr, de: studioDe } as unknown as Record<string, Bundle>, "booking.inquiry.");
  });
});
