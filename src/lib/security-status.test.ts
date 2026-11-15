import { describe, expect, it } from "vitest";
import { SECURITY_STATUS_LOCALES, securityStatus } from "./security-status";

describe("Trust Center status list", () => {
  it("lists the same items with the same status in nl, en, fr and de", () => {
    const shape = (l: string) => securityStatus(l).items.map((i) => `${i.id}:${i.level}`);
    expect(SECURITY_STATUS_LOCALES.sort()).toEqual(["de", "en", "fr", "nl"]);
    for (const l of SECURITY_STATUS_LOCALES) expect(shape(l), l).toEqual(shape("nl"));
  });

  it("never presents the ratchet or the VDF as in use, and keeps hardware binding open", () => {
    const level = (id: string) => securityStatus("nl").items.find((i) => i.id === id)?.level;
    expect(level("pq-ratchet")).toBe("building");
    expect(level("vdf")).toBe("building");
    expect(level("hardware-binding")).toBe("open");
  });

  it("keeps the measured numbers: 1,170 of 1,210 Z3 obligations and dudect below 4.5", () => {
    for (const l of SECURITY_STATUS_LOCALES) {
      const items = securityStatus(l).items;
      const rls = items.find((i) => i.id === "formal-rls")!.body.replace(/[.,\s\u00a0]/g, "");
      expect(rls, l).toContain("1170");
      expect(rls, l).toContain("1210");
      expect(items.find((i) => i.id === "dudect")!.body, l).toMatch(/4[.,]5/);
    }
  });
});
