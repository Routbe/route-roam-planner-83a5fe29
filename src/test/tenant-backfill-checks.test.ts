// @vitest-environment node
/** tenant-backfill D2: a pending invite names its invitee before they join, so it is never a membership deviation. */
import { describe, expect, it } from "vitest";
import { checks } from "../../scripts/tenant-backfill";

describe("tenant-backfill checks", () => {
  it("skips workspace_invites.invited_user_id in D2 and still measures the inviter", async () => {
    const res = await checks(async () => [{ n: 0 }]);
    const names = res.map((r) => r.check);
    expect(names).not.toContain("D2 workspace_invites.invited_user_id->workspace_id");
    expect(names.some((n) => n.startsWith("D2 workspace_invites.") )).toBe(true);
    expect(names).toContain("D1 workspace_invites.workspace_id");
  });
});
