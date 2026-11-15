// @vitest-environment node
/**
 * Zero-trust invariant: every server function carries an auth middleware
 * (requireAuth, requireDeveloperAccess or optionalAuth), unless it is listed
 * below as deliberately public (visitor, token-link or policy-checked entry).
 * A new unguarded function, or a stale entry, fails this test. The list may
 * only shrink without a review. Client-side route gates are never a substitute.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";

const GUARDS = ["requireAuth", "requireDeveloperAccess", "optionalAuth"];

const PUBLIC_SERVER_FNS = new Set([
  "src/lib/admin-platform.functions.ts#getPlatformFeatures",
  "src/lib/agent/connect.functions.ts#getConnectClient",
  "src/lib/alias-profile.functions.ts#getPublicAliasProfileByHandle",
  "src/lib/altcha.functions.ts#getAltchaChallenge",
  "src/lib/app-credentials.functions.ts#getPublicAppCredentials",
  "src/lib/auth-providers.functions.ts#getAuthProviders",
  "src/lib/auth.functions.ts#getSessionUser",
  "src/lib/auth/email-safety.functions.ts#emergencyFreezeEmailChange",
  "src/lib/badge-claims.functions.ts#getStampClaim",
  "src/lib/badges.functions.ts#getBadgeCatalogue",
  "src/lib/bluesky-login.functions.ts#finishBlueskyLogin",
  "src/lib/bluesky-login.functions.ts#getPendingBlueskyLogin",
  "src/lib/bluesky-login.functions.ts#requestFediverseEmailCode",
  "src/lib/booking-engine/booking.functions.ts#createBooking",
  "src/lib/booking-engine/booking.functions.ts#getBookingSummary",
  "src/lib/booking-engine/booking.functions.ts#getHostBookingKeys",
  "src/lib/booking-engine/booking.functions.ts#getNextBookingSlots",
  "src/lib/booking-engine/booking.functions.ts#getPublicEventType",
  "src/lib/booking-engine/booking.functions.ts#getPublicSlots",
  "src/lib/booking-engine/booking.functions.ts#holdBookingSlot",
  "src/lib/booking-engine/booking.functions.ts#releaseBookingSlot",
  "src/lib/booking.functions.ts#getProfileBookingKey",
  "src/lib/booking.functions.ts#requestBooking",
  "src/lib/bootstrap.functions.ts#checkHandleAvailability",
  "src/lib/bootstrap.functions.ts#getBootstrapState",
  "src/lib/bootstrap.functions.ts#suggestHandleForName",
  "src/lib/bootstrap.functions.ts#suggestHandlesFromEmailAddress",
  "src/lib/calendars.functions.ts#getPublicCalendar",
  "src/lib/community.functions.ts#getCommunityStats",
  "src/lib/community.functions.ts#listApprovedReviews",
  "src/lib/contact.functions.ts#submitContactMessage",
  "src/lib/custom-badges.functions.ts#getPublicCustomBadges",
  "src/lib/db/gateway.functions.ts#runDbQuery",
  "src/lib/db/gateway.functions.ts#runDbRpc",
  "src/lib/domain-routing.functions.ts#resolveHostProfile",
  "src/lib/donations.functions.ts#getDonationStatus",
  "src/lib/donations.functions.ts#getDonationTarget",
  "src/lib/donations.functions.ts#startDonationCheckout",
  "src/lib/ephemeral.functions.ts#getPublicPresence",
  "src/lib/event-engine.functions.ts#getPublicEvents",
  "src/lib/feedback.functions.ts#getPublicFeedback",
  "src/lib/feedback.functions.ts#sendFeedbackResponse",
  "src/lib/gateway.functions.ts#getGatewaySession",
  "src/lib/gift-cards.functions.ts#getPublicGiftCard",
  "src/lib/go-link.functions.ts#resolveGoDestination",
  "src/lib/go-link.functions.ts#verifyGoLink",
  "src/lib/guestbook.functions.ts#getPinnedNotes",
  "src/lib/identity/links.functions.ts#confirmIdentityRevoke",
  "src/lib/identity/links.functions.ts#describeIdentityRevoke",
  "src/lib/interaction-votes.functions.ts#getPollResults",
  "src/lib/interaction-votes.functions.ts#votePoll",
  "src/lib/lead-capture.functions.ts#submitLeadCapture",
  "src/lib/locale.functions.ts#getRequestLocale",
  "src/lib/login-code.functions.ts#redeemLoginCodeFn",
  "src/lib/newsletter.functions.ts#confirmNewsletterSubscription",
  "src/lib/newsletter.functions.ts#leaveNewsletter",
  "src/lib/newsletter.functions.ts#subscribeNewsletter",
  "src/lib/parent.functions.ts#approveParentConsent",
  "src/lib/parent.functions.ts#getParentView",
  "src/lib/parent.functions.ts#setParentQaLevel",
  "src/lib/parent.functions.ts#startParentPayment",
  "src/lib/pricing.functions.ts#getPricingSettings",
  "src/lib/questions.functions.ts#getQaPublic",
  "src/lib/recovery/recovery-login.functions.ts#openRecoveryLogin",
  "src/lib/recovery/recovery-login.functions.ts#startRecoveryLogin",
  "src/lib/referral.functions.ts#tagReferralVisit",
  "src/lib/review.functions.ts#confirmReviewDecision",
  "src/lib/review.functions.ts#getReviewPreview",
  "src/lib/showcase.functions.ts#listShowcaseCards",
  "src/lib/showcase.functions.ts#listShowcaseHandles",
  "src/lib/snapchat.functions.ts#getPublicSnapchat",
  "src/lib/social-feed.functions.ts#getSocialFeed",
  "src/lib/studio-profile.functions.ts#getPublicProfileByHandle",
  "src/lib/tip-page.functions.ts#fetchTipSocialImages",
  "src/lib/tip-page.functions.ts#getPublicTipPage",
  "src/lib/tip-page.functions.ts#getTipJarQr",
  "src/lib/tip-page.functions.ts#startTipPayment",
  "src/lib/tour-draft.functions.ts#beginAuthIntent",
  "src/lib/tour-draft.functions.ts#discardTourDraftToken",
  "src/lib/tour-draft.functions.ts#getTourDraftByToken",
  "src/lib/tour-draft.functions.ts#saveTourDraftToken",
  "src/lib/verification.functions.ts#getPaymentConfig",
  "src/lib/visits.functions.ts#recordLinkClickFn",
  "src/lib/visits.functions.ts#recordProfileVisit",
  "src/lib/visual-widgets.functions.ts#getWidgetWeather",
  "src/lib/wallet/wallet.functions.ts#getWalletCard",
  "src/lib/wallet/wallet.functions.ts#getWalletStatus",
  "src/lib/wallet/wallet.functions.ts#lookupPhysicalCardFn",
  "src/lib/wallet/wallet.functions.ts#verifyCardLiveCode",
  "src/lib/workspace-conversion.functions.ts#describeWorkspaceTransfer",
  "src/lib/workspace-conversion.functions.ts#getSunsetStatus",
  "src/lib/workspace-public.functions.ts#getPublicWorkspace",
  "src/lib/workspace-public.functions.ts#resolveMigratedHandle",
  "src/lib/workspace-public.functions.ts#resolveWorkspaceRootAlias",
  "src/lib/workspaces.functions.ts#getWorkspaceContext",
]);

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) return files(p);
    return /\.tsx?$/.test(n) && !/\.test\./.test(n) ? [p] : [];
  });
}

function scan() {
  const out: { id: string; guarded: boolean }[] = [];
  for (const f of files("src")) {
    const s = readFileSync(f, "utf8");
    if (!s.includes("createServerFn")) continue;
    const re = /export const (\w+)\s*=\s*createServerFn/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(s))) {
      const next = s.indexOf("export const", m.index + m[0].length);
      const body = s.slice(m.index, next > 0 ? next : undefined);
      const mw = /\.middleware\(\[([^\]]*)\]/.exec(body)?.[1] ?? "";
      out.push({ id: `${f.replace(/\\/g, "/")}#${m[1]}`, guarded: GUARDS.some((g) => mw.includes(g)) });
    }
  }
  return out;
}

it("every non-public server function has an auth middleware", () => {
  const unguarded = scan().filter((f) => !f.guarded && !PUBLIC_SERVER_FNS.has(f.id)).map((f) => f.id);
  expect(unguarded).toEqual([]);
});

it("the public allowlist has no stale or now-guarded entries", () => {
  const all = new Map(scan().map((f) => [f.id, f.guarded]));
  const stale = [...PUBLIC_SERVER_FNS].filter((id) => all.get(id) !== false);
  expect(stale).toEqual([]);
});

it("/dev/emails and its test mail are refused outside development", () => {
  expect(readFileSync("src/routes/dev.emails.tsx", "utf8")).toMatch(/beforeLoad:\s*\(\)\s*=>\s*\{\s*if \(!import\.meta\.env\.DEV\) throw notFound\(\)/);
  expect(readFileSync("src/lib/email-test.functions.ts", "utf8")).toMatch(/if \(!import\.meta\.env\.DEV\) throw/);
});
