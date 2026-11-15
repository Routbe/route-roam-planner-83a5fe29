// @vitest-environment node
import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { runEnclaveOp } from "./enclave-core";
import type { EnclaveOp, EnclaveOps } from "./protocol";
import { b64uDecode, hostRefOf, type HostBookingKeyDoc } from "@/lib/booking-engine/sealed-booking";
import { checkBookingKeyDoc } from "@/lib/booking-engine/host-booking-key.server";

const HOST = "00000000-0000-4000-8000-0000000000d1";
const OTHER = "00000000-0000-4000-8000-0000000000d2";
async function call<K extends EnclaveOp>(op: K, args: EnclaveOps[K]["req"]): Promise<EnclaveOps[K]["res"]> {
  const r = await runEnclaveOp(op, args);
  if (!r.ok) throw new Error(r.code);
  return r.result as EnclaveOps[K]["res"];
}
const code = async (op: EnclaveOp, args: unknown) => {
  const r = await runEnclaveOp(op, args);
  return r.ok ? "ok" : r.code;
};
async function withDeviceKey(userId: string) {
  const { handle } = await call("masterKey.generate", {});
  await call("masterKey.commitPending", { handle, userId });
}
const keyOf = (doc: HostBookingKeyDoc) => ({ ref: hostRefOf(b64uDecode(doc.publicKey)!), publicKey: b64uDecode(doc.publicKey)! });

describe("host booking key and guest sealing inside the crypto worker (Fase 1)", () => {
  let doc: HostBookingKeyDoc;

  it("needs the member's Master Key on this device", async () => {
    expect(await code("bookingKey.ensure", { userId: HOST, existing: null })).toBe("no_device_key");
  });

  it("creates a publishable document whose seed exists only sealed, and re-checks it", async () => {
    await withDeviceKey(HOST);
    const made = await call("bookingKey.ensure", { userId: HOST, existing: null });
    expect(made.created).toBe(true);
    doc = made.doc;
    expect(Object.keys(doc).sort()).toEqual(["keyId", "kid", "publicKey", "sealedSeed", "v"]);
    expect(checkBookingKeyDoc(doc)).toEqual(doc);
    const again = await call("bookingKey.ensure", { userId: HOST, existing: doc });
    expect(again).toEqual({ doc, created: false });
  });

  it("a guest seals name, e-mail, note and answers that only this host opens", async () => {
    const sealed = await call("booking.seal", { hosts: [keyOf(doc)], payload: { name: "Ada", email: "ada@example.com", note: "allergie", answers: [{ questionId: "q1", value: "true" }] } });
    expect(sealed.payloadId).toMatch(/^[0-9a-f-]{36}$/);
    expect(new TextDecoder().decode(sealed.hosts[0]!.envelope)).not.toContain("Ada");
    const opened = await call("bookingKey.open", { userId: HOST, doc, items: [{ payloadId: sealed.payloadId, envelope: sealed.hosts[0]!.envelope.slice() }] });
    expect(opened.payloads).toEqual([{ name: "Ada", email: "ada@example.com", note: "allergie", answers: [{ questionId: "q1", value: "true" }] }]);
  });

  it("a copy moved to another payload id or tampered with does not open", async () => {
    const sealed = await call("booking.seal", { hosts: [keyOf(doc)], payload: { name: "Ada" } });
    const env = sealed.hosts[0]!.envelope;
    const bad = env.slice();
    bad[bad.length - 1] = (bad[bad.length - 1] ?? 0) ^ 1;
    const r = await call("bookingKey.open", { userId: HOST, doc, items: [
      { payloadId: "11111111-2222-4333-8444-555555555555", envelope: env.slice() },
      { payloadId: sealed.payloadId, envelope: bad },
    ] });
    expect(r.payloads).toEqual([null, null]);
  });

  it("another member cannot open or re-check this host's key", async () => {
    await withDeviceKey(OTHER);
    expect(await code("bookingKey.ensure", { userId: OTHER, existing: doc })).toBe("key_mismatch");
    expect(await code("bookingKey.open", { userId: OTHER, doc, items: [] })).toBe("key_mismatch");
  });

  it("refuses a host reference that does not belong to its key and unknown payload fields", async () => {
    const k = keyOf(doc);
    expect(await code("booking.seal", { hosts: [{ ref: "11111111-2222-4333-8444-555555555555", publicKey: k.publicKey }], payload: { name: "Ada" } })).toBe("invalid_input");
    expect(await code("booking.seal", { hosts: [keyOf(doc)], payload: { name: "Ada", phone: "1" } })).toBe("invalid_input");
    expect(await code("booking.seal", { hosts: [], payload: { name: "Ada" } })).toBe("invalid_input");
  });
});
