// @vitest-environment node
import { beforeEach, expect, it, vi } from "vitest";

const storage = vi.hoisted(() => ({ configured: false }));
const read = vi.hoisted(() => ({ result: { status: "not_found" } as { status: string; body?: string } }));
vi.mock("@/lib/storage/s3.server", () => ({ storageConfigured: () => storage.configured }));
vi.mock("@/lib/pq/prekey-publish.server", () => ({
  productionReadDeps: async () => ({}),
  readPrekeyDocument: async () => read.result,
}));

import { Route } from "@/routes/$username_.prekey-bundle[.]json";

type Get = (ctx: { params: { username: string } }) => Promise<Response>;
const get = () => (Route.options as unknown as { server: { handlers: { GET: Get } } }).server.handlers.GET({ params: { username: "@someone" } });

beforeEach(() => { storage.configured = false; read.result = { status: "not_found" }; });

it("answers 503 storage_unavailable without Scaleway credentials, without throwing", async () => {
  const r = await get();
  expect(r.status).toBe(503);
  expect(await r.json()).toEqual({ error: "storage_unavailable" });
  expect(r.headers.get("cache-control")).toBe("no-store");
});

it("answers 404 not_available when storage is configured but nothing is published", async () => {
  storage.configured = true;
  const r = await get();
  expect(r.status).toBe(404);
  expect(await r.json()).toEqual({ error: "not_available" });
});
