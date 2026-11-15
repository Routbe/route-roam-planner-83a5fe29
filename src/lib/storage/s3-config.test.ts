import { describe, expect, it } from "vitest";
import { resolveBucket, resolveStorageConfig } from "./s3.server";

const S3 = { S3_ACCESS_KEY_ID: "gen-id", S3_SECRET_ACCESS_KEY: "gen-secret", S3_ENDPOINT: "https://s3.example.eu/", S3_REGION: "eu-x" };
const SCW = { SCALEWAY_ACCESS_KEY: "scw-id", SCALEWAY_SECRET_KEY: "scw-secret", SCALEWAY_ENDPOINT: "https://s3.fr-par.scw.cloud", SCALEWAY_REGION: "fr-par" };

describe("storage config resolution", () => {
  it("prefers the generic S3_* credentials, endpoint and region over SCALEWAY_*", () => {
    const c = resolveStorageConfig({ ...SCW, ...S3 });
    expect(c).toMatchObject({ accessKeyId: "gen-id", secretAccessKey: "gen-secret", endpoint: "https://s3.example.eu", region: "eu-x", source: "s3" });
  });

  it("falls back to SCALEWAY_* when no generic pair is set", () => {
    expect(resolveStorageConfig(SCW)).toMatchObject({ accessKeyId: "scw-id", secretAccessKey: "scw-secret", source: "scaleway" });
  });

  it("never mixes a key of one family with the secret of the other", () => {
    const c = resolveStorageConfig({ S3_ACCESS_KEY_ID: "gen-id", SCALEWAY_ACCESS_KEY: "scw-id", SCALEWAY_SECRET_KEY: "scw-secret" });
    expect(c).toMatchObject({ accessKeyId: "scw-id", secretAccessKey: "scw-secret" });
    expect(resolveStorageConfig({ S3_ACCESS_KEY_ID: "gen-id", SCALEWAY_SECRET_KEY: "scw-secret" })).toBeNull();
  });

  it("uses S3_BUCKET_NAME before SCALEWAY_DEFAULT_BUCKET, but a kind-specific bucket first", () => {
    expect(resolveBucket({ S3_BUCKET_NAME: "gen", SCALEWAY_DEFAULT_BUCKET: "scw" }, "client")).toBe("gen");
    expect(resolveBucket({ S3_BUCKET_NAME: "gen", SCALEWAY_INTERNAL_BUCKET: "scw-internal" }, "internal")).toBe("scw-internal");
    expect(resolveBucket({ S3_CLIENT_BUCKET: "gen-client", SCALEWAY_CLIENT_BUCKET: "scw-client", S3_BUCKET_NAME: "gen" }, "client")).toBe("gen-client");
    expect(resolveBucket({}, "client")).toBeUndefined();
  });
});
