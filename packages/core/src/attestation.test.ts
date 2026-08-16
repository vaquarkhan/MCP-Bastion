import { describe, it, expect } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import {
  AttestationVerifier,
  samplingOriginAllowed,
} from "./attestation.js";

describe("attestation", () => {
  it("verifies a valid Ed25519 envelope", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const payload = { tool: "ping", arguments: {} };
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    const signatureBase64 = sign(null, body, privateKey).toString("base64");
    const spki = publicKey.export({ type: "spki", format: "der" }) as Buffer;

    const v = new AttestationVerifier([
      {
        serverId: "srv1",
        publicKeyBase64: spki.toString("base64"),
        allowedTools: ["ping"],
      },
    ]);
    const r = v.verifyEnvelope({
      serverId: "srv1",
      payload,
      signatureBase64,
    });
    expect(r.ok).toBe(true);
    expect(v.toolAllowed("srv1", "ping")).toBe(true);
    expect(v.toolAllowed("srv1", "other")).toBe(false);
  });

  it("advisory sampling origin always allows", () => {
    expect(samplingOriginAllowed(undefined, "advisory")).toBe(true);
  });

  it("require mode needs authenticated origin", () => {
    expect(samplingOriginAllowed(undefined, "require")).toBe(false);
    expect(
      samplingOriginAllowed(
        { authenticated: true, serverId: "s" },
        "require"
      )
    ).toBe(true);
  });
});
